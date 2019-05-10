from collections import OrderedDict

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from enum import Enum

from unicorn.x86_const import *

from cow_taint import CowTaint

regs_to_code = {
    "EAX": UC_X86_REG_EAX,
    "EBP": UC_X86_REG_EBP,
    "EBX": UC_X86_REG_EBX,
    "ECX": UC_X86_REG_ECX,
    "EDI": UC_X86_REG_EDI,
    "EDX": UC_X86_REG_EDX,
    "EFLAGS": UC_X86_REG_EFLAGS,
    "ESI": UC_X86_REG_ESI,
    # "RAX"   : UC_X86_REG_RAX,
    # "RBP"   :UC_X86_REG_RBP,
    # "RBX"   : UC_X86_REG_RBX,
    # "RCX"   : UC_X86_REG_RCX,
    # "RDI"   : UC_X86_REG_RDI,
    # "RDX"   : UC_X86_REG_RDX,
    # "RSI"   : UC_X86_REG_RSI,
    # "RSP"   : UC_X86_REG_RSP,
    # "RIP"   : UC_X86_REG_RIP,
    "ESP": UC_X86_REG_ESP,
    "EIP": UC_X86_REG_EIP,
    # "R8"    : UC_X86_REG_R8,
    # "R9"    : UC_X86_REG_R9,
    # "R10"   : UC_X86_REG_R10,
    # "R11"   : UC_X86_REG_R11,
    # "R12"   : UC_X86_REG_R12,
    # "R13"   : UC_X86_REG_R13,
    # "R14"   : UC_X86_REG_R14,
    # "R15"   : UC_X86_REG_R15
}


class BranchHandler:
    _MONITORED_INSNS = [
        'lahf',
        'pushf',
        'pushfd',
        'adc',
        'adcx',
        'sbb',
    ]

    def __init__(self, emu):
        self._emu = emu
        self.traces = OrderedDict()
        self.possible_branch_gadget = OrderedDict()
        self.cow_taint = CowTaint(self._emu)

        self._valid_addrs = {}
        self._check_for_fw_use = False
        self._last_monitored_fl = None

        self._last_seen_branch = None
        self._insn_after_branch = False

    def monitor_insn(self, sp, g_addr, insn):

        if insn.mnemonic in self._MONITORED_INSNS:

            if self.traces:

                # check validity of the last considered candidate
                fl, traces = self.traces.popitem()
                if fl in self._valid_addrs:

                    # if is valid then we have to check if the number of saved traces for that gadget is equal
                    # to the number of times we encountered the gadget
                    if self._valid_addrs[fl] == len(traces):
                        self.traces[fl] = traces
                    else:
                        self.traces[fl] = traces[: self._valid_addrs[fl]]

            self.cow_taint.reset()
            self.cow_taint.init_taint(insn)

            # after the updates save the trace for the new gadget
            fl = FlagLoading(sp, g_addr, insn.mnemonic)
            fl.checkpoint = self._emu.get_checkpoint()
            if fl not in self.traces:
                self.traces[fl] = [self._get_current_trace()]
            else:
                self.traces[fl].append(self._get_current_trace())

            self._check_for_fw_use = True
            self._last_monitored_fl = fl

        elif self._check_for_fw_use:
            self.cow_taint.taint_propagation(insn)
            if (
                    self.cow_taint.tainted_esp_change(insn)
            ):
                self._add_valid_addr(self._last_monitored_fl)
                self._add_branch(sp, g_addr)
                self._check_for_fw_use = False

        elif self._insn_after_branch and g_addr != self._last_seen_branch[1]:
            self._get_branch_status().add_path(sp)
            self._insn_after_branch = False

    def capstone_to_eflags_aux(self, eflags):
        # FLAGS
        CF = 0x001
        PF = 0x004
        AF = 0x010
        ZF = 0x040
        SF = 0x080
        OF = 0x800

        # capstone flag consts
        # https://github.com/aquynh/capstone/blob/next/include/capstone/x86.h#L73-L118
        MODIFY_CF = 0x2
        MODIFY_PF = 0x10
        MODIFY_AF = 0x1
        MODIFY_ZF = 0x8
        MODIFY_SF = 0x4
        MODIFY_OF = 0x20

        res = 0

        if eflags & MODIFY_AF:
            res |= AF
        if eflags & MODIFY_CF:
            res |= CF
        if eflags & MODIFY_OF:
            res |= OF
        if eflags & MODIFY_PF:
            res |= PF
        if eflags & MODIFY_SF:
            res |= SF
        if eflags & MODIFY_ZF:
            res |= ZF

        return res

    def compute_eflags_setter(self):
        dis32 = Cs(CS_ARCH_X86, CS_MODE_32)
        dis32.detail = True
        flag_insn = False
        for fl, traces in self.traces.items():
            for trace in traces:
                for g_addr in trace:
                    if flag_insn:
                        flag_insn = False
                        break
                    gadget_bytes = self._emu.gadget_map[g_addr].rop_bytes
                    for insn in dis32.disasm(gadget_bytes, g_addr):
                        # Check every instruction of the gadget to see if it can perform a modification of the
                        # monitored bits (doesn't mean that the bits have been actually modified)
                        if insn.eflags and insn.eflags & self.capstone_to_eflags_aux(fl.monitored_bits):
                            fl.set_eflag_bitmask(self.capstone_to_eflags_aux(insn.eflags))
                            flag_insn = True
                            break


    def _get_current_trace(self):
        trace = [g_addr for g_addr, _ in self._emu.gadget_sequence]
        trace.reverse()
        return trace

    def _add_valid_addr(self, fl):
        if fl in self._valid_addrs:
            self._valid_addrs[fl] += 1
        else:
            self._valid_addrs[fl] = 1

    def _add_branch(self, sp, g_addr):
        if (sp, g_addr) not in self.possible_branch_gadget:
            if self._last_seen_branch:
                self.possible_branch_gadget[self._last_seen_branch].loop_counter = 1
            bstat = BranchStatus(sp, g_addr)
            branch = Branch(sp, g_addr, bstat, self._last_monitored_fl)
            self.possible_branch_gadget[sp, g_addr] = branch
            if self._get_branch_status():
                self._get_branch_status().set_internal_branch(branch)
        elif (sp, g_addr) == self._last_seen_branch:
            self.possible_branch_gadget[self._last_seen_branch].loop_counter += 1
            if self.possible_branch_gadget[self._last_seen_branch].loop_counter == 10:
                self._emu.emu_stop()

        self._last_seen_branch = (sp, g_addr)
        self._insn_after_branch = True

    def _get_branch_status(self):
        if self._last_seen_branch:
            return self.possible_branch_gadget[self._last_seen_branch].bstat


class Branch:

    def __init__(self, sp, g_addr, bstat, fl):
        self.sp = sp
        self.g_addr = g_addr
        self.bstat = bstat

        self.loop_counter = 1

        self.flag_loading = fl

    def __eq__(self, other):
        return self.sp == other.sp and self.g_addr == other.g_addr

    def __hash__(self):
        return hash(self.sp) + hash(self.g_addr)


class FlagLoading:

    _INSN2MASK_ = {
        'lahf': 0xd5,
        'pushf': 0x8d5,
        'pushfd': 0x8d5,
        'adc': 0x1,
        'adcx': 0x1,
        'sbb': 0x1,
    }

    def __init__(self, sp, g_addr, insn):
        self.sp = sp
        self.g_addr = g_addr
        self._checkpoint = None
        self._monitored_bits = FlagLoading._INSN2MASK_[insn]
        self._eflag_bitmask = 0

    def get_eflag_bitmask(self):
        return self._eflag_bitmask

    def set_eflag_bitmask(self, bm):
        self._eflag_bitmask = (bm & self._monitored_bits)

    @property
    def monitored_bits(self):
        return self._monitored_bits

    @property
    def checkpoint(self):
        return self._checkpoint

    @checkpoint.setter
    def checkpoint(self, chkpnt):
        self._checkpoint = chkpnt

    def __eq__(self, other):
        return self.sp == other.sp and self.g_addr == other.g_addr

    def __hash__(self):
        return hash(self.sp) + hash(self.g_addr)


class BranchStatus:

    STATUS = Enum('status', 'NOT_EXPLORED VISITED FULLY_EXPLORED')

    def __init__(self, sp, g_addr):
        self.sp = sp
        self.g_addr = g_addr

        self._status = self.STATUS.NOT_EXPLORED

        self._last_following_sp = -1
        self._visited_paths = {}
        self._paths = []

        self._path_to_ibranch_lookup = {}
        self._internal_branches = {}

    def set_internal_branch(self, branch):
        self._internal_branches[branch.sp, branch.g_addr] = branch
        self._path_to_ibranch_lookup[self._last_following_sp] = branch.sp, branch.g_addr

    def get_internal_branches(self):
        for sp in self._paths:
            if sp in self._path_to_ibranch_lookup:
                yield self._internal_branches[self._path_to_ibranch_lookup[sp]]

    def add_path(self, sp):
        self._last_following_sp = sp
        if sp not in self._visited_paths:
            self._visited_paths[sp] = 1
            self._paths.append(sp)
        else:
            self._visited_paths[sp] += 1

    def get_status(self):
        self._compute_status()
        return self._status

    def _compute_status(self):
        if self._status == self.STATUS.NOT_EXPLORED and len(self._paths) < 2:
            return
        elif self._status == self.STATUS.FULLY_EXPLORED:
            return
        else:
            self._status = self.STATUS.VISITED

        for branch in self.get_internal_branches():
            stat = branch.bstat.get_status()
            if stat == self.STATUS.NOT_EXPLORED or stat == self.STATUS.VISITED:
                break
        else:
            self._status = self.STATUS.FULLY_EXPLORED
