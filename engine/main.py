"""
TODO: description of all the modules
"""
import os, sys

from capstone import *
from capstone.x86_const import *

from CFG import CFG
from barf_classification import barf_classify
from emulator import Emulator
from config import *
from multipath import BranchStatus, BranchHandler


def main(path = None):
    if len(sys.argv) != 2:
        print "Usage: python "+sys.argv[0]+" <config.json>"
        print "Try with one of the JSON files from the ROP collection."
        return -1
    
    if path is None:
        path = sys.argv[1]
        config = Config.from_json(path)
    
    out_dir = "output/"
    if not os.path.exists(out_dir):
        os.mkdir(out_dir)

    try:
        emu = Emulator.emu_config(config)
    except MemoryError as me:
        print me.message
        return -1

    # emu.add_function_hook(lambda e: e.emu_stop(), address=0x401030)
    # from syscall_emu import virtualalloc_emu
    # emu.add_function_hook(virtualalloc_emu, name='VirtualAlloc')

    # from unicorn import UC_HOOK_MEM_VALID, UC_HOOK_CODE
    # from types import MethodType
    # def new_hook_mem(self, uc, type, address, size, value, user_data):
    #     print 'NEW HOOOOOOOK'
    # def aa(self, uc, address, size, user_data):
    #     print 'ciao'
    # emu.new_hook = MethodType(new_hook_mem, emu)
    # emu.emu.hook_add(UC_HOOK_MEM_VALID, emu.new_hook)
    # emu.add_unicorn_hook(UC_HOOK_MEM_VALID, new_hook_mem)
    # emu.add_unicorn_hook(UC_HOOK_CODE, aa)

    if path.endswith("CVE-2018-4990-POC.json"):
        from unicorn.x86_const import UC_X86_REG_EDI
        emu.add_pp_hook(0x64560028, 0x64145b62, lambda e: e.emu.reg_write(UC_X86_REG_EDI, 1))

    emu.emu_start()
    emu.output.branch_handler.compute_eflags_setter()

    spgs = [emu.output.sequence_spg]
    seqs = [emu.output.gadget_sequence]

    def explore_branches_from(first_branch, graphs):
        while first_branch.bstat.get_status() != BranchStatus.STATUS.FULLY_EXPLORED:
            for fb in first_branch.bstat.get_internal_branches():
                explore_branches_from(fb, graphs)
            if first_branch.bstat.get_status() == BranchStatus.STATUS.NOT_EXPLORED:
                # force path
                emu.restore_from(first_branch.flag_loading.checkpoint, first_branch.flag_loading.get_eflag_bitmask())
                emu.output.branch_handler.compute_eflags_setter()
                graphs.append(emu.output.mm_esp_graph)
                spgs.append(emu.output.sequence_spg)
                seqs.append(emu.output.gadget_sequence)

    def explore_all_branches():
        graphs = [emu.output.mm_esp_graph]
        if emu.output.branch_handler.possible_branch_gadget:
            explore_branches_from(emu.output.branch_handler.possible_branch_gadget.itervalues().next(), graphs)
        return graphs

    cfgs = explore_all_branches()
    combination = CFG.combine_CFGs(cfgs)
    combination.render_graph()
    combination.render_empty_graph()

    with open(out_dir + 'MP-ip-trace.txt', 'w') as f:
        brand_new = []
        for seq in seqs:
            brand_new.append([hex(a).strip('L') for a, _ in seq])
        f.write(str(brand_new).replace("'", ""))
    with open(out_dir + 'MP-sp-trace.txt', 'w') as f:
        brand_new = []
        for spg in spgs:
            brand_new.append([(hex(a).rstrip('L'), hex(b).rstrip('L')) for a, b in spg])
        f.write(str(brand_new).replace("'", ""))

    from IPBasedCFG import IPBasedMPCFG
    ipCFG = IPBasedMPCFG()
    ipCFG.add_nodes(seqs)
    ipCFG.add_edges(seqs)
    ipCFG.render()

    print emu.output.called_syscall_sequence

    # G = emu.output.mm_esp_graph
    # emu.output.mm_esp_graph.render_graph()
    #
    # b = emu.output.branch_handler.possible_branch_gadget.itervalues().next()
    # emu.restore_from(b.flag_loading.checkpoint, b.flag_loading.get_eflag_bitmask())
    #
    # emu.output.mm_esp_graph.render_graph()
    # emu.output.mm_esp_graph.combine_with(G)
    # emu.output.mm_esp_graph.render_graph()

    # dis32 = Cs(CS_ARCH_X86, CS_MODE_32)
    # dis32.detail = True
    #
    # def get_eflag_name(eflag):
    #     if eflag == X86_EFLAGS_UNDEFINED_OF:
    #         return "UNDEF_OF"
    #     elif eflag == X86_EFLAGS_UNDEFINED_SF:
    #         return "UNDEF_SF"
    #     elif eflag == X86_EFLAGS_UNDEFINED_ZF:
    #         return "UNDEF_ZF"
    #     elif eflag == X86_EFLAGS_MODIFY_AF:
    #         return "MOD_AF"
    #     elif eflag == X86_EFLAGS_UNDEFINED_PF:
    #         return "UNDEF_PF"
    #     elif eflag == X86_EFLAGS_MODIFY_CF:
    #         return "MOD_CF"
    #     elif eflag == X86_EFLAGS_MODIFY_SF:
    #         return "MOD_SF"
    #     elif eflag == X86_EFLAGS_MODIFY_ZF:
    #         return "MOD_ZF"
    #     elif eflag == X86_EFLAGS_UNDEFINED_AF:
    #         return "UNDEF_AF"
    #     elif eflag == X86_EFLAGS_MODIFY_PF:
    #         return "MOD_PF"
    #     elif eflag == X86_EFLAGS_UNDEFINED_CF:
    #         return "UNDEF_CF"
    #     elif eflag == X86_EFLAGS_MODIFY_OF:
    #         return "MOD_OF"
    #     elif eflag == X86_EFLAGS_RESET_OF:
    #         return "RESET_OF"
    #     elif eflag == X86_EFLAGS_RESET_CF:
    #         return "RESET_CF"
    #     elif eflag == X86_EFLAGS_RESET_DF:
    #         return "RESET_DF"
    #     elif eflag == X86_EFLAGS_RESET_IF:
    #         return "RESET_IF"
    #     elif eflag == X86_EFLAGS_TEST_OF:
    #         return "TEST_OF"
    #     elif eflag == X86_EFLAGS_TEST_SF:
    #         return "TEST_SF"
    #     elif eflag == X86_EFLAGS_TEST_ZF:
    #         return "TEST_ZF"
    #     elif eflag == X86_EFLAGS_TEST_PF:
    #         return "TEST_PF"
    #     elif eflag == X86_EFLAGS_TEST_CF:
    #         return "TEST_CF"
    #     elif eflag == X86_EFLAGS_RESET_SF:
    #         return "RESET_SF"
    #     elif eflag == X86_EFLAGS_RESET_AF:
    #         return "RESET_AF"
    #     elif eflag == X86_EFLAGS_RESET_TF:
    #         return "RESET_TF"
    #     elif eflag == X86_EFLAGS_RESET_NT:
    #         return "RESET_NT"
    #     elif eflag == X86_EFLAGS_PRIOR_OF:
    #         return "PRIOR_OF"
    #     elif eflag == X86_EFLAGS_PRIOR_SF:
    #         return "PRIOR_SF"
    #     elif eflag == X86_EFLAGS_PRIOR_ZF:
    #         return "PRIOR_ZF"
    #     elif eflag == X86_EFLAGS_PRIOR_AF:
    #         return "PRIOR_AF"
    #     elif eflag == X86_EFLAGS_PRIOR_PF:
    #         return "PRIOR_PF"
    #     elif eflag == X86_EFLAGS_PRIOR_CF:
    #         return "PRIOR_CF"
    #     elif eflag == X86_EFLAGS_PRIOR_TF:
    #         return "PRIOR_TF"
    #     elif eflag == X86_EFLAGS_PRIOR_IF:
    #         return "PRIOR_IF"
    #     elif eflag == X86_EFLAGS_PRIOR_DF:
    #         return "PRIOR_DF"
    #     elif eflag == X86_EFLAGS_TEST_NT:
    #         return "TEST_NT"
    #     elif eflag == X86_EFLAGS_TEST_DF:
    #         return "TEST_DF"
    #     elif eflag == X86_EFLAGS_RESET_PF:
    #         return "RESET_PF"
    #     elif eflag == X86_EFLAGS_PRIOR_NT:
    #         return "PRIOR_NT"
    #     elif eflag == X86_EFLAGS_MODIFY_TF:
    #         return "MOD_TF"
    #     elif eflag == X86_EFLAGS_MODIFY_IF:
    #         return "MOD_IF"
    #     elif eflag == X86_EFLAGS_MODIFY_DF:
    #         return "MOD_DF"
    #     elif eflag == X86_EFLAGS_MODIFY_NT:
    #         return "MOD_NT"
    #     elif eflag == X86_EFLAGS_MODIFY_RF:
    #         return "MOD_RF"
    #     elif eflag == X86_EFLAGS_SET_CF:
    #         return "SET_CF"
    #     elif eflag == X86_EFLAGS_SET_DF:
    #         return "SET_DF"
    #     elif eflag == X86_EFLAGS_SET_IF:
    #         return "SET_IF"
    #     else:
    #         return None
    #
    # def get_up_flags(eflags):
    #     updated_flags = []
    #     for i in range(0, 46):
    #         if eflags & (1 << i):
    #             updated_flags.append(get_eflag_name(1 << i))
    #     print("\tEFLAGS: %s" % (','.join(p for p in updated_flags)))
    #
    # # For every gadget that had used an eflag related instruction there are possible multiple traces if that gadget is
    # # used in multiple branching instructions
    # flag_insn = False
    # infos = []
    # eflags_g_uses = {}
    # for fl, traces in emu.branch_handler.traces.items():
    #     for trace in traces:
    #         if fl.g_addr in eflags_g_uses:
    #             eflags_g_uses[fl.g_addr] += 1
    #         else:
    #             eflags_g_uses[fl.g_addr] = 1
    #         for g_addr in trace:
    #             if flag_insn:
    #                 flag_insn = False
    #                 break
    #             gadget_bytes = emu.gadget_map[g_addr].rop_bytes
    #             for insn in dis32.disasm(gadget_bytes, g_addr):
    #                 if insn.eflags:
    #                     infos.append((g_addr, insn.address, insn.eflags))
    #                     fl.eflag_bitmask = insn.eflags
    #                     flag_insn = True
    #                     break
    #
    # print "BRANCH INFOS:\n"
    #
    # print "Flags set up:\n"
    # for g_addr, insn_addr, eflags in infos:
    #     print emu.gadget_map[g_addr]
    #     get_up_flags(eflags)
    #     print
    #
    # print 'Eflags loading gadgets:\n'
    # for g_addr, uses in eflags_g_uses.items():
    #     print 'Used {} times'.format(uses)
    #     print emu.gadget_map[g_addr]

    print "Branching actions:"
    for sp, g_addr in emu.output.branch_handler.possible_branch_gadget.keys():

        print '\nGADGET:'
        print 'sp value: 0x{:x}'.format(sp)
        print emu.output.gadget_map[g_addr]

        print 'STATUS DEBUG {}'.format(emu.output.branch_handler.possible_branch_gadget[sp, g_addr].bstat.get_status())
        print 'INTERNAL BRANCH STATUSES: '
        for branch in emu.output.branch_handler.possible_branch_gadget[sp, g_addr].bstat.get_internal_branches():
            print '0x{:x}, {}'.format(branch.bstat.sp, branch.bstat.get_status())

    tg_map = barf_classify(emu.output.gadget_map, True)
    print tg_map

    return 0


if __name__ == "__main__":
    main()
