from capstone import *


class CowTaint:

    regs_taint = {
        "AL": False,
        "AH": False,
        "AX": False,
        "EAX": False,
        "BL": False,
        "BH": False,
        "BX": False,
        "EBX": False,
        "CL": False,
        "CH": False,
        "CX": False,
        "ECX": False,
        "DL": False,
        "DH": False,
        "DX": False,
        "EDX": False,
        "DI": False,
        "EDI": False,
        "SI": False,
        "ESI": False,
    }

    _reg_tainter_list = {
        "EAX": ["EAX", "AX", "AH", "AL"],
        "AX": ["AX", "AH", "AL"],
        "AH": ["AH"],
        "AL": ["AL"],
        "EBX": ["EBX", "BX", "BH", "BL"],
        "BX": ["BX", "BH", "BL"],
        "BH": ["BH"],
        "BL": ["BL"],
        "ECX": ["ECX", "CX", "CH", "CL"],
        "CX": ["CX", "CH", "CL"],
        "CH": ["CH"],
        "CL": ["CL"],
        "EDX": ["EDX", "DX", "DH", "DL"],
        "DX": ["DX", "DH", "DL"],
        "DH": ["DH"],
        "DL": ["DL"],
        "EDI": ["EDI", "DI"],
        "DI": ["DI"],
        "ESI": ["ESI", "SI"],
        "SI": ["SI"],
    }

    memory_taint = {}

    def __init__(self, emu):
        self.dis = Cs(CS_ARCH_X86, CS_MODE_32)
        self.dis.detail = True
        self._emu = emu

    def init_taint(self, first_insn):
        for insn in self.dis.disasm(first_insn.instruction_bytes, first_insn.address):
            for op in insn.operands:
                if op.type == CS_OP_REG and op.access & CS_AC_WRITE:
                    self._taint_reg(insn.reg_name(op.reg))
                elif op.type == CS_OP_MEM and op.access & CS_AC_WRITE:
                    value = self._get_mem_addr(insn, op)
                    self._taint_mem(value, op.size)

            # LAHF and PUSHF/PUSHFD
            if not insn.operands:
                for reg in insn.regs_write:
                    self._taint_reg(insn.reg_name(reg))
                    if insn.reg_name(reg) == 'esp':
                        if insn.mnemonic == 'pushf':
                            addr = self._emu.reg_read('ESP') - 2
                            self._taint_mem(addr, 2)
                        elif insn.mnemonic == 'pushfd':
                            addr = self._emu.reg_read('ESP') - 4
                            self._taint_mem(addr, 4)

    def reset(self):
        for reg in self.regs_taint.keys():
            self.regs_taint[reg] = False
        self.memory_taint = {}

    def taint_propagation(self, insn):
        for i in self.dis.disasm(insn.instruction_bytes, insn.address):
            op_value = -1
            dsts, srcs = ([], [])
            for op in i.operands:
                if op.type == CS_OP_REG:
                    op_value = i.reg_name(op.reg)
                elif op.type == CS_OP_MEM:
                    op_value = (self._get_mem_addr(i, op), op.size)
                if op.access & CS_AC_READ:
                    srcs.append(op_value)
                if op.access & CS_AC_WRITE:
                    dsts.append(op_value)

            if len(i.operands) == 1 and i.mnemonic == 'pop':
                srcs.append((self._emu.reg_read('ESP'), i.operands[0].size))

            self._taint_if_src(dsts, srcs)

    def tainted_esp_change(self, insn):
        for i in self.dis.disasm(insn.instruction_bytes, insn.address):
            if (
                    len(i.operands) > 1 and
                    i.reg_name(i.operands[0].reg) == 'esp' and
                    i.operands[0].access & CS_AC_WRITE
            ):
                mod_operand = i.operands[1]
            elif (
                    len(i.operands) > 1 and
                    i.reg_name(i.operands[1].reg) == 'esp' and
                    i.operands[1].access & CS_AC_WRITE
            ):
                mod_operand = i.operands[0]
            elif len(i.operands) == 1 and i.mnemonic == 'pop' and i.reg_name(i.operands[0].reg) == 'esp':
                return self._check_taint_mem(self._emu.reg_read('ESP'), i.operands[0].size)
            else:
                return False

            if mod_operand.access != CS_AC_INVALID:
                if mod_operand.type == CS_OP_REG:
                    return self._check_taint_reg(i.reg_name(mod_operand.reg))
                else:
                    return self._check_taint_mem(self._get_mem_addr(i, mod_operand), mod_operand.size)

    def _get_mem_addr(self, insn, op):
        base = insn.reg_name(op.mem.base, 'Default').upper()
        index = insn.reg_name(op.mem.index, 'Default').upper()
        disp = op.mem.disp
        scale = op.mem.scale
        value = 0
        value += self._emu.reg_read(base) if base != 'DEFAULT' else 0
        value += self._emu.reg_read(index) * scale if index != 'DEFAULT' else 0
        value += disp
        return value

    def _taint_reg(self, reg, clean=False):
        if reg.upper() in self.regs_taint:
            for r in self._reg_tainter_list[reg.upper()]:
                self.regs_taint[r] = not clean

    def _check_taint_reg(self, reg):
        if reg.upper() in self.regs_taint:
            return self.regs_taint[reg.upper()]

    def _taint_mem(self, addr, size, clean=False):
        s = size
        while s >= 1:
            self.memory_taint[(addr, s)] = not clean
            s /= 2

    def _check_taint_mem(self, addr, size):
        if (addr, size) in self.memory_taint:
            return self.memory_taint[addr, size]

    def _taint_if_src(self, dsts, srcs):
        for src in srcs:
            if type(src) == unicode:
                for dst in dsts:
                    if type(dst) == unicode:
                        self._taint_reg(dst, clean=(not self._check_taint_reg(src)))
                    if type(dst) == tuple:
                        addr, size = dst
                        self._taint_mem(addr, size, clean=(not self._check_taint_reg(src)))
            if type(src) == tuple:
                addr, size = src
                for dst in dsts:
                    if type(dst) == unicode:
                        self._taint_reg(dst, clean=(not self._check_taint_mem(addr, size)))


if __name__ == '__main__':
    from ROP_model import ROPInstruction
    class emu:
        def __init__(self):
            self.v = 10
        def reg_read(self, name):
            return self.v
    e = emu()
    i = ROPInstruction(bytearray('\x9C'), 1, 0x100, 'pushfd', '')
    # i = ROPInstruction(bytearray('\x9F'), 1, 0x100, 'lahf', '')
    t = CowTaint(e)
    t.init_taint(i)
    e.v -= 4
    i = ROPInstruction(bytearray('\x5C'), 1, 0x104, 'pop', 'esp')
    # t.taint_propagation(i)
    print t.tainted_esp_change(i)
