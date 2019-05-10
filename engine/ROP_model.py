from collections import OrderedDict

from utility import *

gadget_delimiters = ['ret', 'jmp', 'call']


class ROPGadget:

    """
    This class represent a ROP gadget. A ROP gadget is a sequence of instructions terminated by a gadget delimiter.
    A gadget delimiter is a particular instruction that pass the control from a gadget to another.

    Attributes:
         address (int): the address of the gadget. This address must be loaded in stack eventually.
         instructions (dict): a dictionary containing all the instructions that form the gadget. The keys are the
                              addresses of the instructions and the values are ROPInstruction objects.
         rop_bytes (bytearray): the bytes that form the gadget.
         gadget_size (int): the size of the gadget in bytes.
    """

    def __init__(self, address, instructions, gadget_bytes):
        # type: (int, list, bytearray) -> None

        self.__address = address
        self.__instructions = OrderedDict()
        self.__rop_bytes = b""
        for instruction in instructions:
            self.__rop_bytes += instruction.instruction_bytes
            self.__instructions[instruction.address] = instruction
        self.__gadget_size = gadget_bytes

    @classmethod
    def from_bytes(cls, address, gadget_bytes):
        gadget_size = 0

        # Disassemble the instructions of the gadget and save a list of ROPInstruction objects
        instructions = []
        for instruction in dis32.disasm(str(gadget_bytes), address):

            i = ROPInstruction(instruction.bytes, instruction.size, instruction.address,
                               instruction.mnemonic, instruction.op_str)
            instructions.append(i)
            gadget_size += instruction.size
            if instruction.mnemonic in gadget_delimiters:
                break

        return cls(address, instructions, gadget_size)

    @property
    def instructions(self):
        return self.__instructions

    @property
    def gadget_size(self):
        return self.__gadget_size

    @property
    def rop_bytes(self):
        return self.__rop_bytes

    @property
    def address(self):
        return self.__address

    def __str__(self):
        to_str = ""
        for instruction in self.__instructions.values():
            to_str += str(instruction) + "\n"
        return to_str


class ROPInstruction:

    """
    Represent a x86 instruction.

    Attributes:
        instruction_bytes (bytearray): the bytes of the instruction.
        size (int): the size of the instruction.
        address (int): the address of the instruction.
        mnemonic (str): the operation performed by the instruction.
        op1 (str): the first argument of the instruction. Default is empty string.
        op2 (str): the second argument of the instruction. Default is empty string.
    """

    def __init__(self, instruction_bytes, size, address, mnemonic, operands):
        # type: (ROPInstruction, bytearray, int, int, str, str) -> None

        self.instruction_bytes = instruction_bytes
        self.size = size
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = operands
        operands = [operand.strip() for operand in operands.split(",")]
        if len(operands) == 3:
            self.op1, self.op2, self.op3 = operands
        elif len(operands) == 2:
            self.op1, self.op2 = operands
            self.op3 = ""
        elif len(operands) == 1:
            self.op1 = operands[0]
            self.op2 = ""
            self.op3 = ""
        else:
            self.op1 = ""
            self.op2 = ""
            self.op3 = ""

    def __str__(self):

        instr_bytes = ""
        for c in self.instruction_bytes:
            instr_bytes += "{:0>2}".format(hex(c).lstrip('0x')) + " "

        instr_bytes = "{:<16}".format(instr_bytes)
        if self.op2 != "":
            return "0x%x:  %s%s %s, %s" % (self.address, instr_bytes, self.mnemonic, self.op1, self.op2)
        elif self.op1 != "":
            return "0x%x:  %s%s %s" % (self.address, instr_bytes, self.mnemonic, self.op1)
        else:
            return "0x%x:  %s%s" % (self.address, instr_bytes, self.mnemonic)
