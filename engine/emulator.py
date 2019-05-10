import re
import struct
from collections import namedtuple
from types import MethodType

from unicorn import *
from unicorn.x86_const import *

from config import *
from page_usage_bitmap import PageUsageBitmap
from PE_interaction import *
from rop_logger import *
from ROP_model import *
from syscall_emu import *
from emu_state import *

from multipath import *

from CFG import *

VERBOSE_LOGGING = False

regs_to_code = {
    "EAX"    : UC_X86_REG_EAX,
    "EBP"    : UC_X86_REG_EBP,
    "EBX"    : UC_X86_REG_EBX,
    "ECX"    : UC_X86_REG_ECX,
    "EDI"    : UC_X86_REG_EDI,
    "EDX"    : UC_X86_REG_EDX,
    "EFLAGS" : UC_X86_REG_EFLAGS,
    "ESI"    : UC_X86_REG_ESI,
    # "RAX"   : UC_X86_REG_RAX,
    # "RBP"   :UC_X86_REG_RBP,
    # "RBX"   : UC_X86_REG_RBX,
    # "RCX"   : UC_X86_REG_RCX,
    # "RDI"   : UC_X86_REG_RDI,
    # "RDX"   : UC_X86_REG_RDX,
    # "RSI"   : UC_X86_REG_RSI,
    # "RSP"   : UC_X86_REG_RSP,
    # "RIP"   : UC_X86_REG_RIP,
    "ESP"    : UC_X86_REG_ESP,
    "EIP"    : UC_X86_REG_EIP,
    # "R8"    : UC_X86_REG_R8,
    # "R9"    : UC_X86_REG_R9,
    # "R10"   : UC_X86_REG_R10,
    # "R11"   : UC_X86_REG_R11,
    # "R12"   : UC_X86_REG_R12,
    # "R13"   : UC_X86_REG_R13,
    # "R14"   : UC_X86_REG_R14,
    # "R15"   : UC_X86_REG_R15
}


class Emulator:

    # region Configuration and startup
    def __init__(self, pe_targets, first_gadget_addr, stack_init_state, shellcode, os_version):
        # type: (list, int, list, bool, str) -> None

        self.logger = ROPLogger()
        self.logger.print_log("\n----------- Starting the emulator setup -----------\n")

        # Create the emulator
        self.emu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.branch_handler = BranchHandler(self)

        # Parse the target PE files
        self.PE_targets = []
        for pe_path, pe_base in pe_targets:
            if pe_base == -1:
                self.PE_targets.append(Target_PEFile(pe_path))
            else:
                self.PE_targets.append(Target_PEFile(pe_path, pe_base))

        # Map the emulator memory
        self.mm = self.MemoryMap(self.emu)
        pe_mappings = []
        for pe in self.PE_targets:

            image_base = pe.image_base

            for section in pe.sections_map:
                sect_address, sect_size, sect_data, protection = section
                self.mm.mmap(image_base + sect_address, sect_size, protection)
                self.write_code_at(image_base + sect_address, sect_data)

            pe_mappings.append((image_base, pe.size_of_image))

        self.k32_exp = Kernel32Exports(os_version)

        # Retrieve the first gadget and save it
        gadget = self.get_gadget_at(first_gadget_addr)
        self.gadget_map = OrderedDict()
        self.current_gadget = gadget
        self.gadget_map[gadget.address] = gadget
        self.gadget_sequence = []
        self.sequence_spg = []

        # Map a page for the syscall returns and a page for the syscall pointers
        map_returns(self)
        self.emu.mem_map(IAT_POINTED_PAGE_ADD, UNICORN_PAGE_ALIGNMENT, UC_PROT_NONE)
        self.IAT_page_pointer = IAT_POINTED_PAGE_ADD
        self.called_syscall_seq = []

        # Map the stack
        max_pe_base, max_pe_size = max(pe_mappings)
        stack_top = max_pe_base + max_pe_size + (1024 * 1024)  # Leave 1MB of free space between stack and pe mappings
        self.mm.mmap(stack_top, self.mm.max_stack_size, UC_PROT_WRITE | UC_PROT_READ)
        self.mm.stack_base = stack_top + self.mm.max_stack_size
        self.emu.reg_write(regs_to_code["ESP"], stack_top + self.mm.max_stack_size - UNICORN_PAGE_ALIGNMENT + 96)

        # self.mm.flag_shellcode_possible_area(self.reg_read('ESP'), size=UNICORN_PAGE_ALIGNMENT)
        self.shellcode = shellcode

        # Initialize the stack for the emulator
        for address in stack_init_state:
            self.push_on_stack(address)
        self.push_on_stack(hex(first_gadget_addr))

        esp_value = self.reg_read('ESP')
        stack_entry, _ = self.mm.get_last_shadow_stack_entry(esp_value)
        self.esp_predecessor = BaseNode()
        # self.mm.flag_shellcode_possible_area(stack_top, end=esp_value)

        self.emu.reg_write(regs_to_code['ESP'], esp_value + 4)

        # self.emu.mem_write(0x00403024, pack_data_correct_size(5, 4))  # Fibonacci input
        # self.emu.mem_write(0x00403020, pack_data_correct_size(5, 4))  # Factorial input
        # self.emu.mem_write(0x004041a8, pack_data_correct_size(2, 4))

        # The shellcode possible area here is from the top of the stack to the start of the chain and from the end of
        # the chain till the end of the stack

        self.output = None

        self.emu.reg_write(regs_to_code["EIP"], first_gadget_addr)
        self.last_seen_eflags = self.reg_read('EFLAGS')
        self.set_hooks()
        self.function_hooks = {}
        self.pp_hooks = {}

        self.to_unmap = None

    def emu_start(self):

        eip_value = self.reg_read("EIP")
        self.logger.print_log("\n----------- Starting the execution at 0x%x -----------\n\n" % eip_value)
        try:
            self.emu.emu_start(eip_value, 0xffffffff)
        except UcError as e:
            eip_value = self.reg_read("EIP")
            self.emu_stop()
            # self.print_regs()
            # self.print_stack_values()
            self.logger.print_log("\n\nA Unicorn error occurred while executing at address 0x%x" % eip_value)
            self.logger.print_log("ERROR: %s\n\n" % e)

    def get_checkpoint(self):
        cxt = self.emu.context_save()

        from copy import deepcopy

        return EmuCheckpoint(
            emu_context=cxt,
            gadget_sequence=deepcopy(self.gadget_sequence),
            called_syscall_sequence=deepcopy(self.called_syscall_seq),
            current_gadget=self.current_gadget,
            esp_predecessor=self.esp_predecessor,
            mm_memory_shadow=deepcopy(self.mm.memory_shadow),
            mm_written_pages=deepcopy(self.mm.written_pages),
            mm_shadow_stack=deepcopy(self.mm.shadow_stack),
            mm_esp_graph=deepcopy(self.mm.esp_graph),
            sequence_spg=deepcopy(self.sequence_spg))

    def restore_from(self, checkpoint, bitmask=0):
        self.emu.context_restore(checkpoint.emu_context)
        self.gadget_sequence = checkpoint.gadget_sequence
        self.called_syscall_seq = checkpoint.called_syscall_sequence
        self.current_gadget = checkpoint.current_gadget
        self.esp_predecessor = checkpoint.esp_predecessor
        self.mm.memory_shadow = checkpoint.mm_memory_shadow
        self.mm.written_pages = checkpoint.mm_written_pages
        self.mm.shadow_stack = checkpoint.mm_shadow_stack
        self.mm.esp_graph = checkpoint.mm_esp_graph
        self.sequence_spg = checkpoint.sequence_spg

        self.output = None

        # Restore emulator stack from the shadow stack
        for address, entry in self.mm.shadow_stack.items():
            last_value_written = self.mm.shadow_stack[address][-1][0]
            lvw_size = self.mm.shadow_stack[address][-1][1]
            self.emu.mem_write(address, pack_data_correct_size(last_value_written, lvw_size))

        # Restore emulator memory from shadow memory
        for _, entry in self.mm.memory_shadow.items():
            last_value_written = entry.values[-1][0]
            lvw_size = entry.values[-1][1]
            self.emu.mem_write(entry.address, pack_data_correct_size(last_value_written, lvw_size))

        ef = self.reg_read('EFLAGS')
        self.emu.reg_write(regs_to_code['EFLAGS'], ef ^ bitmask)

        self.emu_start()

    def emu_stop(self):
        """
        Stops the emulator and log some info.
        """
        self.emu.emu_stop()
        # rop_chain_log = ROPLogger("rop_chain")
        # for address, regs in self.gadget_sequence:
        #     rop_chain_log.print_log(self.gadget_map[address], on_shell=False)
        #     rop_chain_log.print_log(regs, on_shell=False)
        # rop_chain_log.log_close()
        # # self.logger.print_stack_state(self.stack_init_state, self.gadget_map)
        # memory_status_log = ROPLogger('memory_status')
        # memory_status_log.log_memory_status(self.emu.mem_regions(), self.mm, self.gadget_map)
        # memory_status_log.log_close()
        # self.mm.esp_graph.render_graph()

        from copy import deepcopy
        self.output = EmuOutput(
            gadget_sequence=self.gadget_sequence,
            gadget_map=self.gadget_map,
            called_syscall_sequence=list(self.called_syscall_seq),
            branch_handler=self.branch_handler,
            mm_esp_graph=deepcopy(self.mm.esp_graph),
            sequence_spg=self.sequence_spg)
        self.logger.log_close()

    @classmethod
    def emu_config(cls, config):
        # type: (Config) -> Emulator

        state = list(config.stack_init_state)
        state.reverse()
        return cls(config.PE_targets, int(config.first_gadget_addr, 16), state, config.shellcode, config.os_version)
    # endregion Configuration and startup

    # ------------------------------------------------------------------------------------------------------------------
    # region Memory interaction
    class MemoryMap:
        """
        Class that holds memory metadata and methods for memory interaction.

        Attributes:
            :param Uc emu: an emulator instance to interact with memory.
            :param list[tuple] ip_good_areas: list that holds tuples containing starting and ending address of every
                                              memory area considered good.
            :param list[tuple] shellcode_possible_areas: list that holds tuples containing starting and ending address
                                                         of every memory area that could contain a shellcode.
            :param dict[PageUsageBitmap] written_pages: a dictionary whose keys are page aligned addresses and whose
                                                        values are PageUsageBitmaps that hold the write state of the
                                                        memory.
            :param int max_stack_size: the stack size (1 MB).
            :param int stack_base: the address of the base of the stack.
        """

        def __init__(self, emu):
            # type: (Uc) -> None

            self.emu = emu
            self.ip_good_areas = [(IAT_POINTED_PAGE_ADD, IAT_POINTED_PAGE_ADD + UNICORN_PAGE_ALIGNMENT),
                                  (RETURNS_PAGE_ADDRESS, RETURNS_PAGE_ADDRESS + UNICORN_PAGE_ALIGNMENT)]

            self.shellcode_possible_areas = []

            self.memory_shadow = {}
            self.mem_shadow_entry = namedtuple(
                'MemShadowEntry',
                ['address', 'values', 'accessed', 'gadget_accessed', 'accessed_while_empty'],
                verbose=False
            )

            self.written_pages = {}

            self.max_stack_size = 1024 * 1024  # Map 1MB for the stack
            self.stack_base = -1
            self.shadow_stack = OrderedDict()
            self.esp_graph = CFG()

        # region Memory state interaction
        def mmap(self, address, size, prot=UC_PROT_ALL):
            # type: (int, int, int) -> None

            """
            Maps memory for the emulator. The address and the size given as input are automatically aligned.

            Attributes:
                :param int address: the starting address of the region to allocate. If not aligned is aligned by the
                                    method.
                :param int size: the size of the memory to be mapped. If not multiple of 4096 is aligned by the method.
                :param int prot: Unicorn protection level for the memory.
            """

            page_size = get_page_size(size)
            base = self.get_mapping_zone(address, page_size)
            self.emu.mem_map(base, page_size, prot)
            if prot & UC_PROT_EXEC:
                self.ip_good_areas.append((base, base + page_size))
        
        def munmap(self, address, size):
            if address is not None and size is not None and self.is_address_mapped(address):
                add = align_address(address, PREVIOUS)
                s = get_page_size(size)
                self.emu.mem_unmap(add, s)
                self.ip_good_areas.remove((add, add + s))

        def mprotect(self, address, size, prot):
            # type: (int, int, int) -> None

            """
            Change the protection of an emulator memory area. If the area is not mapped it will be mapped with the right
            protection level.

            Attributes:
                :param address: the address of the memory area. Eventually aligned.
                :param size: the size of the memory area. Eventually aligned.
                :param prot: the protection level to be assigned.
            """

            base = align_address(address, PREVIOUS)
            page_size = get_page_size(size)

            for start, end, _ in self.emu.mem_regions():
                if start <= base < end:
                    self.emu.mem_protect(base, end - base + 1, prot)
                    break
            else:
                self.mmap(address, size, prot)

            if prot & UC_PROT_EXEC:
                self.ip_good_areas.append((base, base + page_size))

        def flag_written_zone(self, address, size):
            # type: (int, int) -> None

            """
            Flag a memory area as runtime written. Used to keep track of the usage of the pages.

            Attributes:
                :param address: the address of the written area.
                :param size: the size of the written area.
            """

            map_base = align_address(address, PREVIOUS)
            if map_base not in self.written_pages:
                pbm = PageUsageBitmap(map_base)
                pbm.address_wrote(address, size)
                self.written_pages[map_base] = pbm
            else:
                self.written_pages[map_base].address_wrote(address, size)

        def write_in_shadow_mem(self, address, value, size, read=False):
            if address not in self.memory_shadow:
                if read:
                    self.memory_shadow[address] = self.mem_shadow_entry(
                        address,
                        [(value, size, True)],
                        accessed=True,
                        gadget_accessed=True,
                        accessed_while_empty=False
                    )
                else:
                    self.memory_shadow[address] = self.mem_shadow_entry(
                        address,
                        [(value, size, False)],
                        accessed=False,
                        gadget_accessed=False,
                        accessed_while_empty=False
                    )
            else:
                if not read:
                    self.memory_shadow[address].values.append((value, size, False))

        def get_memory_entry(self, address):
            if address in self.memory_shadow:
                if self.memory_shadow[address].values:
                    return self.memory_shadow[address].values[-1]
                else:
                    return []

        def flag_entry_accessed(self, address):
            if (
                not (self.stack_base - self.max_stack_size <= address < self.stack_base)  # and
                # not (IAT_POINTED_PAGE_ADD <= address < IAT_POINTED_PAGE_ADD + UNICORN_PAGE_ALIGNMENT) and
                # not (RETURNS_PAGE_ADDRESS <= address < RETURNS_PAGE_ADDRESS + UNICORN_PAGE_ALIGNMENT)
            ):
                if address in self.memory_shadow:
                    mem_entry = self.get_memory_entry(address)
                    if mem_entry:
                        value, size, _ = mem_entry
                        sub = self.memory_shadow[address].values[0: -1]
                        sub.append((value, size, True))
                        self.memory_shadow[address] = self.memory_shadow[address]._replace(values=sub)
                        self.memory_shadow[address] = self.memory_shadow[address]._replace(accessed=True)
                        self.memory_shadow[address] = self.memory_shadow[address]._replace(gadget_accessed=True)
                else:
                    self.memory_shadow[address] = self.mem_shadow_entry(address, [], True, True, True)

        def add_stack_shadow_element(self, esp, value, size):
            if esp in self.shadow_stack:
                self.shadow_stack[esp].append((value, size))
            else:
                self.shadow_stack[esp] = [(value, size)]

        def get_last_shadow_stack_entry(self, esp):
            if esp in self.shadow_stack:
                entry = self.shadow_stack[esp]
                return entry[-1]
            else:
                return None, None

        def flag_shellcode_possible_area(self, start, **kwargs):

            """
            Flag an area as suspected to contain shellcode.

            Attributes:
                :param start: the start address of the area.
                :param kwargs: the value could be either size or end. The end is the end address of the area, the size
                               is self explanatory.

            Exceptions:
                :raise TypeError: a TypeError is raised if neither end nor size are provided in kwargs, if there are
                                  additional parameters or there are both size and end and if end is less than start.
            """

            size = kwargs.pop('size', -1)
            if size == -1:
                end = kwargs.pop('end', -1)
                if end == -1:
                    raise TypeError('Neither end nor size provided!')
                elif end < start:
                    raise TypeError('The end address should be greater than the start address: 0x{:x} < 0x{:x}'.format(
                        end, start
                    ))
                elif kwargs:
                    raise TypeError('Unexpected **kwargs: %r' % kwargs)
                elif (start, end) not in self.shellcode_possible_areas:
                    self.shellcode_possible_areas.append((start, end))
            elif kwargs:
                if 'end' in kwargs:
                    raise TypeError('Only one between size and end must be given!')
                else:
                    raise TypeError('Unexpected **kwargs: %r' % kwargs)
            elif (start, start + size) not in self.shellcode_possible_areas:
                self.shellcode_possible_areas.append((start, start + size))

        # endregion Memory state interaction

        # region State queries
        def is_flagged(self, address):
            # type: (int) -> tuple

            """

            Attributes:
                :param int address:

            :return:
            """

            page_aligned_address = align_address(address, PREVIOUS)
            if page_aligned_address in self.written_pages:
                return self.written_pages[page_aligned_address].is_address_wrote(address)
            return False, 0

        def is_address_mapped(self, address):
            # type: (int) -> bool

            for base, end, _ in self.emu.mem_regions():
                if base <= address < end:
                    return True
            return False

        def search_for_complete_mappings(self, _from, _to):
            mappings = []
            for base, end, _ in self.emu.mem_regions():
                if _from <= base and end <= _to:
                    mappings.append((base, end))
            return mappings

        def get_mapping_zone(self, base, size):
            base = align_address(base, PREVIOUS)
            page_size = get_page_size(size)
            while (
                    self.is_address_mapped(base) or
                    self.is_address_mapped(base + page_size) or
                    self.search_for_complete_mappings(base, page_size)
            ):
                base += 4096
            return base

        def is_address_executable(self, address):
            # type: (int) -> bool

            for start, end, prot in self.emu.mem_regions():
                if start <= address < end:
                    return (prot & UC_PROT_EXEC) == 4
            return False

        def is_address_writable(self, address):
            for start, end, prot in self.emu.mem_regions():
                if start <= address < end:
                    return (prot & UC_PROT_WRITE)
            return False

        def is_esp_good(self, esp=None):
            # type: (None) -> bool

            """
            Tells whether the value of esp is in range that is considered good at the time of the call.

            :return: whether esp is good or not.
            """

            esp = self.emu.reg_read(regs_to_code['ESP']) if esp is None else esp
            return self.stack_base - self.max_stack_size <= esp < self.stack_base

        def is_eip_good(self):
            # type: (None) -> bool

            eip = self.emu.reg_read(regs_to_code['EIP'])
            for base, end in self.ip_good_areas:
                if base <= eip < end:
                    return True
            return False

        def is_in_shellocode_zone(self, address=-1):

            eip = self.emu.reg_read(regs_to_code['EIP']) if address == -1 else address
            for base, end in self.shellcode_possible_areas:
                if base <= eip < end:
                    return True
            return False
        # endregion State queries

    # region Emulator memory access
    def push_on_stack(self, value):
        # type: (str) -> None

        int_value, value_size = compute_chain_entry(value)
        if VERBOSE_LOGGING:
            self.logger.print_log("Next value to push 0x%x" % int_value)
        value = pack_data_correct_size(int_value, value_size)
        esp_value = self.reg_read("ESP") - value_size
        if VERBOSE_LOGGING:
            self.logger.print_log("esp value after the push 0x%x" % esp_value, log=False)
        self.emu.reg_write(regs_to_code["ESP"], esp_value)
        self.emu.mem_write(esp_value, value)
        self.mm.add_stack_shadow_element(esp_value, int_value, value_size)

    def peek_from_stack(self, stack_offset=0, size=4):
        # type: (int, int) -> int

        esp = self.reg_read("ESP")
        value = -1
        if self.mm.is_address_mapped(esp + stack_offset) and self.mm.is_address_mapped(esp + stack_offset + size):
            value = struct.unpack("<L", self.emu.mem_read(esp + stack_offset, size))[0]
        return value

    def write_code_at(self, address, code):
        self.emu.mem_write(address, str(code))

    def get_gadget_at(self, address):
        # type: (int) -> ROPGadget

        """
        Search for a ROP gadget in the emulator memory at the given address.

        Args:
            :param address: the address of the gadget to search

        Returns:
            :return: a ROPGadget object representing the found gadget

        Exceptions:
            :raise MemoryError: if the gadget is not present in memory.
        """

        gadget_size = 0
        gadget_bytes = b""

        gadget_max_size = 500
        is_mapped = self.mm.is_address_mapped(address + gadget_max_size)
        while not is_mapped:
            gadget_max_size -= 10
            if gadget_max_size < 0:
                raise MemoryError("The gadget can't be found in memory at address 0x{:x}. Check if the versions of the "
                                  "targeted PEs are right and if the initial state of the stack is correct.".
                                  format(address))
            is_mapped = self.mm.is_address_mapped(address + gadget_max_size)
        gadget_bytes += self.emu.mem_read(address, gadget_max_size)

        return ROPGadget.from_bytes(address, gadget_bytes)
    # endregion Emulator memory access

    # endregion Memory interaction

    # ------------------------------------------------------------------------------------------------------------------
    # region Hooks
    def set_hooks(self):
        self.emu.hook_add(UC_HOOK_MEM_VALID, self.__hook_mem_accesses)
        self.emu.hook_add(UC_HOOK_MEM_READ_AFTER, self.__hook_mem_read_success)
        self.emu.hook_add(UC_HOOK_CODE, self.__hook_code)

        self.emu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.__hook_mem_unmapped)
        self.emu.hook_add(UC_HOOK_MEM_FETCH_PROT | UC_HOOK_MEM_READ_PROT, self.__hook_fetch_prot)
        self.emu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self.__hook_fetch_unmapped)

    def add_unicorn_hook(self, hook_type, hook_func):
        self.emu.hook_add(hook_type, MethodType(hook_func, self))

    # region Control flow hooks
    def __hook_mem_accesses(self, uc, type, address, size, value, user_data):
        if type == UC_MEM_FETCH:
            print "Fetched from 0x{:x}".format(address)
        elif type == UC_MEM_READ:
            print "Read attempt 0x{:x}".format(address)
        elif type == UC_MEM_WRITE:
            print "Write attempt at 0x{:x} -> 0x{:x}".format(address, value)
            if not self.mm.stack_base - self.mm.max_stack_size <= address < self.mm.stack_base:
                self.mm.flag_written_zone(address, size)
                self.mm.write_in_shadow_mem(address, value, size)
            else:
                self.mm.add_stack_shadow_element(address, value, size)
        else:
            # I have broken unicorn
            self.emu_stop()
            return False

        return True

    def __hook_mem_read_success(self, uc, type, address, size, value, user_data):

        print 'Successful read from 0x{:x} -> 0x{:x}'.format(address,
                                                             struct.unpack('<L' * (size // 4) + 'B' * (size % 4),
                                                                           self.emu.mem_read(address, size))[0])
        self.mm.write_in_shadow_mem(address, value, size, read=True)

    def __hook_code(self, uc, address, size, user_data):

        if not self.mm.is_esp_good():

            esp_value = self.reg_read("ESP")
            self.logger.print_log("Unexpected value for ESP 0x{:x}".format(esp_value))
            was_it_written, written_size = self.mm.is_flagged(esp_value)
            if was_it_written:
                self.logger.print_log(" ----------------------------- Stack --------------------------------- ",
                                      log=False)
                mem_value = self.peek_from_stack(size=size)
                # TODO: handle this
                self.logger.print_log(" --------------------------- End stack ------------------------------- ",
                                      log=False)

            self.emu_stop()
            return False

        # https://giphy.com/gifs/instead-87xihBthJ1DkA
        just_do_it = self.continue_with_eip(address)
        if not just_do_it:
            return False
        
        if RETURNS_PAGE_ADDRESS <= address < RETURNS_PAGE_ADDRESS + UNICORN_PAGE_ALIGNMENT:
            if self.to_unmap is not None:
                self.mm.munmap(self.to_unmap[0], self.to_unmap[1])

        sp = self.reg_read('ESP')
        if (sp - 4, address) in self.pp_hooks:
            f, ret = self.pp_hooks.pop((sp - 4, address))
            f(self)
            return ret

        if address in self.current_gadget.instructions:

            self.logger.print_log("executing code at 0x%x" % address, log=False)
            instruction = self.current_gadget.instructions[address]
            self.logger.print_log(instruction)
            if VERBOSE_LOGGING:
                self.print_regs()

            esp_value = self.reg_read('ESP')
            self.branch_handler.monitor_insn(esp_value - 4, self.current_gadget.address, instruction)
            stack_entry, _ = self.mm.get_last_shadow_stack_entry(esp_value - 4)

            if not (
                    self.mm.esp_graph.has_node(sp=esp_value, value=stack_entry) and (
                    self.esp_predecessor.sp, self.esp_predecessor.value) == (esp_value, stack_entry)
            ):
                if stack_entry == self.current_gadget.address:

                    new_node = CFGNode(
                        sp=esp_value,
                        value=stack_entry,
                        gadget=self.gadget_map[stack_entry])
                    self.mm.esp_graph.add_node(new_node)
                    self.mm.esp_graph.add_egde(new_node, self.esp_predecessor)
                    self.esp_predecessor = new_node

            if re.match(".*(?<!, )(\[(.+)\]),? ?(.*)?", str(instruction.op2)):
                self._check_IAT_dereference(instruction.op2)
            elif (
                    (instruction.mnemonic == 'jmp' or instruction.mnemonic == 'call')
                    and re.match(".*(?<!, )(\[(.+)\]),? ?(.*)?", str(instruction.op1))
            ):
                self._check_IAT_dereference(instruction.op1)

            if instruction.mnemonic in gadget_delimiters:  # == 'ret':
                future_eip = self.peek_from_stack()
                self.logger.print_log("before ret the value on stack is 0x{:x}".format(future_eip))
                if VERBOSE_LOGGING:
                    self.print_stack_values()

                if future_eip in address_to_syscall:
                    self.logger.print_log('Import table function called! Called: ' + address_to_syscall[future_eip])
                else:
                    if (
                            self.mm.is_address_executable(future_eip) and
                            not (RETURNS_PAGE_ADDRESS <= future_eip < RETURNS_PAGE_ADDRESS + UNICORN_PAGE_ALIGNMENT) and
                            not (self.mm.stack_base - self.mm.max_stack_size <= future_eip < self.mm.stack_base)
                    ):
                            self.save_log_info()
                            gadget = self.get_gadget_at(future_eip)
                            self.new_gadget_found(gadget.address, gadget)
        else:
            if self.mm.is_address_executable(address):
                self.logger.print_log("Executing code at 0x%x" % address)
                if (
                        not (RETURNS_PAGE_ADDRESS <= address < RETURNS_PAGE_ADDRESS + UNICORN_PAGE_ALIGNMENT) and
                        not (self.mm.stack_base - self.mm.max_stack_size <= address < self.mm.stack_base)
                ):
                    gadget = self.get_gadget_at(address)
                    self.new_gadget_found(address, gadget)
                    self.save_log_info()
                    self.logger.print_log(gadget.instructions[address])

                    esp_value = self.reg_read('ESP')

                    new_node = CFGNode(
                        sp=esp_value,
                        value=gadget.address,
                        gadget=self.gadget_map[gadget.address])
                    self.mm.esp_graph.add_node(new_node)
                    self.mm.esp_graph.add_egde(new_node, self.esp_predecessor)
                    self.esp_predecessor = new_node

                    self.branch_handler.monitor_insn(self.reg_read('ESP') - 4, gadget.address,
                                                     gadget.instructions[address])

        return True

    # endregion Control flow hooks

    # region Error handling hooks
    def __hook_fetch_prot(self, uc, access, address, size, value, user_data):
        self.logger.print_log("\nCallback: fetch from a non-exec area 0x{:x}".format(address))

        if address in address_to_syscall:
            if VERBOSE_LOGGING:
                self.print_stack_values()
            self.logger.print_log("It is a syscall that was located at 0x{:x}: {}".format(address, address_to_syscall[address]))
            syscall_name = address_to_syscall[address]
            return self.call_syscall_if_supported(syscall_name)
        elif self.check_EIP_k32_exports():
            if VERBOSE_LOGGING:
                self.print_stack_values()
            ret_addr = struct.unpack("<L", self.emu.mem_read(self.reg_read('ESP'), 4))[0]
            is_mapped_and_executable = self.mm.is_address_executable(ret_addr)
            if is_mapped_and_executable:
                return True
            else:
                self.logger.print_log("Something is wrong here!")
                return False
        elif self.check_shellcode_if_defined(address):
            return False
        else:
            if VERBOSE_LOGGING:
                self.logger.print_log("State:")
                self.print_regs()
                self.print_stack_values()
            return False

    def __hook_mem_unmapped(self, uc, access, address, size, value, user_data):

        n = get_page_size(size) / 4
        map_base = align_address(address, PREVIOUS)
        self.mm.mmap(map_base, size, UC_PROT_READ | UC_PROT_WRITE)
        self.write_code_at(map_base, b"\xAA\xBB\xCC\xDD" * n)

        if access == UC_MEM_WRITE_UNMAPPED:
            self.write_code_at(address, value)
            self.mm.write_in_shadow_mem(address, value, size)
        else:
            self.mm.flag_entry_accessed(address)

        return True

    def __hook_fetch_unmapped(self, uc, access, address, size, value, user_data):

        if not self.check_shellcode_if_defined(address):
            if self.check_EIP_k32_exports():
                self.mm.mmap(address, size, UC_PROT_READ | UC_PROT_EXEC)
                self.to_unmap = (address, size)
                return True
            elif guess_syscall(self):
                self.mm.mmap(address, size, UC_PROT_READ | UC_PROT_EXEC)
                self.to_unmap = (address, size)
                return True
            else:
                print "\n\n"
                print "=" * 30 + " Debug prints " + "=" * 30
                print "Fetch unmapped\n\taddress: 0x{:x}\n\tsize: {}\n\tvalue: {}\n".format(address, size, value)
                self.print_regs()
                self.print_stack_values()
                print "=" * 73

        return False
    # endregion Error handling hooks

    # endregion Hooks

    # ------------------------------------------------------------------------------------------------------------------
    # region Utilities

    # region Analysis utilities
    def print_regs(self):
        for reg in regs_to_code:
            self.logger.print_log(reg + ": 0x{0:x}".format(self.reg_read(reg)))

    def save_log_info(self):
        regs_values = ""
        for reg_name, reg_code in regs_to_code.items():
            regs_values += reg_name + ": 0x{0:x}".format(self.emu.reg_read(reg_code)) + "\n"
        self.gadget_sequence.append((self.current_gadget.address, regs_values))
        self.sequence_spg.append((self.reg_read('ESP'), self.current_gadget.address))

    def print_stack_values(self):
        self.logger.print_log(" ----------------------------- Stack --------------------------------- ", log=False)
        esp_value = self.reg_read("ESP")
        for addr, entry in ((addr, self.mm.shadow_stack[addr]) for addr in reversed(self.mm.shadow_stack)):
            value, size = entry[len(entry) - 1]
            if addr != esp_value:
                self.logger.print_log("Value at address 0x{:x} = 0x{:<8x}".format(addr, value), False)
            else:
                self.logger.print_log("Value at address 0x{:x} = 0x{:<8x}  <== ESP".format(addr, value), False)
        self.logger.print_log(" --------------------------- End stack ------------------------------- ", log=False)

    def search_gadget(self, g_addr, occur=1):
        seq = [g for g, _ in self.gadget_sequence]
        num_occur = seq.count(g_addr)
        if occur > num_occur:
            return None
        idx = seq.index(g_addr)
        ret = idx
        for i in xrange(1, occur):
            idx = seq[ret + 1:].index(g_addr)
            ret += idx + 1
        return self.gadget_sequence[ret]

    def add_function_hook(self, f, address=-1, name='', ret=False):
        if address == -1 and name:
            self.function_hooks[name] = (f, ret)
        elif address != -1 and not name:
            self.function_hooks[address] = (f, ret)

    def add_pp_hook(self, sp, ip, f, ret=False):
        self.pp_hooks[sp, ip] = (f, ret)
    # endregion

    # region General utilities
    def get_right_PE(self, address):

        for pe in self.PE_targets:
            if pe.check_address(address):
                return pe
        return None

    def reg_read(self, reg):
        return self.emu.reg_read(regs_to_code[reg])

    def new_gadget_found(self, address, gadget):
        self.current_gadget = gadget
        self.gadget_map[address] = gadget
    # endregion

    # region Control flow checks
    def check_shellcode_if_defined(self, address):

        if self.shellcode and self.mm.is_in_shellocode_zone(address):
            self.logger.print_log("Shellcode reached!")
            self.emu_stop()
            return True
        else:
            return False

    def _check_IAT_dereference(self, operation):
        s = operation.index("[")
        e = operation.index("]")
        address_to_deref = operation[s + 1: e].upper()
        if address_to_deref.upper()[0: 3] in regs_to_code:
            reg_name = address_to_deref[0: 3]  # exclude things like reg + const TODO
            value = self.reg_read(reg_name)
        else:
            value = int(address_to_deref, 16)
        pe_target = self.get_right_PE(value)
        if pe_target is not None and value in pe_target.import_table:
            syscall_name = pe_target.import_table[value]
            if syscall_name not in syscall_to_address:
                print 'New IAT dereference: {}'.format(syscall_name)
                self.emu.mem_write(value, struct.pack('<L', self.IAT_page_pointer))
                address_to_syscall[self.IAT_page_pointer] = syscall_name
                syscall_to_address[syscall_name] = self.IAT_page_pointer
                self.IAT_page_pointer += 1
            else:
                print 'Another IAT dereference to: {}'.format(syscall_name)
                self.emu.mem_write(value, struct.pack('<L', syscall_to_address[syscall_name]))

    def continue_with_eip(self, address):

        if address in self.function_hooks:
            f, ret = self.function_hooks[address]
            f(self)
            return ret

        shellcode_defined = self.check_shellcode_if_defined(address)
        if not shellcode_defined and not self.mm.is_eip_good():
            # the instruction pointer is not considered good at this point, still in a mapped zone
            # it is not a shellcode address, it could be a runtime written zone containing code
            self.logger.print_log("Unexpected EIP value 0x{:x}".format(address))
            if not self.mm.is_address_executable(address):
                if self.check_EIP_k32_exports():
                    return True
                elif guess_syscall(self):
                    return True
                else:
                    # TODO: if contains something ask if the privileges have to be forced to continues
                    # it doesn't contain code. this is bad
                    self.emu_stop()
                    return False
            else:
                # it does contain something executable, check if it was runtime written and ask the analyst if he
                # wants to continue the execution. show what's inside the memory (?) TODO
                is_written, written_size = self.mm.is_flagged(address)
                if is_written:
                    content = self.emu.mem_read(address, written_size)
                    # TODO: act about this
                    return True
                else:
                    self.logger.print_log("EIP points to a zone that may contain junk, "
                                          "the execution will be stopped", log=False)
                    self.emu_stop()
                    return False
        else:
            if address in address_to_syscall:
                self.call_syscall_if_supported(address_to_syscall[address])
            return not shellcode_defined

    def check_EIP_k32_exports(self):
        address = self.reg_read('EIP')
        name_by_addr, name_by_rva = (self.k32_exp.get_name_by_address(address),
                                     self.k32_exp.get_name_by_RVA(address))
        if name_by_addr:  # TODO: handle lists
            self.logger.print_log('Hardwired function called! Called: ' + name_by_addr)
            return self.call_syscall_if_supported(name_by_addr)
        elif name_by_rva:
            self.logger.print_log('Hardwired function called! Called: ' + name_by_rva)
            return self.call_syscall_if_supported(name_by_rva)
        else:
            return False

    def call_syscall_if_supported(self, syscall_name):
        if syscall_name in supported_syscall:
            supported_syscall[syscall_name](self)
            self.called_syscall_seq.append(syscall_name)
            if syscall_name != 'exit':
                addr = right_sized_ret[syscall_name]
                self.emu.reg_write(regs_to_code["EIP"], addr)
                return True
            else:
                return False
        else:
            if syscall_name in self.function_hooks:
                f, ret = self.function_hooks[syscall_name]
                f(self)
                return ret
            self.logger.print_log('Syscall {} not supported!'.format(syscall_name))
            self.emu_stop()
            return False
    # endregion Control flow checks

    # endregion Utilities

