import os
from unicorn import *


class ROPLogger:

    _path = "debug/"

    def __init__(self, name="rop_logger", trucate=True):
        if not os.path.exists(self._path):
            os.makedirs(self._path)
        self.__name = os.path.join(self._path, name)
        self._log_file = open(self.__name, "w") if trucate else open(self.__name, "a")
        self.__open = True

    def print_log(self, s, log=True, on_shell=True):
        if on_shell:
            print s
        if log and self.__open:
            print >> self._log_file, s

    def log_close(self):
        self._log_file.close()
        self.__open = False

    # def print_stack_state(self, stack_state, gadget_map):
    #     self.print_log('=' * 20 + 'Final stack values' + '=' * 20)
    #     for address in stack_state:
    #         if not (type(address) in (int, long)):
    #             address = int(address, 16)
    #         if address in gadget_map:
    #             self.print_log("0x{:<8x} [GADGET ADDRESS]".format(address))
    #         else:
    #             self.print_log("0x{:<8x} [DATA]".format(address))
    #     self.print_log('=' * 58)

    def log_memory_status(self, mem_regions, mm, gadget_map):

        written_pages = mm.written_pages
        mem_shadow = mm.memory_shadow
        stack_top = mm.stack_base - mm.max_stack_size
        stack_shadow = mm.shadow_stack

        prot2s = {UC_PROT_NONE: 'None', UC_PROT_READ: 'READ', UC_PROT_WRITE: 'WRITE',
                  UC_PROT_READ | UC_PROT_WRITE: 'READ_WRITE', UC_PROT_EXEC: 'EXEC',
                  UC_PROT_READ | UC_PROT_EXEC: 'READ_EXEC', UC_PROT_WRITE | UC_PROT_EXEC: 'WRITE_EXEC',
                  UC_PROT_ALL: 'READ_WRITE_EXEC'}

        # Iterate through mapped regions
        for begin, end, prot in mem_regions:
            self.print_log("[+] From 0x{:x} to 0x{:x} with protection level {}".format(begin, end, prot2s[prot]),
                           on_shell=False)

            # Check if the page was rt written then for every address in the page we need to check if that chunk of the
            # page was actually written
            if begin in written_pages:
                self.print_log("\t[+] The page was written at runtime", on_shell=False)
                address_iterator = iter(range(begin, end))

                for a in address_iterator:
                    was_wrote, written_size = written_pages[begin].is_address_wrote(a)

                    # Find the parts of the page that are written
                    if was_wrote and a in mem_shadow:
                        self.print_log("\t\t[+] Written zone [ 0x{:x} - 0x{:x} (size={})]".
                                       format(a, a + written_size, written_size), on_shell=False)
                        self.print_log("\t\t\t- Write history for the address 0x{:x} => [{}]".format(a, ', '.join(
                            [
                                hex(v).rstrip('L') for v in
                                [value[0] for value in mem_shadow[a].values]
                            ]
                        )), on_shell=False)
                        if mem_shadow[a].accessed:
                            if mem_shadow[a].accessed_while_empty:
                                self.print_log(
                                    '\t\t\t\t[-] Memory location [ 0x{:x} - 0x{:x} (size={})] was accessed while empty!'
                                    .format(a, a + mm.get_memory_entry(a)[1], written_size), on_shell=False
                                )
                            if mem_shadow[a].values:
                                self.print_log("\t\t\t\t[+] Actually accessed values of the history [{}]".format(
                                    ', '.join([hex(value[0]).rstrip('L') for value in mem_shadow[a].values if value[2]])
                                ), on_shell=False)
                                self.print_log("\t\t\t\t[-] Never accessed values [{}]".format(
                                    ', '.join([hex(value[0]).rstrip('L') for value in mem_shadow[a].values if not value[2]])
                                ), on_shell=False)
                        else:
                            self.print_log("\t\t\t\t[-] Never accessed address 0x{:x}".format(a), on_shell=False)
                        # [next(address_iterator, '') for x in range(written_size)]
                    else:
                        if a in mem_shadow and mem_shadow[a].accessed_while_empty:
                            self.print_log('\t\t[-] Memory location 0x{:x} accessed while empty!'.format(a),
                                           on_shell=False)
                        if a in mem_shadow and mem_shadow[a].accessed:
                            self.print_log('\t\t[-] Never runtime written memory location', on_shell=False)
                            if mem_shadow[a].values:
                                self.print_log("\t\t\t- Read history for the address 0x{:x} => [{}]".format(a, ', '.join(
                                    [
                                        hex(v).rstrip('L') for v in
                                        [value[0] for value in mem_shadow[a].values]
                                    ]
                                )), on_shell=False)

            if begin == stack_top:
                for address, entry in stack_shadow.items():
                    self.print_log('\t[+] 0x{:x} = [{}]'.format(address, ', '.join(
                        [
                            hex(v).rstrip('L') for v, _ in stack_shadow[address]
                        ])), on_shell=False)
                    for v, _ in stack_shadow[address]:
                        if v in gadget_map:
                            self.print_log('\t\t[+] 0x{:x} GADGET ADDRESS'.format(v), on_shell=False)
                        else:
                            self.print_log('\t\t[-] 0x{:x} DATA'.format(v), on_shell=False)
