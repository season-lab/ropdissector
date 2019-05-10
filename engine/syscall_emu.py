import random

from collections import namedtuple
from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_ALL
from unicorn.x86_const import UC_X86_REG_EAX

from utility import *
from rop_logger import *


# TODO: add the Ex and the W and A versions of every syscall

__syscall_logger = ROPLogger('syscall_log')


def log_syscall_info(syscall_sig, additional_info):
    __syscall_logger = ROPLogger('syscall_log', trucate=False)
    __syscall_logger.print_log(syscall_sig, on_shell=False)
    __syscall_logger.print_log(additional_info, on_shell=False)
    __syscall_logger.log_close()


def virtualalloc_emu(emu):
    lpaddress = emu.peek_from_stack(stack_offset=4)
    dwsize = emu.peek_from_stack(stack_offset=8)
    flallocationtype = emu.peek_from_stack(stack_offset=12)
    mem_protection = emu.peek_from_stack(stack_offset=16)

    print "\n[+] Emulating VirtualAlloc"

    memory_prot = {0x10: 'PAGE_EXECUTE', 0x20: 'PAGE_EXECUTE_READ', 0x40: 'PAGE_EXECUTE_READWRITE'}
    allocation_type = {0x00001000: 'MEM_COMMIT', 0x00002000: 'MEM_RESERVE'}
    print "[+] Params:"
    print "\t[-] lpAddress: 0x{:x}".format(lpaddress)
    print "\t[-] dwSize: {} (hex: 0x{:x})".format(dwsize, dwsize)
    print "\t[-] flAllocationType: 0x{:x} ({})".format(flallocationtype, allocation_type[flallocationtype])
    print "\t[-] flProtect: 0x{:x} ({})".format(mem_protection, memory_prot[mem_protection])

    aligned_lpaddress = align_address(lpaddress, PREVIOUS)
    dwsize = get_page_size(dwsize)

    print "Mapping from " + hex(aligned_lpaddress) + " " + str(dwsize) + " bytes!\n"

    protection = __memory_prot[mem_protection]
    is_mapped = emu.mm.is_address_mapped(lpaddress)
    if flallocationtype == 0x1000 and not is_mapped:
        emu.mm.mmap(aligned_lpaddress, dwsize, protection)
    else:
        emu.mm.mprotect(aligned_lpaddress, dwsize, protection)
    if protection & UC_PROT_EXEC:
        emu.mm.flag_shellcode_possible_area(aligned_lpaddress, size=dwsize)
    return aligned_lpaddress


def virtualprotect_emu(emu):
    lpaddress = emu.peek_from_stack(stack_offset=4)
    dwsize = emu.peek_from_stack(stack_offset=8)
    flnewprotect = emu.peek_from_stack(stack_offset=12)
    oldprotect = emu.peek_from_stack(stack_offset=16)

    print "\n[+] Emulating VirtualProtect"

    memory_prot = {0x10: 'PAGE_EXECUTE', 0x20: 'PAGE_EXECUTE_READ', 0x40: 'PAGE_EXECUTE_READWRITE'}
    print "[+] Params:"
    print "\t[-] lpAddress: 0x{:x}".format(lpaddress)
    print "\t[-] dwSize: {} (hex: 0x{:x})".format(dwsize, dwsize)
    print "\t[-] flNewProtect: 0x{:x} ({})".format(flnewprotect, memory_prot[flnewprotect])
    print "\t[-] lpflOldProtect: 0x{:x}".format(oldprotect)

    dwsize = get_page_size(dwsize)
    aligned_lpaddress = align_address(lpaddress, PREVIOUS)

    print "Changing permissions of " + str(dwsize) + " bytes from " + hex(aligned_lpaddress)
    print

    new_protection = __memory_prot[flnewprotect]
    emu.mm.mprotect(lpaddress, dwsize, new_protection)

    if new_protection & UC_PROT_EXEC:
        emu.mm.flag_shellcode_possible_area(aligned_lpaddress, size=dwsize)

    return aligned_lpaddress


def setDEPpolicy_emu(emu):
    dwflags = emu.peek_from_stack(stack_offset=4)
    if dwflags == 0:
        print "Emulating SetProcessDEPPolicy - Disabling DEP!"
        for start, end, prot in emu.emu.mem_regions():
            if not (prot & UC_PROT_EXEC):
                emu.mm.mprotect(start, end - start + 1, prot | UC_PROT_EXEC)
                emu.mm.flag_shellcode_possible_area(start, end=end)
    return True


class LoadGetProcCombo:
    def __init__(self):
        self._emu = None
        self.handle_to_lib = {}

    def set_emu(self, emu):
        if not self._emu:
            self._emu = emu

    def loadlibrary(self):
        lpFileName = self._emu.peek_from_stack(stack_offset=4)
        name = _get_string_from_memory(self._emu, lpFileName)
        print 'Emulating LoadLibrary - Loading {}'.format(name)
        handle = random.getrandbits(32)
        self._emu.emu.reg_write(UC_X86_REG_EAX, handle)
        self.handle_to_lib[handle] = name.replace('.dll', '')

    def getprocaddress(self):
        hModule = self._emu.peek_from_stack(stack_offset=4)
        lpProcName = self._emu.peek_from_stack(stack_offset=8)
        if hModule not in self.handle_to_lib:
            self._emu.emu_stop()
        else:
            procName = _get_string_from_memory(self._emu, lpProcName)
            if procName not in syscall_to_address:
                print 'Emulating GetProcAddress - Loading {}.{} at address 0x{:x}'.format(
                    self.handle_to_lib[hModule],
                    procName,
                    self._emu.IAT_page_pointer)
                self._emu.emu.reg_write(UC_X86_REG_EAX, self._emu.IAT_page_pointer)
                address_to_syscall[self._emu.IAT_page_pointer] = procName
                syscall_to_address[procName] = self._emu.IAT_page_pointer
                self._emu.emu.reg_write(UC_X86_REG_EAX, self._emu.IAT_page_pointer)
                self._emu.IAT_page_pointer += 1
            else:
                self._emu.emu.reg_write(UC_X86_REG_EAX, syscall_to_address[procName])


def loadlibrary_emu(emu):
    __loadlibgetproc_combo.set_emu(emu)
    __loadlibgetproc_combo.loadlibrary()


def getprocaddress_emu(emu):
    __loadlibgetproc_combo.set_emu(emu)
    __loadlibgetproc_combo.getprocaddress()


def wcsstr_emu(emu):
    # FIXME: I'm assuming to find wcs2 into wcs1
    wcs1 = emu.peek_from_stack(stack_offset=4)
    wcs2 = emu.peek_from_stack(stack_offset=8)

    to_search = _get_string_from_memory(emu, wcs2)
    i = 0
    while True:
        content_read = emu.emu.mem_read(wcs1 + i, 100)
        if to_search in str(content_read):
            i += str(content_read).index(to_search)
            break
        else:
            i += 100

    emu.emu.reg_write(UC_X86_REG_EAX, wcs1 + i)


def cryptstringtobinary_emu(emu):
    pszString = emu.peek_from_stack(stack_offset=4)
    cchString = emu.peek_from_stack(stack_offset=8)
    dwFlags = emu.peek_from_stack(stack_offset=12)
    pbBinary = emu.peek_from_stack(stack_offset=16)
    pcbBinary = emu.peek_from_stack(stack_offset=20)
    pdwSkip = emu.peek_from_stack(stack_offset=24)
    pdwFlags = emu.peek_from_stack(stack_offset=28)

    flag_to_str = {
        0x00000000: 'CRYPT_STRING_BASE64HEADER',
        0x00000001: 'CRYPT_STRING_BASE64',
        0x00000002: 'CRYPT_STRING_BINARY',
        0x00000003: 'CRYPT_STRING_BASE64REQUESTHEADER',
        0x00000004: 'CRYPT_STRING_HEX',
        0x00000005: 'CRYPT_STRING_HEXASCII',
        0x00000006: 'CRYPT_STRING_BASE64_ANY',
        0x00000007: 'CRYPT_STRING_ANY',
        0x00000008: 'CRYPT_STRING_HEX_ANY',
        0x00000009: 'CRYPT_STRING_BASE64X509CRLHEADER',
        0x0000000a: 'CRYPT_STRING_HEXADDR',
        0x0000000b: 'CRYPT_STRING_HEXASCIIADDR',
        0x0000000c: 'CRYPT_STRING_HEXRAW',
        0x20000000: 'CRYPT_STRING_STRICT'
    }
    input_str = _get_string_from_memory(emu, pszString)

    emu.write_code_at(pbBinary, 'CS2B_dummy\x00')
    emu.write_code_at(pcbBinary, 11)

    syscall_sig = ("== START\n\n"
                   "CryptStringToBinary(\n"
                   "\t_In_    LPCTSTR pszString  = 0x{:x},\n"
                   "\t_In_    DWORD   cchString  = 0x{:x},\n"
                   "\t_In_    DWORD   dwFlags    = 0x{:x} [{}],\n"
                   "\t_In_    BYTE    *pbBinary  = 0x{:x},\n"
                   "\t_Inout_ DWORD   *pcbBinary = 0x{:x},\n"
                   "\t_Out_   DWORD   *pdwSkip   = 0x{:x},\n"
                   "\t_Out_   DWORD   *pdwFlags  = 0x{:x}\n"
                   ");\n".format(
                       pszString, cchString, dwFlags, flag_to_str[dwFlags], pbBinary, pcbBinary, pdwSkip, pdwFlags)
                   )
    additional_info = ("Input string  *pszString = {}\n"
                       "Output buffer *pbBinary  = CS2B_dummy\n"
                       "Output length *pcbBinary = 11\n"
                       "\n== END\n".format(input_str))

    log_syscall_info(syscall_sig, additional_info)

    emu.emu.reg_write(UC_X86_REG_EAX, 1)


def rtldecompressbuffer_emu(emu):
    CompressionFormat = emu.peek_from_stack(stack_offset=4)
    UncompressedBuffer = emu.peek_from_stack(stack_offset=8)
    UncompressedBufferSize = emu.peek_from_stack(stack_offset=12)
    CompressedBuffer = emu.peek_from_stack(stack_offset=16)
    CompressedBufferSize = emu.peek_from_stack(stack_offset=20)
    FinalUncompressedSize = emu.peek_from_stack(stack_offset=24)

    format_to_s = {
        0x2: 'COMPRESSION_FORMAT_LZNT1',
        0x4: 'COMPRESSION_FORMAT_XPRESS'
    }

    emu.write_code_at(UncompressedBuffer, 'RTLDB_dummy\x00')
    emu.write_code_at(FinalUncompressedSize, 12)

    syscall_sig = ("== START\n\n"
                   "RtlDecompressBuffer(\n"
                   "\tUSHORT CompressionFormat      = 0x{:x} [{}],\n"
                   "\tPUCHAR UncompressedBuffer     = 0x{:x},\n"
                   "\tULONG  UncompressedBufferSize = 0x{:x},\n"
                   "\tPUCHAR CompressedBuffer       = 0x{:x},\n"
                   "\tULONG  CompressedBufferSize   = 0x{:x},\n"
                   "\tPULONG FinalUncompressedSize  = 0x{:x}\n"
                   ");\n".format(
                        CompressionFormat, format_to_s[CompressionFormat], UncompressedBuffer, UncompressedBufferSize,
                        CompressedBuffer, CompressedBufferSize, FinalUncompressedSize)
                   )
    additional_info = ("Input buffer  *CompressedBuffer      = {}\n"
                       "Output buffer *UncompressedBuffer    = RTLDB_dummy\n"
                       "Output size   *FinalUncompressedSize = 12\n"
                       "\n== END\n".format(_get_string_from_memory(emu, CompressedBuffer)))

    log_syscall_info(syscall_sig, additional_info)
    pass


def gettemppath_emu(emu):
    nBufferLength = emu.peek_from_stack(stack_offset=4)
    lpBuffer = emu.peek_from_stack(stack_offset=8)

    syscall_sig = ("== START\n\n"
                   "GetTempPath(\n"
                   "\t_In_  DWORD  nBufferLength = {},\n"
                   "\t_Out_ LPTSTR lpBuffer      = 0x{:x}\n"
                   ");\n".format(nBufferLength, lpBuffer))

    import tempfile
    t = tempfile.gettempdir() + "\\"
    length = len(t)
    if length > nBufferLength:
        additional_info = ("Temp path length = {} > {}\n"
                           "Output           = {}\n"
                           "\n== END\n".format(length, nBufferLength, length))
        emu.emu.reg_write(UC_X86_REG_EAX, length)
    else:
        emu.write_code_at(lpBuffer, t)
        additional_info = ("Output *lpBuffer = {}\n"
                           "\n== END\n".format(t))
        emu.emu.reg_write(UC_X86_REG_EAX, length)

    log_syscall_info(syscall_sig, additional_info)


class WindowsFile:

    creation_disposition = {1: 'CREATE_NEW', 2: 'CREATE_ALWAYS', 3: 'OPEN_EXISTING', 4: 'OPEN_ALWAYS',
                              5: 'TRUNCATE_EXISTING'}

    desired_access = {0x80000000L, 0x40000000L, 0x20000000L, 0x10000000L}

    __memory_prot = {0x2: UC_PROT_READ, 0x4: UC_PROT_READ | UC_PROT_WRITE, 0x8: UC_PROT_READ,
                 0x10: UC_PROT_EXEC, 0x20: UC_PROT_EXEC | UC_PROT_READ, 0x40: UC_PROT_ALL, 0x80: UC_PROT_EXEC}

    __FILE_MAP_COPY = 0x00000001
    __FILE_MAP_WRITE = 0x0002
    __FILE_MAP_READ = 0x0004
    __SECTION_MAP_EXECUTE = 0x0008
    __FILE_MAP_EXECUTE = 0x0020

    __map_desired_access = {__FILE_MAP_COPY: UC_PROT_READ | UC_PROT_WRITE, __FILE_MAP_EXECUTE: UC_PROT_EXEC,
                            __FILE_MAP_WRITE: UC_PROT_WRITE, __FILE_MAP_READ: UC_PROT_READ}

    share_mode = {0: 'NO_SHARE', 1: 'FILE_SHARE_READ', 2: 'FILE_SHARE_WRITE', 4: 'FILE_SHARE_DELETE', }

    def __init__(self):
        self._emu = None
        self._file = namedtuple(
            'FileOBJ',
            ['filename', 'desiredAccess', 'shareMode', 'creationDisposition'],
            verbose=False
        )
        self._files = {}
        self._file_mappings = {}

    def set_emu(self, emu):
        if not self._emu:
            self._emu = emu

    def createfile(self):
        lpFileName = self._emu.peek_from_stack(stack_offset=4)
        dwDesiredAccess = self._emu.peek_from_stack(stack_offset=8)
        dwShareMode = self._emu.peek_from_stack(stack_offset=12)
        lpSecurityAttributes = self._emu.peek_from_stack(stack_offset=16)
        dwCreationDisposition = self._emu.peek_from_stack(stack_offset=20)
        dwFlagsAndAttributes = self._emu.peek_from_stack(stack_offset=24)
        hTemplateFile = self._emu.peek_from_stack(stack_offset=28)

        file_name = _get_string_from_memory(self._emu, lpFileName)
        share = self.share_mode[dwShareMode]
        creation_disposition = self.creation_disposition[dwCreationDisposition]

        handle = random.getrandbits(32)
        self._files[handle] = self._file(file_name, dwDesiredAccess, share, creation_disposition)

        self._emu.emu.reg_write(UC_X86_REG_EAX, handle)

    def createfilemapping(self):
        hFile = self._emu.peek_from_stack(stack_offset=4)
        lpFileMappingAttributes = self._emu.peek_from_stack(stack_offset=8)
        flProtect = self._emu.peek_from_stack(stack_offset=12)
        dwMaximumSizeHigh = self._emu.peek_from_stack(stack_offset=16)
        dwMaximumSizeLow = self._emu.peek_from_stack(stack_offset=20)
        lpName = self._emu.peek_from_stack(stack_offset=24)

        if hFile in self._files:
            prot = self.__memory_prot[flProtect]
            hmap = random.getrandbits(32)
            self._file_mappings[hmap] = prot
            self._emu.emu.reg_write(UC_X86_REG_EAX, hmap)

    def mapviewoffile(self):
        hFileMappingObject = self._emu.peek_from_stack(stack_offset=4)
        dwDesiredAccess = self._emu.peek_from_stack(stack_offset=8)
        dwMaximumSizeHigh = self._emu.peek_from_stack(stack_offset=12)
        dwMaximumSizeLow = self._emu.peek_from_stack(stack_offset=16)
        dwNumberOfBytesToMap = self._emu.peek_from_stack(stack_offset=20)

        if hFileMappingObject in self._file_mappings:
            prot = UC_PROT_NONE
            if dwDesiredAccess & self.__SECTION_MAP_EXECUTE:
                prot |= UC_PROT_ALL
            else:
                if dwDesiredAccess & self.__FILE_MAP_COPY:
                    prot |= self.__map_desired_access[self.__FILE_MAP_COPY]
                if dwDesiredAccess & self.__FILE_MAP_READ:
                    prot |= self.__map_desired_access[self.__FILE_MAP_READ]
                if dwDesiredAccess & self.__FILE_MAP_EXECUTE:
                    prot |= self.__map_desired_access[self.__FILE_MAP_EXECUTE]
                if dwDesiredAccess & self.__FILE_MAP_WRITE:
                    prot |= self.__map_desired_access[self.__FILE_MAP_WRITE]
            addr = self._emu.mm.get_mapping_zone(0, dwNumberOfBytesToMap)
            self._emu.mm.mmap(addr, dwNumberOfBytesToMap, prot)
            if prot & UC_PROT_EXEC:
                self._emu.mm.flag_shellcode_possible_area(addr, size=get_page_size(dwNumberOfBytesToMap))
            self._emu.emu.reg_write(UC_X86_REG_EAX, addr)
    
    @property
    def files(self):
        return self._files


def createfile_emu(emu):
    __winfile.set_emu(emu)
    __winfile.createfile()


def createfilemapping_emu(emu):
    __winfile.set_emu(emu)
    __winfile.createfilemapping()


def mapviewoffile_emu(emu):
    __winfile.set_emu(emu)
    __winfile.mapviewoffile()


def memcpy(emu):
    destination = emu.peek_from_stack(stack_offset=4)
    source = emu.peek_from_stack(stack_offset=8)
    num = emu.peek_from_stack(stack_offset=12, size=4)

    if emu.mm.is_address_mapped(source):
        if not emu.mm.is_address_mapped(destination):
            emu.mm.mmap(destination, num, UC_PROT_READ | UC_PROT_WRITE)
        if emu.mm.is_in_shellocode_zone(address=source) and not emu.mm.is_in_shellocode_zone(address=destination):
            emu.mm.flag_shellcode_possible_area(destination, size=get_page_size(num))
        written, size = emu.mm.is_flagged(source)
        if written:
            content = emu.emu.mem_read(source, size)
            emu.emu.mem_write(destination, content)


def fopen_emu(emu):
    filename = emu.peek_from_stack(stack_offset=4)
    mode = emu.peek_from_stack(stack_offset=8)

    syscall_sig = ("== START\n\n"
                   "fopen(\n"
                   "\tconst char * filename = 0x{:x},\n"
                   "\tconst char * mode     = 0x{:x}\n"
                   ");\n".format(filename, mode)
                   )
    additional_info = ("Input file name *filename = {}\n"
                       "Open mode       *mode     = {}\n"
                       "Output handle             = 0xABADCAFE\n"
                       "\n== END\n".format(_get_string_from_memory(emu, filename), _get_string_from_memory(emu, mode)))

    log_syscall_info(syscall_sig, additional_info)

    emu.emu.reg_write(UC_X86_REG_EAX, 0xABADCAFE)


def fwrite_emu(emu):
    ptr = emu.peek_from_stack(stack_offset=4)
    size = emu.peek_from_stack(stack_offset=8)
    nmemb = emu.peek_from_stack(stack_offset=12)
    stream = emu.peek_from_stack(stack_offset=16)

    syscall_sig = ("== START\n\n"
                   "fwrite(\n"
                   "\tconst void *ptr = 0x{:x},\n"
                   "\tsize_t size     = 0x{:x},\n"
                   "\tsize_t nmemb    = 0x{:x},\n"
                   "\tFILE *stream    = 0x{:X}\n"
                   ");\n".format(ptr, size, nmemb, stream))

    additional_info = ("Input to be written *ptr = {}\n"
                       "\n== END\n".format(_get_string_from_memory(emu, ptr)))

    log_syscall_info(syscall_sig, additional_info)
    pass


def fclose_emu(emu):
    stream = emu.peek_from_stack(stack_offset=4)
    if stream != 0xABADCAFE:
        print 'Wrong handle'
        emu.emu_stop()
        return False

    emu.emu.reg_write(UC_X86_REG_EAX, 0)
    return True


def printf_emu(emu):
    format_str_p = emu.peek_from_stack(stack_offset=4)
    format_str = _get_string_from_memory(emu, format_str_p)
    copy_str = format_str
    offset = 4
    specifier_pos = copy_str.find('%')
    while specifier_pos != -1:
        specifier = copy_str[specifier_pos + 1 : specifier_pos + 2]
        if specifier == 'c':
            offset += 1
            to_print = emu.peek_from_stack(stack_offset=offset)
        else:
            offset += 4
            to_print = emu.peek_from_stack(stack_offset=offset)
        format_str = format_str[:specifier_pos] + '{:' + specifier + '}' + format_str[specifier_pos + 2:]
        format_str = format_str.format(to_print)
        copy_str = copy_str[specifier_pos + 2:]
        specifier_pos = copy_str.find('%')
    print 'Result of printf: ' + format_str


def exit_emu(emu):
    print 'Exit called with exit status {}'.format(emu.peek_from_stack(stack_offset=4))
    emu.emu_stop()


def nooperation_syscall_emu(_):
    pass


RETURNS_PAGE_ADDRESS = int("0xffff0000", 16)
IAT_POINTED_PAGE_ADD = RETURNS_PAGE_ADDRESS + UNICORN_PAGE_ALIGNMENT


def map_returns(emu):
    ret = b'\xc3'
    returns = [b"\xc2{}\x00\x00".format(chr(hex_v)) for hex_v in xrange(1, 100)]
    emu.emu.mem_map(RETURNS_PAGE_ADDRESS, UNICORN_PAGE_ALIGNMENT, UC_PROT_READ | UC_PROT_EXEC)
    emu.write_code_at(RETURNS_PAGE_ADDRESS, ret)
    for code, offset in step_enumerate(returns, 4, 4):
        emu.write_code_at(RETURNS_PAGE_ADDRESS + offset, code)


# Returns the address of the correct return to be used
# based on the number of bytes to be eliminated from stack
def _ret_address(return_size):
    # type: (int) -> int

    if return_size == 0:
        return int("0xffff0000", 16)
    else:
        return int("0xffff0000", 16) + (return_size * 4)


def _get_string_from_memory(emu, lpString):
    i = 0
    string = ''
    # TODO: mem_shadow interaction, is_string field
    while True:
        if not emu.mm.is_address_mapped(lpString):
            return ''
        content_read = emu.emu.mem_read(lpString + i, 1)
        if content_read == '\x00':
            break
        string += content_read
        i += 1
    return str(string)


__winfile = WindowsFile()
__loadlibgetproc_combo = LoadGetProcCombo()


supported_syscall = {
    'VirtualAlloc': virtualalloc_emu,
    'VirtualProtect': virtualprotect_emu,
    'SetProcessDEPPolicy': setDEPpolicy_emu,
    'LoadLibraryA': loadlibrary_emu,
    'GetProcAddress': getprocaddress_emu,
    'wcsstr': wcsstr_emu,
    'CryptStringToBinaryA': cryptstringtobinary_emu,
    'RtlDecompressBuffer': rtldecompressbuffer_emu,
    'GetTempPathA': gettemppath_emu,
    'fopen': fopen_emu,
    'CreateFileA': createfile_emu,
    'CreateFileMappingA': createfilemapping_emu,
    'MapViewOfFile': mapviewoffile_emu,
    'fwrite': fwrite_emu,
    'fclose': fclose_emu,
    'memcpy': memcpy,
    'Sleep': nooperation_syscall_emu,
    'printf': printf_emu,
    'exit': exit_emu,
}

params_for_function = dict()
params_for_function[1] = ['Sleep', 'LoadLibraryA', 'fclose', 'exit', 'printf']  # printf should be always included since has VARGS
params_for_function[2] = params_for_function[1] + ['GetProcAddress', 'GetTempPathA', 'wcsstr', 'fopen']
params_for_function[3] = params_for_function[2] + ['memcpy']
params_for_function[4] = params_for_function[3] + ['VirtualAlloc', 'VirtualProtect', 'fwrite']
params_for_function[5] = params_for_function[4] + ['MapViewOfFile']
params_for_function[6] = params_for_function[5] + ['RtlDecompressBuffer', 'CreateFileMappingA']
params_for_function[7] = params_for_function[6] + ['CryptStringToBinaryA', 'CreateFileA']


right_sized_ret = {
    'VirtualAlloc': _ret_address(16),
    'VirtualProtect': _ret_address(16),
    'SetProcessDEPPolicy': _ret_address(4),
    'LoadLibraryA': _ret_address(4),
    'GetProcAddress': _ret_address(8),
    'wcsstr': _ret_address(0),
    'CryptStringToBinaryA': _ret_address(28),
    'RtlDecompressBuffer': _ret_address(24),
    'GetTempPathA': _ret_address(8),
    'fopen': _ret_address(0),
    'CreateFileA': _ret_address(28),
    'CreateFileMappingA': _ret_address(24),
    'MapViewOfFile': _ret_address(20),
    'memcpy': _ret_address(0),
    'fwrite': _ret_address(0),
    'fclose': _ret_address(0),
    'Sleep': _ret_address(4),
    'printf': _ret_address(0),
}


def guess_syscall(emu):
    def check_ret_exec(addr):
        if emu.mm.is_address_executable(addr):
            return True
        else:
            print "The execution will be stopped because the return address is wrong!"
            return False
    
    def get_parameter_for(params=[]):
        def get_parameter_at(position=0):
            if position < len(params):
                return params[position]
            return None
        if params:
            return get_parameter_at

    ret_addr = emu.peek_from_stack(stack_offset=0)

    # Guess parameters for the function
    param_num = 0
    i = 4
    curr_param = 0
    guessed_params = []
    while True:
        curr_param = emu.peek_from_stack(stack_offset=i)
        if curr_param in emu.gadget_map or (emu.reg_read('ESP') + i) not in emu.mm.shadow_stack:
            break
        guessed_params.append(curr_param)
        i += 4
        param_num += 1

    allocation_type = {0x00001000, 0x00002000}

    if not emu.mm.is_address_mapped(ret_addr):
        print "No guesses available for the parameters in stack."
        return False

    get_parameter_at = get_parameter_for(params=guessed_params)
    if get_parameter_at is None:
        get_parameter_at = lambda position: emu.peek_from_stack(stack_offset=((position + 1) * 4))
    functions = []
    if get_parameter_at(position=2) in allocation_type and get_parameter_at(position=3) in __memory_prot:
        functions.append('VirtualAlloc')
    if get_parameter_at(position=2) in __memory_prot:
        functions.append('CreateFileMappingA' if get_parameter_at(position=0) in __winfile.files else 'VirtualProtect')
    if get_parameter_at(position=0) in __loadlibgetproc_combo.handle_to_lib:
        functions.append('GetProcAddress')
    if get_parameter_at(position=0) in __winfile._file_mappings:
        functions.append('MapViewOfFile')
    if (
        get_parameter_at(position=1) in __winfile.desired_access and 
        get_parameter_at(position=2) in __winfile.share_mode and 
        get_parameter_at(position=4) in __winfile.creation_disposition
    ):
        functions.append('CreateFileA')
    if get_parameter_at(position=0) == 0 or get_parameter_at(position=0) == 1:
        functions.append('SetProcessDEPPolicy')
    if emu.mm.is_address_writable(get_parameter_at(position=1)):
        functions.append('GetTempPathA')
    if emu.mm.is_address_writable(get_parameter_at(position=0)) and emu.mm.is_address_mapped(get_parameter_at(position=1)):
        functions.append('memcpy')

    if not functions:
        print "No guesses available for the parameters in stack."
        if param_num > 0 and param_num in params_for_function:
            functions.extend(params_for_function[param_num])
        else:
            functions.extend(params_for_function[7])

    function_name = functions[0]
    if len(functions) > 1:
        print 'Function candidates (guessed params [ {}]):'.format(''.join('0x{:x} '.format(el) for el in guessed_params))
        for i, name in enumerate(functions):
            print '\t{}: {}'.format(i, name) 
        just_do_it = -1
        while just_do_it < 0 or just_do_it >= len(functions):
            just_do_it = raw_input("Select the index [n to exit]> ")
            if just_do_it == 'n':
                return False
            just_do_it = int(just_do_it) if just_do_it.strip().isdigit() else -1
        function_name = functions[just_do_it]
    else:
        print '[+] The stack values suggest that a {} could be a right guess for a system call.'.format(function_name)
    
    emu.call_syscall_if_supported(function_name)
    return check_ret_exec(ret_addr)


address_to_syscall = {}
syscall_to_address = {}

__memory_prot = {0x2: UC_PROT_READ, 0x4: UC_PROT_READ | UC_PROT_WRITE, 0x8: UC_PROT_READ,
                 0x10: UC_PROT_EXEC, 0x20: UC_PROT_EXEC | UC_PROT_READ, 0x40: UC_PROT_ALL, 0x80: UC_PROT_EXEC}

