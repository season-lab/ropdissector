import pefile
from os import listdir
from os.path import isfile, join
from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_NONE, UC_PROT_WRITE

from utility import *


class Target_PEFile:

    """
    Class to represent a PE file that is the target of the ROP exploit.

    Attributes:
        path (str): the PE file path into the file system.
        pe (PE): the PE object.
        image_base (int): the address of the base of the image.
        PE_bytes (bytearray): the actual content of the file.
        sections_map (list): a list containing the sections of the PE file. The entries are tuples containing the
                             virtual address of the section, the size of the data, the actual data and the unicorn
                             protection level.
        import_table (dict): a dictionary representing the import table of the PE file. The keys are the addresses of
                             the imported functions and the values are the function names.
    """

    def __init__(self, path, image_base=-1):
        # type: (str, int) -> None

        self.path = path.encode('utf-8')
        self.pe = pefile.PE(self.path)

        if image_base == -1:
            self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        else:
            self.image_base = align_address(image_base)

        with open(self.path, "rb") as binary:
            self.PE_bytes = binary.read()

        self.size_of_image = self.pe.OPTIONAL_HEADER.SizeOfImage

        self.sections_map = []
        for section in self.pe.sections:
            if section.IMAGE_SCN_CNT_CODE or section.IMAGE_SCN_CNT_INITIALIZED_DATA:
                sect_address, sect_size = (section.PointerToRawData, section.SizeOfRawData)
                protection = _section_protections(section)
                self.sections_map.append((section.VirtualAddress, section.SizeOfRawData,
                                          self.PE_bytes[sect_address: sect_address + sect_size], protection))

        self.import_table = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if not imp.import_by_ordinal:
                        self.import_table[imp.address - self.pe.OPTIONAL_HEADER.ImageBase + self.image_base] = imp.name

        self.export_table = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                self.export_table[self.image_base + exp.address] = exp.name

    def check_address(self, address):
        # type: (int) -> bool

        return self.image_base <= address <= self.image_base + self.size_of_image


# A private helper function that translates the protection level
# of the section in input in the actual unicorn protection level
# constant.
def _section_protections(section):
    protection = UC_PROT_NONE
    if section.IMAGE_SCN_MEM_EXECUTE:
        protection |= UC_PROT_EXEC
    if section.IMAGE_SCN_MEM_READ:
        protection |= UC_PROT_READ
    if section.IMAGE_SCN_MEM_WRITE:
        protection |= UC_PROT_WRITE

    return protection


class Kernel32Exports:

    def __init__(self, os_version):

        k32_names = []
        k32_path = 'kernel32/'

        if os_version == 'Win7' or os_version == 'undefined':
            path_to_files = k32_path + 'win7/'
            k32_names.extend([path_to_files + f for f in listdir(path_to_files)
                              if isfile(join(path_to_files, f)) and f.endswith('.dll')])
        if os_version == 'XP' or os_version == 'undefined':
            path_to_files = k32_path + 'xp/'
            k32_names.extend([path_to_files + f for f in listdir(path_to_files)
                              if isfile(join(path_to_files, f)) and f.endswith('.dll')])
        if os_version == 'Server2003' or os_version == 'undefined':
            path_to_files = k32_path + 'srv03/'
            k32_names.extend([path_to_files + f for f in listdir(path_to_files)
                              if isfile(join(path_to_files, f)) and f.endswith('.dll')])

        self.__export_by_address = {}
        self.__export_by_RVA = {}
        for name in k32_names:
            k32 = pefile.PE(name, fast_load=True)
            k32.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
            ])
            image_base = k32.OPTIONAL_HEADER.ImageBase
            for exp in k32.DIRECTORY_ENTRY_EXPORT.symbols:
                self.__add_item_by_address(image_base, exp)
                self.__add_item_by_RVA(exp)

    def __add_item_by_RVA(self, exp):

        if exp.address in self.__export_by_RVA and self.__export_by_RVA[exp.address] != exp.name:
            if type(self.__export_by_RVA[exp.address]) == list:
                self.__export_by_RVA[exp.address].append(exp.name)
            else:
                new_elements = [self.__export_by_RVA[exp.address], exp.name]
                self.__export_by_RVA[exp.address] = new_elements
        else:
            self.__export_by_RVA[exp.address] = exp.name

    def __add_item_by_address(self, image_base, exp):

        address = image_base + exp.address
        if address in self.__export_by_address and self.__export_by_address[address] != exp.name:
            if type(self.__export_by_address[address]) == list:
                self.__export_by_address[address].append(exp.name)
            else:
                new_elements = [self.__export_by_address[address], exp.name]
                self.__export_by_address[address] = new_elements
        else:
            self.__export_by_address[address] = exp.name

    def get_name_by_address(self, address):
        if address in self.__export_by_address:
            return self.__export_by_address[address]
        return False

    def get_name_by_RVA(self, rva):
        if rva in self.__export_by_RVA:
            return self.__export_by_RVA[rva]
        return False
