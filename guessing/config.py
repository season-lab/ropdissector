import json


class Config:

    def __init__(self, pe_targets, first_gadget_addr, stack_init_state, shellcode, os_version):
        # type: (list, str, list, bool, str) -> None

        self.__PE_targets = pe_targets
        self.__first_gadget_addr = first_gadget_addr
        self.__stack_init_state = stack_init_state
        self.__shellcode = shellcode
        self.__os_version = os_version

    @classmethod
    def from_json(cls, path_to_config):
        # type: (str) -> Config

        with open(path_to_config) as config:
            data = json.load(config)
        
        pe_targets = data['PE_targets']
        pe_target_list = []

        for target in pe_targets:
            target_path = target['PE_path']
            
            target_base = -1
            if 'image_base' in target:
                target_base = int(target['image_base'], 16)
            
            pe_target_list.append((target_path, target_base))

        os_version = ""
        if 'os_version' in data:
            os_version = data['os_version']
        return cls(pe_target_list, data['first_gadget'], data['stack_init_state'], data['shellcode'], os_version)

    @property
    def PE_targets(self):
        return self.__PE_targets

    @property
    def first_gadget_addr(self):
        return self.__first_gadget_addr

    @property
    def stack_init_state(self):
        return self.__stack_init_state

    @property
    def shellcode(self):
        return self.__shellcode

    @property
    def os_version(self):
        return self.__os_version
