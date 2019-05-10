import json
import os
import re
import sys
from copy import deepcopy

from utility import step_enumerate, compute_chain_entry
from config import *

PRECOMP_DIR = 'precomputed_gadgets'
precomputed_gadgets_dir = os.path.join(os.getcwd(), PRECOMP_DIR)


class PE:
    def __init__(self, path, base=0, parse_RVAs=False):
        self.dir_path = path
        self.base = base
        first_json = os.listdir(os.path.join(path, self.dir_path))[0]
        if not os.path.isfile(os.path.join(path, first_json)):
            raise ValueError('dir must contain json files')
        with open(os.path.join(path, first_json)) as js:
            json_parsed = json.load(js)
            self.size = json_parsed['PE_info']['SizeOfCode']
            if parse_RVAs:
                self.RVAs = [0, json_parsed['PE_info']['BaseOfCode']]
                if 'exports' in json_parsed['PE_info']:
                    self.RVAs.extend(json_parsed['PE_info']['exports'])
                # self.RVAs.extend(json_parsed['PE_info']['FunctionsOffset'])
                else:
                    print '{}/{}'.format(self.dir_path, first_json)
            else:
                self.RVAs = [0, json_parsed['PE_info']['BaseOfCode']]
            self.name = json_parsed['PE_info']['Name']
            self._preferred_base = json_parsed['PE_info']['ImageBase']
            self.rva_off = 0
            self.aslr_compiled = json_parsed['PE_info']['ASLR_compiled']
            self.support_forced_aslr = json_parsed['PE_info']['SupportRelocs']

    def _parse_json(self):
        for js_name in os.listdir(self.dir_path):
            with open(os.path.join(self.dir_path, js_name)) as js:
                yield json.load(js)

    def search_at(self, delta_addr):
        for json_parsed in self._parse_json():
            curr_ce = json_parsed[str(delta_addr)] if str(delta_addr) in json_parsed else None
            if curr_ce:
                if curr_ce['spOffset'] == 'undef':
                    return 0, 0
                else:
                    spoff = curr_ce['spOffset'] - (curr_ce['spOffset'] % 4)
                    pattern = re.compile('ret ?([0-9]*)?;', re.I)
                    ret_modifier = 0
                    for found in pattern.finditer(curr_ce['Gadget']):
                        if found.group(1):
                            ret_modifier = int(found.group(1), 16) - (int(found.group(1), 16) % 4)
                    print '[0x{:x}] Found candidate at {} - spOffset: {}, ret_mod : 0x{:x}'.format(self.base, curr_ce['Gadget'], spoff, ret_modifier)
                    return spoff, ret_modifier
        return 0, 0

    def get_preferred_base(self):
        return self._preferred_base

    def __repr__(self):
        return '{} [ImageBase 0x{:x}]'.format(self.name, self.base if self.base > 0 else self._preferred_base + self.rva_off)


def explore(pe, dict_chain, sp_change, depth, _delta_ret=0):
    last_delta_addr = -1
    while depth > 0:
        g_addr = dict_chain[sp_change - _delta_ret]
        delta_addr = g_addr - pe.base
        if delta_addr < 0 or delta_addr > pe.size:
            return False
        (delta_esp, delta_ret) = pe.search_at(delta_addr)
        sp_change = sp_change + delta_esp
        if delta_esp <= 0 or sp_change - delta_ret not in dict_chain or sp_change <= 0:
            return False
        if delta_addr != last_delta_addr:
            depth -= 1
        last_delta_addr = delta_addr
        _delta_ret = delta_ret
    return True


def guess(pe, dict_chain, start_sp=0, depth=3, leaked=False, not_rand_chain=False, enable_forced_aslr=False):
    _64KB_chunks = (pe.size + 0xFFFE) >> 16
    g_offset = dict_chain[start_sp] & 0xFFFF0000
    print 'Trying {} for dll {}'.format(_64KB_chunks, pe.dir_path)
    for page_idx in xrange(_64KB_chunks):
        if leaked:
            break
        if pe.aslr_compiled or (pe.support_forced_aslr and enable_forced_aslr):
            pe.base = g_offset - (page_idx * 0x10000)
        if (
                (not pe.aslr_compiled and not (pe.support_forced_aslr and enable_forced_aslr))
                or not_rand_chain
        ):
            pe.base = pe.get_preferred_base()
            break
        if pe.base <= 0:
            break
        if explore(pe, dict_chain, start_sp, depth):
            yield (deepcopy(pe), pe.base, 0)
    if leaked or pe.base <= 0:
        for rva in pe.RVAs:
            pe.base = (-rva)
            pe.rva_off = rva
            if explore(pe, dict_chain, start_sp, depth):
                yield (deepcopy(pe), pe.get_preferred_base(), rva)
    if not_rand_chain and explore(pe, dict_chain, start_sp, depth):
        yield (deepcopy(pe), pe.base, 0)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Usage: python "+sys.argv[0]+" <config.json>"
        print "Try with one of the JSON files from the ROP collection."
        exit(1)
    path = sys.argv[1]

    conf = Config.from_json(path)
    chain = [conf.first_gadget_addr]
    chain.extend(conf.stack_init_state)
    dict_chain = dict()
    for ce, j in step_enumerate(chain, start=0, step=4):
        dict_chain[j] = compute_chain_entry(ce)[0]

    goods = []
    for root, dirs, _ in os.walk(precomputed_gadgets_dir, topdown=False):
        for directory in dirs:
            try:
                pe = PE(os.path.join(root, directory), parse_RVAs=False)
            except ValueError as e:
                continue
            for pe, base, rva in guess(pe, dict_chain, leaked=False, not_rand_chain=False, enable_forced_aslr=True):
                print '====== {}, 0x{:x}, 0x{:x} ======'.format(pe.dir_path, base, rva)
                goods.append((pe.dir_path, pe))

    print goods
