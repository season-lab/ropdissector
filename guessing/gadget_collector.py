from ropper import RopperService
from ropper.semantic import Analyser, IRSBAnalyser
from ropper.arch import ArchitectureX86

import pefile
import json
import os
import pyvex
import subprocess

from ropgadget.binary import Binary
from ropgadget.args import Args
from ropgadget.gadgets import Gadgets
from ropgadget.options import Options

from operator import attrgetter


TESTSET_DIR = 'testset/'
RESULTS_DIR = 'results/'
NUCLEUS = '../nucleus/nucleus'
RESULTS_SUBDIR_PATTERN = 'results/{}/'
OUTFILE_PATTERN = 'results/{}/{}-g{}_{}.json'

options = {
    'color': False,
    'badbytes': '00',
    'all': True,
    'inst_count': 6,
    'type': 'rop',
    'detailed': False}


rs = RopperService(options)
analyser = Analyser()


def ropper_analyser(gadget):
    try:
        arch = ArchitectureX86()
        irsb = pyvex.IRSB(bytes(gadget['bytes']), gadget['vaddr'], arch.info, bytes_offset=0,
                          num_bytes=len(gadget['bytes']), opt_level=0)
        irsb_anal = IRSBAnalyser()
        anal = irsb_anal.analyse(irsb)
        archinfo = arch.info
        anal.spOffset = analyser.findSpOffset(None, anal, archinfo.register_names[archinfo.registers['sp'][0]])
        return anal

    except pyvex.PyVEXError as e:
        pass
    except:
        pass


pe_dir = os.path.join(os.getcwd(), TESTSET_DIR)
if not os.path.exists(os.path.join(os.getcwd(), RESULTS_DIR)):
    os.mkdir(os.path.join(os.getcwd(), RESULTS_DIR))

for f in os.listdir(pe_dir):
    if not os.path.exists(os.path.join(os.getcwd(), RESULTS_SUBDIR_PATTERN.format(f))):
        os.mkdir(os.path.join(os.getcwd(), RESULTS_SUBDIR_PATTERN.format(f)))
    print 'Testing {}'.format(f)
    ropper_parsing_error = False
    with open(os.path.join(pe_dir, f), 'rb') as curr_pe:
        pe_bytes = curr_pe.read()
        try:
            rs.addFile(name=f, bytes=pe_bytes)
        except ValueError:
            ropper_parsing_error = True
        pe = pefile.PE(data=pe_bytes)
    print 'Nucleus...'
    nucleus_out = subprocess.check_output([NUCLEUS, '-d', 'linear', '-t', 'pe', '-a', 'x86-32', '-f', '-e',
                                           '{}'.format(os.path.join('testset/', f))])
    nucleus_out = nucleus_out.split()
    nucleus_out = [int(nucleus_out[i], 16) - pe.OPTIONAL_HEADER.ImageBase for i in xrange(0, len(nucleus_out), 2)]
    pe_info = {
        'Name': f,
        'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
        'SizeOfCode': pe.get_section_by_rva(pe.OPTIONAL_HEADER.BaseOfCode).SizeOfRawData,
        'BaseOfData': pe.OPTIONAL_HEADER.BaseOfData,
        'SizeOfData': pe.OPTIONAL_HEADER.SizeOfInitializedData + pe.OPTIONAL_HEADER.SizeOfUninitializedData,
        'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
        'ASLR_compiled': pe.OPTIONAL_HEADER.DllCharacteristics & 0x40 != 0,
        'SupportRelocs': pe.has_relocs(),
        'FunctionsOffset': nucleus_out,
    }

    # ----- ROPgadget -----
    rg_offset = 0
    config = ['--binary', os.path.join(pe_dir, f), '--all', '--nojop', '--nosys', ]
    rg_args = Args(config).getArgs()
    rg_bin = Binary(rg_args)
    G = Gadgets(rg_bin, rg_args, rg_offset)
    exec_sections = rg_bin.getExecSections()
    rg_gadgets = []
    for section in exec_sections:
        rg_gadgets += G.addROPGadgets(section)
    rg_gadgets = G.passClean(rg_gadgets, rg_args.multibr)
    rg_gadgets = Options(rg_args, rg_bin, rg_gadgets).getGadgets()
    # ---------------------

    if not ropper_parsing_error:
        rs.setArchitectureFor(name=f, arch='x86')
        rs.loadGadgetsFor(name=f)
        rp_gadgets = rs.getFileFor(f).gadgets
        rp_gadgets.sort(key=attrgetter('address'))
        print 'Found {} gadgets!'.format(len(rp_gadgets))
        rs.setImageBaseFor(name=f, imagebase=0x0)
    else:
        rp_gadgets = []

    rp_len = len(rp_gadgets)
    rg_len = len(rg_gadgets)
    rp = True
    gadgets = rp_gadgets
    if rp_len < rg_len:
        gadgets = rg_gadgets
        rp = False
    rep = (len(gadgets) / 5000) + 1
    for r in xrange(rep):
        _map = dict()
        _map['PE_info'] = pe_info
        for gn, g in enumerate(gadgets[r * 5000: (r + 1) * 5000]):
            print '{} rep of {} - {} of 5000'.format(r, rep, gn)
            _g_dict = dict()
            if rp:
                _g_dict['Gadget'] = '{}'.format(g)
                g.info = analyser.analyse(g)
                _g_dict['spOffset'] = g.info.spOffset if g.info else 'undef'
                _map[g.address] = _g_dict
            else:
                g_addr = g['vaddr'] - pe_info['ImageBase']
                _g_dict['Gadget'] = '0x{:08x}: {}'.format(g_addr, g['gadget'].replace(' ; ', '; '))
                analysis = ropper_analyser(g)
                _g_dict['spOffset'] = analysis.spOffset if analysis else 'undef'
                _map[g_addr] = _g_dict

        with open(
                os.path.join(
                    os.getcwd(),
                    OUTFILE_PATTERN.format(f, r, rep-1, len(gadgets[r * 5000: (r + 1) * 5000]), f)
                ), 'w') as jf:
            json.dump(_map, jf, sort_keys=True)

    # i = 0
    # j = 0
    # rep = 0
    # rp_len = len(rp_gadgets)
    # rg_len = len(rg_gadgets)
    # while True:
    #     inserted = 0
    #     _map = dict()
    #     _map['PE_info'] = pe_info
    #     while inserted < 5000:
    #         _g_dict = dict()
    #         if i < rp_len:
    #             g = rp_gadgets[i]
    #             if g.address not in _map:
    #                 _g_dict['Gadget'] = '{}'.format(g)
    #                 analysis = analyser.analyse(g)
    #                 g.info = analysis
    #                 _g_dict['spOffset'] = g.info.spOffset if g.info else 'undef'
    #                 _map[g.address] = _g_dict
    #                 inserted += 1
    #         i += 1
    #         if j < rg_len:
    #             g = rg_gadgets[j]
    #             g_addr = g['vaddr'] - pe_info['ImageBase']
    #             if g_addr not in _map:
    #                 _g_dict['Gadget'] = '0x{:08x}: {}'.format(g_addr, g['gadget'].replace(' ; ', '; '))
    #                 analysis = ropper_analyser(g)
    #                 _g_dict['spOffset'] = analysis.spOffset if analysis else 'undef'
    #                 _map[g_addr] = _g_dict
    #                 inserted += 1
    #         j += 1
    #         if inserted < 5000 and i >= rp_len and j >= rg_len:
    #             break
    #     rep += 1
    #     with open(
    #             os.path.join(
    #                 os.getcwd(),
    #                 OUTFILE_PATTERN.format(f, rep, inserted, f)
    #             ), 'w') as jf:
    #         json.dump(_map, jf, sort_keys=True)
    #     if i >= rp_len and j >= rg_len:
    #         break

    rs.removeFile(f)
