import sys

from barf.analysis.codeanalyzer.codeanalyzer import CodeAnalyzer
from barf.analysis.gadgets.classifier import GadgetClassifier
from barf.analysis.gadgets.verifier import GadgetVerifier
from barf.analysis.gadgets.gadget import RawGadget
from barf.arch.arch import ARCH_X86_MODE_32
from barf.arch.x86.parser import X86Parser
from barf.arch.x86.translator import X86Translator
from barf.arch.x86.x86 import X86ArchitectureInformation
from barf.arch.translator import TranslationError
from barf.core.reil.emulator.emulator import ReilEmulator
from barf.core.smt.smtsolver import Z3Solver
from barf.core.smt.smttranslator import SmtTranslator
from barf.tools.gadgets.gadgets import print_gadgets_raw, print_gadgets_typed


def barf_classify(gadget_map, printout=True):
    arch_mode = ARCH_X86_MODE_32
    arch_info = X86ArchitectureInformation(arch_mode)
    translator = X86Translator(arch_mode)
    instruction_parser = X86Parser(arch_mode)
    ir_emulator = ReilEmulator(arch_info)
    classifier = GadgetClassifier(ir_emulator, arch_info)
    raw_gadgets = {}
    typed_gadgets = []
    for _, gadget in gadget_map.items():

        # Translation cycle: from my emulator to BARF representation
        classifiable = False
        barf_instr_list = []
        for _, instr in gadget.instructions.items():
            # Parse a ROPInstruction into the BARF representation of an x86 instruction
            barf_instr = instruction_parser.parse("{} {}".format(instr.mnemonic, instr.op_str))
            barf_instr.address = instr.address
            try:
                # Translate an x86 instruction into a list of REIL instructions
                reil_transl_instrs = translator.translate(barf_instr)
                barf_instr.ir_instrs = reil_transl_instrs
                classifiable = True
            except TranslationError:
                classifiable = False
            finally:
                barf_instr_list.append(barf_instr)

        # Classification of the gadgets
        barf_g = RawGadget(barf_instr_list)
        raw_gadgets[barf_g.address] = barf_g
        if classifiable:
            classified = classifier.classify(barf_g)
            for tg in classified:
                typed_gadgets.append(tg)
    if printout:
        print_gadgets_raw(list(raw_gadgets.values()), sys.stdout, 'addr', True, 'Raw Gadgets', False)
        verified = []
        unverified = []
        solver = Z3Solver()
        translator = SmtTranslator(solver, arch_info.address_size)
        code_analyzer = CodeAnalyzer(solver, translator, arch_info)
        verifier = GadgetVerifier(code_analyzer, arch_info)
        for tg in typed_gadgets:
            if verifier.verify(tg):
                verified.append(tg)
            else:
                unverified.append(tg)
        print_gadgets_typed(verified, sys.stdout, arch_info.address_size, 'Verified classification')
        print_gadgets_typed(unverified, sys.stdout, arch_info.address_size, 'Unverified classification')
        for tg in typed_gadgets:
            if tg.address in raw_gadgets:
                raw_gadgets.pop(tg.address)
        print_gadgets_raw(list(raw_gadgets.values()), sys.stdout, 'addr', False, 'Not classified', False)

    return {tg.address: tg for tg in typed_gadgets}
