from collections import namedtuple


EmuCheckpoint = namedtuple(
    'EmuCheckpoint',
    [
        'emu_context',
        'gadget_sequence',
        'called_syscall_sequence',
        'current_gadget',
        'esp_predecessor',
        'mm_memory_shadow',
        'mm_written_pages',
        'mm_shadow_stack',
        'mm_esp_graph',
        'sequence_spg',
    ],
    verbose=False
)


EmuOutput = namedtuple(
    'EmuOutput',
    [
        'gadget_sequence',
        'gadget_map',
        'called_syscall_sequence',
        'branch_handler',
        'mm_esp_graph',
        'sequence_spg',
    ],
    verbose=False
)
