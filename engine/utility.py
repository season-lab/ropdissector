"""
Utility module which contains misc functions.

Attributes:
    :PREVIOUS (int): constant to be used with the align_address function.
    :NEXT (int): constant to be used with the align_address function.
    :UNICORN_PAGE_ALIGNMENT (int): constant that indicates the right alignment for addresses used with the unicorn
                                   emulator.
"""

from struct import pack

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

dis32 = Cs(CS_ARCH_X86, CS_MODE_32)

PREVIOUS = 0
NEXT = 1

UNICORN_PAGE_ALIGNMENT = 4096


def _alignment_utility(number, alignment_type=NEXT, alignment=UNICORN_PAGE_ALIGNMENT):
    # type: (int, int, int) -> int

    ret = number if alignment_type == PREVIOUS else (number + alignment - 1)
    ret &= ~(alignment - 1)
    return ret


def align_address(address, alignment=NEXT):
    """
    Align the address to a multiple of UNICORN_PAGE_ALIGNMENT to allow unicorn to use it. The chosen address depends on
    the value of the second parameter.
    :param address: the address to be aligned.
    :param alignment: indicates whether the address should be aligned with the next address or the previous address.
                      (Example: NEXT if 4097 should be aligned to 8192, previous if should be aligned to 4096).
    :return: the aligned address.
    """
    return _alignment_utility(address, alignment)


def get_page_size(size):
    size = size if size != 0 else 4096
    return _alignment_utility(size)


def step_enumerate(l, start=0, step=1):
    """
    A custom version of the enumerate function that allow to specify a step.
    :param l: the iterable.
    :param start: the index to begin with.
    :param step: the step at which the index should be changed.

    :return: a generator composed of tuples (item, index).
    """

    for item in l:
        yield (item, start)
        start += step


def s32(value):
    return -(value & 0x80000000) | (value & 0x7fffffff)


def compute_chain_entry(str_value):
    value_ = str_value.replace('0x', '')
    value_size = len(value_) // 2
    value_size = value_size if value_size != 3 else 4
    int_value = s32(int(str_value, 16))

    return int_value, value_size


def pack_data_correct_size(int_value, value_size):
    long_values = value_size // 4
    short_leftovers = (value_size % 4) // 2
    byte_leftovers = (value_size % 2)
    value = pack('<l' * long_values + 'h' * short_leftovers + 'b' * byte_leftovers, s32(int_value))
    return value
