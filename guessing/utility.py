"""
Utility module which contains misc functions.

"""


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
