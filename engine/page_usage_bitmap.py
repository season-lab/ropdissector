"""
Module for the class PageUsageBitmap.
Constants:
    BITMAP_GRANULARITY (int): tells how many bytes are addressed by a bit in the bitmap.
    BITMAP_BIT_SIZE (int): the size of the int used in the bitmap (64 -> c_uint64).
    MEMORY_CHUNK_SIZE (int): number of bytes addressed by a single c_uint64.
    PAGE_SIZE (int): the size of a page.
"""

from ctypes import c_uint64


BITMAP_GRANULARITY = 1

# DON'T change these values
BITMAP_BIT_SIZE = 64
MEMORY_CHUNK_SIZE = BITMAP_GRANULARITY * BITMAP_BIT_SIZE
PAGE_SIZE = 4096


class PageUsageBitmap:

    """
    A class that represent the actual usage of a page.
    Attributes:
        base (int): the address base of the page (must be page aligned).
        chunk_bitmap_list (list): a list of c_uint64 that tells the usage of a memory chunk.
    """

    def __init__(self, base):
        self.base = base
        self.chunk_bitmap_list = [c_uint64(0) for _ in range(PAGE_SIZE / MEMORY_CHUNK_SIZE)]

    def __access_correct_bitmap(self, address):
        # type: (int) -> tuple

        chunk_bitmap_offset = address ^ self.base
        chunk_bitmap_offset = int(chunk_bitmap_offset / MEMORY_CHUNK_SIZE) % MEMORY_CHUNK_SIZE
        return chunk_bitmap_offset, self.chunk_bitmap_list[chunk_bitmap_offset].value

    def address_wrote(self, address, written_bytes=1):
        # type: (int, int) -> None

        """
        Updates the bitmap to remember that from the given address a certain number of bytes were written.
        :param address: the address from which the wrote has begun.
        :param written_bytes: the number of written bytes.
        :return: None
        """

        written_bytes /= BITMAP_GRANULARITY

        while written_bytes > 0 and address < self.base + PAGE_SIZE:
            chunk_bitmap_offset, bitmap_value = self.__access_correct_bitmap(address)
            memory_chunk_base = MEMORY_CHUNK_SIZE * chunk_bitmap_offset
            masked_address = address ^ self.base
            bit_offset = int((masked_address - memory_chunk_base) / BITMAP_GRANULARITY) % BITMAP_BIT_SIZE
            for offset in range(bit_offset, bit_offset + written_bytes):
                if 0 <= offset < BITMAP_BIT_SIZE:
                    bitmap_value |= (c_uint64(1).value << c_uint64(offset).value)
                    written_bytes -= 1
                elif chunk_bitmap_offset < (PAGE_SIZE / MEMORY_CHUNK_SIZE):
                    address = self.base + memory_chunk_base + MEMORY_CHUNK_SIZE
                    break

            self.chunk_bitmap_list[chunk_bitmap_offset] = c_uint64(bitmap_value)

    def is_address_wrote(self, address):
        # type: (int) -> tuple

        """
        Tells if an address has been written and the number of written bytes.
        :param address: the address from which the check must start.
        :return: a tuple (bool, int) that tells if the memory zone has been written and by how many bytes.
        """

        chunk_bitmap_offset, bitmap_value = self.__access_correct_bitmap(address)
        memory_chunk_base = MEMORY_CHUNK_SIZE * chunk_bitmap_offset
        masked_address = address ^ self.base
        bit_offset = int((masked_address - memory_chunk_base) / BITMAP_GRANULARITY) % BITMAP_BIT_SIZE
        written_size = 0
        for offset in range(bit_offset, MEMORY_CHUNK_SIZE):
            if not bitmap_value & (c_uint64(1).value << c_uint64(offset).value):
                break
            written_size += 1
        return written_size != 0, written_size


if __name__ == '__main__':

    bm = PageUsageBitmap(0x10f00000)
    bm.address_wrote(0x10f00ffc, 10)
    for value in bm.chunk_bitmap_list:
        print hex(value.value)
    print '\n\n'
    print bm.is_address_wrote(0x10f00ffc)
