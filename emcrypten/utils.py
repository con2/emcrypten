from io import BytesIO
import struct


class Pack():
    """
    A helper to pack/unpack to/from a BytesIO iteratively.
    """
    def __init__(self, *args, **kwargs):
        self.buffer = BytesIO(*args)

    def pack(self, fmt, *args, **kwargs):
        self.buffer.write(struct.pack(fmt, *args, **kwargs))

    def unpack(self, fmt):
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, self.buffer.read(size))

    def getvalue(self):
        return self.buffer.getvalue()