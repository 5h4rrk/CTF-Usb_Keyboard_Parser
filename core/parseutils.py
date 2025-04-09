LE = 'little'
BE = 'big'
BYTE_SIZE  = 0x1
WORD_SIZE  = 0x2
DWORD_SIZE = 0x4
QWORD_SIZE = 0x8

class SingleBaseClass:
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(SingleBaseClass, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self.__class__._initialized:
            self.pos = 0x0
            self.count = 0x00
            self.__class__._initialized = True


class ParseUtils(SingleBaseClass):
    """
        ParseUtils class to unpack various data types from a bytestream.
    """
    def unpack_byte(self, stream):
        self.pos += 1
        return stream[self.pos - 1]

    def unpack_word(self, stream, endian=LE):  # 2 bytes
        self.pos += 2
        return int.from_bytes(stream[self.pos - 2:self.pos], endian)

    def unpack_dword(self, stream, endian=LE):  # 4 bytes
        self.pos += 4
        return int.from_bytes(stream[self.pos - 4:self.pos], endian)

    def unpack_qword(self, stream, endian=LE):  # 8 bytes
        self.pos += 8
        return int.from_bytes(stream[self.pos - 8:self.pos], endian)

    def unpack_bytes(self, stream, length):
        """
            Extracts a sequence of bytes from the stream.
        """
        self.pos += length
        return stream[self.pos - length:self.pos]

    def unpack_string(self, stream) -> str:
        """
            Extracts a null-terminated string from the stream.
        """
        start_pos = self.pos
        while self.pos < len(stream) and stream[self.pos] != 0x00:
            self.pos += 1
        result = stream[start_pos:self.pos].decode('utf-8', errors='ignore')
        self.pos += 1  # Skip the null terminator
        return result

    def unwrap(self,stream, endian=LE):
        self.pos += len(stream)
        return int.from_bytes(stream, endian)

    @staticmethod
    def read_byte(file):
        return file.read(BYTE_SIZE)

    def read_word(self, file):
        return self.unwrap(file.read(WORD_SIZE))

    def read_dword(self, file):
        return self.unwrap(file.read(DWORD_SIZE))

    def read_qword(self, file):
        return self.unwrap(file.read(QWORD_SIZE))

    @staticmethod
    def read_bytes(file, length):
        # NOTE: For marking EOF
        if length < 0: return None
        return file.read(length)

    def skip_bytes(self,file, pos):
        self.pos += pos
        file.read(pos)

    def skip_pos(self, file):
        pass

    def reset_count(self):
        self.count = 0x0

    def get_byte(self,stream):
        self.count += 1
        return stream[self.count - 1]

    def get_word(self,stream, endian=LE):  # 2 bytes
        self.count += 2
        return int.from_bytes(stream[self.count - 2:self.count], endian)

    def get_dword(self,stream, endian=LE):  # 4 bytes
        self.count += 4
        return int.from_bytes(stream[self.count - 4:self.count], endian)

    def get_qword(self,stream, endian=LE):  # 8 bytes
        self.count += 8
        return int.from_bytes(stream[self.count - 8 :self.count], endian)

    def get_bytes(self,stream, length):
        return stream[self.count : self.count + length]

def _le_to_be(num): return ((num >> 24) & 0xFF) | ((num >> 8) & 0xFF00) | ((num << 8) & 0xFF0000) | ((num << 24) & 0xFF000000)

def read_file(name):
    """Returns the address of file where it being loaded"""
    return open(name, 'rb')