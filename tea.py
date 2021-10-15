import struct
import ctypes


class TEA:
    def __init__(self, key):
        self.__key = key
        self.__delta = 0x9e3779b9
        self.__sum = 0xC6EF3720
        try:
            self.__keys = struct.unpack('>4I', self.__key)  # 128 bits length/16 bytes length
        except struct.error:
            print(struct.error)
            exit(0)

    def get_delta(self):
        return self.__delta

    def get_sum(self):
        return self.__sum

    def set_delta(self, delta):
        self.__delta = delta

    def set_sum(self, s):
        self.__sum = s

    @staticmethod
    def __change_type(text: bytes):
        """
        Try to change bytes array to number list
        64 bits length/8 bytes length
        """
        try:
            return struct.unpack('>2I', text)
        except struct.error:
            print(struct.error)
            exit(0)

    def __calc(self, text: bytes, mode='encrypt'):
        """
        use C type to calculate
        """
        s = ctypes.c_uint32(0)
        v = list(self.__change_type(text))
        v0, v1 = ctypes.c_uint32(v[0]), ctypes.c_uint32(v[1])
        if mode == 'encrypt':
            for _ in range(32):
                s.value += self.__delta
                v0.value += (((v1.value << 4) + self.__keys[0]) ^ (v1.value + s.value) ^ (
                            (v1.value >> 5) + self.__keys[1]))
                v1.value += (((v0.value << 4) + self.__keys[2]) ^ (v0.value + s.value) ^ (
                            (v0.value >> 5) + self.__keys[3]))
        else:
            for _ in range(32):
                v1.value -= (((v0.value << 4) + self.__keys[2]) ^ (v0.value + s.value) ^ (
                            (v0.value >> 5) + self.__keys[3]))
                v0.value -= (((v1.value << 4) + self.__keys[0]) ^ (v1.value + s.value) ^ (
                            (v1.value >> 5) + self.__keys[1]))
                s.value -= self.__delta
        return struct.pack('>2I', v0.value, v1.value)

    def encrypt(self, plaintext: bytes):
        ciphertext = b''
        for i in range(0, len(plaintext), 8):
            ciphertext += self.__calc(plaintext[i:i+8])
        return ciphertext

    def decrypt(self, ciphertext: bytes):
        plaintext = b''
        for i in range(0, len(ciphertext), 8):
            plaintext += self.__calc(ciphertext, 'decrypt')
        return plaintext


if __name__ == '__main__':
    tea = TEA(b'test' * 4)
    print(tea.encrypt(b'test' * 2))
    print(tea.decrypt(tea.encrypt(b'test' * 2)))
