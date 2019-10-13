#!/usr/bin/env python
from z3 import *

#
# Utils functions
#

def get_content(filename):
    with open(filename, "rb") as f:
        return list(f.read())

def get_dword(data, i):
    return data[i] | data[i+1] << 8 | data[i+2] << 16 | data[i+3] << 24

def to_buffer(data, val):
    data.append(val & 0xFF)
    data.append((val >> 0x08) & 0xFF)
    data.append((val >> 0x10) & 0xFF)
    data.append((val >> 0x18) & 0xFF)

def rol(v, n, size):
    masq = 2**size - 1
    return ((v << n) & masq) | ((v >> (size - n)) & masq)

def ror(v, n, size):
    masq = 2**size - 1
    return ((v >> n) & masq) | ((v << (size - n)) & masq)

def rol32(v, n):
    return rol(v, n, 32)

def rol64(v, n):
    return rol(v, n, 64)

def ror32(v, n):
    return ror(v, n, 32)

def ror64(v, n):
    return ror(v, n, 64)

def pad_data(data):
    data.append(0x80)
    while len(data) % 4 != 0:
        data.append(0)

def BIT(v, n):
    return ((1 << n) & v) >> n

#
# Encryption/Decryption functions
#

def decrypt_buffer(data, key):
    """Decrypt function"""

    out_buf = []
    for i in range(0, len(data), 4):
        val = get_dword(data, i)
        k_round = key

        k_round = ror64(k_round, 0xd)
        j = 0x4D

        while j > 0:
            k_round = rol64(k_round, 1)

            val = rol32(val, 1)
            v32 = (val >> 4) & 1 | (val >> 26) & 0xE0 | (val >> 22) & 0x10 | (val >> 13) & 8 | (val >> 7) & 4 | (val >> 4) & 2

            rigth_val = BIT(val, 0) ^ BIT(val, 12) ^ BIT(val, 20) ^ BIT(k_round, 0)
            left_val  = BIT(0xBB880F0FC30F0000, v32)

            if val & 1:
                b = 1 ^ BIT(val, 12) ^ BIT(val, 20) ^ BIT(k_round, 0) ^ BIT(0xBB880F0FC30F0000, v32)
                val &= 0xFFFFFFFE
                val |= b
            else:
                val &= 0xFFFFFFFE
                b = 0 ^ BIT(val, 12) ^ BIT(val, 20) ^ BIT(k_round, 0) ^ BIT(0xBB880F0FC30F0000, v32)
                val |= b

            j -= 1

        to_buffer(out_buf, val)

    return bytes(out_buf)

def encrypt_buffer(data, key):
    """Encrypt function"""

    out_buf = []

    for i in range(0, len(data), 4):
        val = get_dword(data, i)
        k_round = key
        j = 0x4D

        while j > 0:

            v32 = (val >> 4) & 1 | (val >> 26) & 0xE0 | (val >> 22) & 0x10 | (val >> 13) & 8 | (val >> 7) & 4 | (val >> 4) & 2

            rigth_val = BIT(val, 0) ^ BIT(val, 12) ^ BIT(val, 20) ^ BIT(k_round, 0)
            left_val  = BIT(0xBB880F0FC30F0000, v32)

            if (rigth_val == left_val):
                val = ror32(val & 0xFFFFFFFE, 1)
            else:
                val = ror32(val | 1, 1)

            k_round = ror64(k_round, 1)

            j -= 1

        to_buffer(out_buf, val)

    return bytes(out_buf)

def encrypt_val(val, k_round):
    """Encrypt function using Z3 operators and values"""

    # Logical operators written using the Z3 syntax
    rol_32 = lambda x, y: (x << y) | (LShR(x, 32 - y))
    rol_64 = lambda x, y: (x << y) | (LShR(x, 64 - y))
    ror_32 = lambda x, y: (LShR(x, y)) | (x << (32 - y))
    ror_64 = lambda x, y: (LShR(x, y)) | (x << (64 - y))
    bit_z  = lambda v, n: Extract(0, 0, LShR(v, n)) & BitVecVal(1, 1)

    j = 0x4D
    while j > 0:
        v32 = LShR(val, 4) & 1 | LShR(val, 26) & 0xE0 | LShR(val, 22) & 0x10 | LShR(val, 13) & 8 | LShR(val, 7) & 4 | LShR(val, 4) & 2

        rigth_val = bit_z(val, 0) ^ bit_z(val, 12) ^ bit_z(val, 20) ^ bit_z(k_round, 0)
        v33 = ZeroExt(32, v32)
        left_val  = bit_z(BitVecVal(0xBB880F0FC30F0000, 64), v33)

        val = If(rigth_val == left_val,
                ror_32(val & BitVecVal(0xFFFFFFFE, 32), BitVecVal(1, 32)),
                ror_32(val | BitVecVal(1, 32), BitVecVal(1, 32))
                )

        k_round = ror_64(k_round, 1)

        j -= 1

    return val

def main():
    """Main function"""

    s = Solver()
    k = BitVec("k", 64)

    v1 = encrypt_val(BitVecVal(0x474E5089, 32), k) # PNG_HEADER[0:4]
    v2 = encrypt_val(BitVecVal(0x0A1A0A0D, 32), k) # PNG_HEADER[4:8]

    s.add(v1 == BitVecVal(0x58c9d43d, 32))
    s.add(v2 == BitVecVal(0x0fbf795f, 32))

    if s.check() == sat:
        modl = s.model()
        key = modl[k].as_long()
        print("[+] Found encryption key: 0x{:016x}".format(key))

    data = get_content("secret.png.enc")
    out_buf = decrypt_buffer(data, key)

    with open("secret.png", "wb") as f:
        f.write(out_buf)

if __name__ == "__main__":
    main()
