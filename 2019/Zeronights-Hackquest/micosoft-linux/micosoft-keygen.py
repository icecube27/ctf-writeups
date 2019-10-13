#!/usr/bin/env python
from Crypto.Hash import SHA256
import sys

def keygen(mail):
    """Keygen function"""

    SBOX = list(map(
        lambda x: x ^ 0x55,
        [
            0x49, 0x48, 0x51, 0x54, 0x4D, 0x4C, 0x5D, 0x50,
            0x41, 0x40, 0x59, 0x5C, 0x45, 0x44, 0x55, 0x58,
            0x46, 0x47, 0x5B, 0x5A, 0x42, 0x43, 0x5F, 0x5E,
            0x4E, 0x4F, 0x53, 0x52, 0x4A, 0x4B, 0x57, 0x56
        ]
    ))

    global_hash = [0] * 32
    passcode =    [0] * 16

    for c in mail:
        hash_sha256 = SHA256.new(bytes(c, 'utf-8')).digest()
        for i in range(32):
            global_hash[i] = (global_hash[i] + hash_sha256[i]) % 0xEC

    index = 0x0E
    for i in range(16):

        I = SBOX[index]
        X = global_hash[I]
        index = SBOX[I]
        Y = global_hash[index]

        passcode[i] = (X*Y) % 9

    print("{}: {}{}{}{}-{}{}{}{}-{}{}{}{}-{}{}{}{}".format(mail, *passcode))

def main():
    """Main function"""

    if len(sys.argv) < 2:
        print("Usage: {} <mail>".format(sys.argv[0]))
        return -1

    mail = sys.argv[1]
    keygen(mail)

if __name__:
    main()
