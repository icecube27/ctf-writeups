#!/usr/bin/env python
###############################
## CTFZone 2018 - Write up
## Challenge : Signature Server
## Author : icecube27
###############################
from pwn import *
from base64 import b64encode, b64decode

HOST = "crypto-02.v7frkwrfyhsjtbpfcppnu.ctfz.one"
PORT = 1337

p = remote(HOST, PORT)

MESSAGE_LENGTH           = 32
show_flag_command        = "show flag" + (MESSAGE_LENGTH-9) * "\xff"
fake_show_flag_command   = "rhow flag" + (MESSAGE_LENGTH-9) * "\xff"
admin_command            = "su admin"  + (MESSAGE_LENGTH-8) * "\x00"
fake_admin_command       = "ru admin"  + (MESSAGE_LENGTH-8) * "\x00"

# Receive the first to line
def init():
    p.recvline()
    p.recvline()

# Ask the server to sign the data
def sign(data):
    p.send("sign:{}".format(b64encode(data)))
    data = p.recvline()
    #print("[+] Received data : {}".format(data))
    return data

# Get signature for the server
def get_signature(message):
    signed  = sign(message)
    s       = b64decode(signed.split(",")[1])
    return s

# Get the checksum for a message
def get_checksum(message):
    print repr(message)
    signed = sign(message)
    s      = b64decode(signed.split(",")[0])
    return u32(s[-4:])

# Find the checksum for a specific message by asking the server;
# since the server checks the checksum before the signature if we
# receive the message "Error : wrong signature" we know that we 
# sent a message with a good checksum.
# Thus, in order to find the signature I first compute the 
# signature of a similar message (@f_chk) and then I try all the 
# signature in [f_chk - 1024; f_chk + 1024]
#
# Remark : the checksum could be computed locally but since I did
# not find (quickly) a good implementation of the winterniz 
# signature in Python during the CTF I chose to use this method :)
def find_checksum(cmd, f_chk):
    for i in range(f_chk - 1024, f_chk + 1024):

        # Here we try to execute a command with a wrong signature
        data = exec_command(cmd + p32(i), "dGVzdA==")
        if "signature" in data:
            return i
    return -1

# Try to send the 'execute_command' command on the remote server
def exec_command(cmd, s, debug = False):
    cmd_b64 = b64encode(cmd)
    s_b64   = b64encode(s)
    payload = "execute_command:{},{}".format(cmd_b64, s_b64)
    if debug: 
        print("[+] Length cmd       : {}".format(len(cmd)))
        print("[+] Length signature : {}".format(len(s)))
        print("[+] Sending payload  : {}".format(payload))
    p.sendline(payload)
    data = p.recvline()
    return data

# Since we cannot compute the signature for the blocks in range
# [32;26], I chose to implement a brute force:
# We many message and check if the bytes of the checksum at the
# index "pos" is equal to the byte of our wanted checksum at 
# index "pos"; if it is the case, we know that the 32-bytes block
# at index "32+pos" correspond to the rigth signed block so we 
# return this block.
def find_checksum_signature(chk, pos):
    chk_s = p32(chk)
    i = 0
    while True:
        signed  = sign(p32(i))
        s       = b64decode(signed.split(",")[0])
        signa   = b64decode(signed.split(",")[1])
        if s[32+pos] == chk_s[pos]:
            data = signa[32*(32+pos):32*(32+pos+1)]
            return data
        i += 1

# Main function
def exploit():
    init()

    ############################ ADMIN COMMAND ###########################

    # Get a wrong checksum
    f_chk = get_checksum(fake_admin_command)
    print("[+] Found fake checksum : 0x{:08x}".format(f_chk))

    # Find the good checksum
    chk = find_checksum(admin_command, f_chk)
    print("[+] Found good checksum : 0x{:08x}".format(chk))

    assert(chk != -1)

    # Build the signature
    cmd = admin_command + p32(chk)

    block_1 = get_signature(fake_admin_command)
    print("[.] Fake block : {}".format(block_1.encode("hex")))

    block_2 = get_signature("s")
    print("[.] S block    : {}".format(block_2.encode("hex")))

    signed  = block_2[:32] + block_1[32:32*32]

    chk_block_0 = find_checksum_signature(chk, 0)
    chk_block_1 = find_checksum_signature(chk, 1)

    print("[+] Checksum block : {}".format(chk_block_0.encode("hex")))
    print("[+] Checksum block : {}".format(chk_block_1.encode("hex")))

    #signed += chk_block_0 + chk_block_1 + block_1[32*34:32*36]
    signed += chk_block_0 + chk_block_1 + block_1[32*34:32*36]
    print signed.encode("hex")

    data = exec_command(cmd, signed, debug = True)
    print("Received data from exec_command : {}".format(data))

    ############################ SHOW FLAG COMMAND ###########################

    # Get a wrong checksum
    f_chk = get_checksum(fake_show_flag_command)
    print("[+] Found fake checksum : 0x{:08x}".format(f_chk))

    # Find the good checksum
    chk = find_checksum(show_flag_command, f_chk)
    print("[+] Found good checksum : 0x{:08x}".format(chk))

    assert(chk != -1)

    # Build the signature
    cmd = show_flag_command + p32(chk)

    block_1 = get_signature(fake_show_flag_command)
    print("[.] Fake block : {}".format(block_1.encode("hex")))

    block_2 = get_signature("s")
    print("[.] S block    : {}".format(block_2.encode("hex")))

    signed  = block_2[:32] + block_1[32:32*32]

    chk_block_0 = find_checksum_signature(chk, 0)
    chk_block_1 = find_checksum_signature(chk, 1)

    print("[+] Checksum block : {}".format(chk_block_0.encode("hex")))
    print("[+] Checksum block : {}".format(chk_block_1.encode("hex")))

    signed += chk_block_0 + chk_block_1 + block_1[32*34:32*36]
    print signed.encode("hex")

    data = exec_command(cmd, signed, debug = True)
    print("Received data from exec_command : {}".format(data))

if __name__ == "__main__":
    exploit()
