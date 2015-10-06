# ----------------------------------------------------------------------------
#  Source:    receive.py
#  Author:    Keith R. Gover
#  Date:      October 05, 2015
#  Modified:  October 06, 2015
#  File:      Python script for doing authenticated encryption.  This is the
#             receive side that checks the hash tag and ensures message
#             authentication and then decrypts the message.
#  Remarks:   University of Maryland: Cybersecurity Capstone Project
# ----------------------------------------------------------------------------
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
import binascii

# ----------------------------------------------------------------------------
#  Read in the two files being transmitted:
#      * Packet containing the encrypted message and the hash value to check.
#      * The two 128-bit keys.
# ----------------------------------------------------------------------------
try:
    fi = open('packet.dat', 'r')
    c_tmp = fi.read()
    fi.close()
except IOError:
    print('Cannot find file: packet.dat')
    exit(255)

try:
    fi = open('bank.auth', 'r')
    k_tmp = binascii.unhexlify(fi.read())
    fi.close()
except IOError:
    print('Cannot find file: bank.auth')
    exit(255)

# ----------------------------------------------------------------------------
#  This block does the following:
#      * Extracts the hash tag from the full ciphertext (c_tmp).
#      * Extracts the IV and encrypted message from the full ciphertext.
#      * Runs the hash function on the full ciphertext and compares it to the
#        hash tag sent with the file.
#      * Decrypts the message.
# ----------------------------------------------------------------------------
h_tag = c_tmp[0:32]
c_tmp = binascii.unhexlify(c_tmp[32:])

iv = c_tmp[0:AES.block_size]
c_msg = c_tmp[AES.block_size:]

key_enc = k_tmp[0:16]
key_mac = k_tmp[16:]

hash = HMAC.new(key_mac)
hash.update(c_tmp)
cipher = AES.new(key_enc, AES.MODE_CFB, iv)

if (h_tag == hash.hexdigest()):
    p_msg = cipher.decrypt(c_msg)
    print p_msg + '\n'
else:
    print('Error processing: packet.dat')
    exit(255)
