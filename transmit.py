# ----------------------------------------------------------------------------
#  Source:    transmit.py
#  Author:    Keith R. Gover
#  Date:      October 05, 2015
#  Modified:  October 06, 2015
#  File:      Python script for doing authenticated encryption.  This is the
#             transmit side that generates the bank.auth file and the
#             encrypted packed containing a hash tag and the encrypted
#             message.
#  Remarks:   University of Maryland: Cybersecurity Capstone Project
# ----------------------------------------------------------------------------
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
import binascii

# ----------------------------------------------------------------------------
#  Read in the message we want to transmit.
# ----------------------------------------------------------------------------
try:
    fi = open('./message.txt', 'r')
    p_msg = fi.read()
    fi.close()
except IOError:
    print('Cannot find file: message.txt')
    exit(255)

# ----------------------------------------------------------------------------
#  We are using "encrypt then authenticate" since this provides CCA security.
#  Both keys are 128-bits.
#
#  The first block does the encryption of the message using an AES block
#  cipher in cipher feedback mode (CFB).
#
#  The second block takes the encrypted message and runs it through a hash
#  function HMAC so we can be certain it has not been altered.
#
#  While this does provide CCA security, we still need to worry about replay,
#  re-ordering and reflection attacks. This can be made more secure by
#  including packet numbers that are tracked on each side.
# ----------------------------------------------------------------------------
key_enc = binascii.unhexlify('36f18357be4dbd77f050515c73fcf9f2')
key_mac = binascii.unhexlify('863c8ba215f0e32dd76c10baef307ff8')

iv = Random.new().read(AES.block_size)
cipher = AES.new(key_enc, AES.MODE_CFB, iv)
c_msg = iv + cipher.encrypt(p_msg)

hash = HMAC.new(key_mac)
hash.update(c_msg)
h_val = hash.hexdigest()

# ----------------------------------------------------------------------------
#  Write out two files:
#      * The 16-byte hash value and the ciphertext that we hashed.
#      * The bank,auth file containing the two 128-bit keys.
# ----------------------------------------------------------------------------
try:
    fo = open('./packet.dat', 'w')
    fo.write(h_val)
    fo.write(binascii.hexlify(c_msg))
    fo.close()
except IOError:
    print ('Cannot find file: packet.txt')
    exit(255)

try:
    fo = open('./bank.auth', 'w')
    fo.write(binascii.hexlify(key_enc))
    fo.write(binascii.hexlify(key_mac))
    fo.close()
except IOError:
    print ('Cannot find file: bank.auth')
    exit(255)

print p_msg + '\n'
