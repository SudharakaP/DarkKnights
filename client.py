# ----------------------------------------------------------------------------
#  Source:    client.py
#  Author:    Keith R. Gover
#  Date:      October 05, 2015
#  Modified:  October 07, 2015
#  File:      Python script for doing authenticated encryption.  This is the
#             client side (ATM) that:
#                 * Reads in the message to be sent.
#                 * Reads the bank.auth file to get the encryption keys.
#                 * Encrypt and hash the message.
#                 * Create a packet containing the hash tag and the encrypted
#                   message.
#                 * Send the packet out to the bank.
#  Remarks:   University of Maryland: Cybersecurity Capstone Project
# ----------------------------------------------------------------------------
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
from helper import print_flush
import binascii, socket, sys, datetime

# Get the command to be sent from the command line.
msg_file = sys.argv[1]

# ----------------------------------------------------------------------------
#  Read in the message we want to transmit and the bank.auth file containing
#  the 2 128-bit encryption keys.  The keys are in hexadecimal and need to be
#  converted back to binary.
# ----------------------------------------------------------------------------
try:
    fi = open(msg_file, 'r')
    p_msg = fi.read()
    fi.close()
except IOError:
    print('Cannot find file: ' + msg_file)
    exit(255)

try:
    fi = open('bank.auth', 'r')
    k_tmp = binascii.unhexlify(fi.read())
    fi.close()
except IOError:
    print('Cannot find file: bank.auth')
    exit(255)

# Print the command we are sending to stdout
print_flush(p_msg)

# ----------------------------------------------------------------------------
#  We are using "encrypt then authenticate" since this provides CCA security.
#  This code does the following:
#
#      * Extract the 2 128-bit keys from the bank.auth file.
#
#      * Create an initialization vector (IV) for the cipher.  It is very
#        important that same IV is not used with the same key more than once.
#        Doing so can lead to extremely vulnerable code. 
#
#      * Do the encryption of the message using an AES block cipher in cipher
#        feedback mode (CFB).  CFB mode is similar to CBC mode but allows the
#        cipher to be used as a stream cipher.  This makes the code simpler
#        in that we don't have to encrypt in 16-byte chunks.
#
#      * The message includes a 26-byte datetime stamp that the bank can use
#        as a packet ID to guard against replay attacks.
#
#      * Take the encrypted message and runs it through an HMAC hash function
#        so we can be certain it has not been altered in transit.  The default
#        hash function used for HMAC is MD5.
#
#      * Create packet for transmission in hexadecimal form.  The hash tag is
#        already in hex but the ciphertext needs to be converted.
#
#      * Send the packet out on the port.
#
#      * Successful exit requires exit with code 0
#
#  TODO:
#      * We might want to look at using a stronger hash function in the HMAC
#        like SHA256.
#
# ----------------------------------------------------------------------------
key_enc = k_tmp[0:AES.block_size]
key_mac = k_tmp[AES.block_size:]

iv = Random.new().read(AES.block_size)
cipher = AES.new(key_enc, AES.MODE_CFB, iv)
c_msg = iv + cipher.encrypt(p_msg + str(datetime.datetime.now())) 

hash = HMAC.new(key_mac)
hash.update(c_msg)

pkt = hash.hexdigest() + binascii.hexlify(c_msg)

channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
channel.connect(('localhost', 3000))
channel.send(pkt)

exit(0)
