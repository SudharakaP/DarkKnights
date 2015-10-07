# ----------------------------------------------------------------------------
#  Source:    client.py
#  Author:    Keith R. Gover
#  Date:      October 05, 2015
#  Modified:  October 06, 2015
#  File:      Python script for doing authenticated encryption.  This is the
#             client side (ATM) that:
#                 * Reads in the message to be sent.
#                 * Reads the bank.auth file to get the encryption keys.
#                 * Generates the packet containing a hash tag of the
#                   encrypted message and the encrypted message.
#                 * Send the packet out to the bank.
#  Remarks:   University of Maryland: Cybersecurity Capstone Project
# ----------------------------------------------------------------------------
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
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

print '\n' + p_msg + '\n'

# ----------------------------------------------------------------------------
#  We are using "encrypt then authenticate" since this provides CCA security.
#  This code does the following:
#
#      * Break the contents of the bank.auth file into 2 128-bit keys.
#
#      * Do the encryption of the message using an AES block cipher in cipher
#        feedback mode (CFB).  The message includes a 26-byte datetime stamp
#        that the bank can use as a packet ID to prevent replay attacks.
#
#      * Takes the encrypted message and runs it through an HMAC hash function
#        so we can be certain it has not been altered in transit.
#
#      * Create packet for transmission in hexadecimal form.  The hash tag is
#        already in hex but the ciphertext needs to be converted.
#
#      * Sends the packet out on the port.
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
