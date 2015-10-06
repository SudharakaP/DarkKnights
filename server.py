# ----------------------------------------------------------------------------
#  Source:    server.py
#  Author:    Keith R. Gover
#  Date:      October 05, 2015
#  Modified:  October 06, 2015
#  File:      Python script for doing authenticated encryption.  This is the
#             server side (bank) that:
#                 * Generate the encryption keys & writes them to bank.auth.
#                 * Listen to the port waiting for communication from the ATM.
#                 * When a packet arrives, check the hash tag to ensures the
#                   message is an authentic message from the ATM.
#                 * If the message is authentic, then decrypt the message.
#  Remarks:   University of Maryland: Cybersecurity Capstone Project
# ----------------------------------------------------------------------------
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
import binascii
import socket

# ----------------------------------------------------------------------------
#  Generate two 128-bit key, one for authentication and one for encryption.
# ----------------------------------------------------------------------------
key_enc = Random.new().read(AES.block_size)
key_mac = Random.new().read(AES.block_size)

try:
    fo = open('./bank.auth', 'w')
    fo.write(binascii.hexlify(key_enc))
    fo.write(binascii.hexlify(key_mac))
    fo.close()
except IOError:
    print ('Cannot find file: bank.auth')
    exit(255)

# ----------------------------------------------------------------------------
#  This block does the following, note the incoming packet is in a
#  hexadecimal form:
#
#      * Continually isten to the port and wait for a packet to arrive.  This
#        code currently is only allowing one connection.  Will need to expand
#        so multiple ATM's can connect.
#
#      * Extracts the hash tag from the full ciphertext (c_tmp).  This needs
#        to remain in hexadecimal form.
#
#      * Extracts the IV and encrypted message from the full ciphertext.
#        This needs to be converted to binary.
#
#      * Runs the hash function on the full ciphertext and compares it to the
#        hash tag extracted in the step above.
#
#      * If the message is authentic, decrypts and prints out the message.
#
# ----------------------------------------------------------------------------
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(('localhost', 8089))
serversocket.listen(1)

while True:
    connection, address = serversocket.accept()
    c_tmp = connection.recv(256)
    if (len(c_tmp) > 0) and (len(c_tmp) < 256):
        h_tag = c_tmp[0:32]
        c_tmp = binascii.unhexlify(c_tmp[32:])
        
        iv = c_tmp[0:AES.block_size]
        c_msg = c_tmp[AES.block_size:]

        hash = HMAC.new(key_mac)
        hash.update(c_tmp)
        cipher = AES.new(key_enc, AES.MODE_CFB, iv)
        
        if (h_tag == hash.hexdigest()):
            p_msg = cipher.decrypt(c_msg)
            print '\n' + p_msg + '\n'
        else:
            print('Error processing: packet.dat')
            exit(255)
    
        break
