# ----------------------------------------------------------------------------
#  Source:    server.py
#  Author:    Keith R. Gover
#  Date:      October 05, 2015
#  Modified:  October 07, 2015
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
from hmac import compare_digest
from helper import print_flush
import binascii, socket

# Maintain a list of previous date/time stamps
id_list = []

# ----------------------------------------------------------------------------
#  Generate two 128-bit key, one for authentication and one for encryption.
#  The AES block size is always 16-bytes (128-bits).  These are written to
#  the file bank.auth in hexadecimal form.
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
#      * Continually isten to the port and wait for a packet to arrive.
#
#      * When a packet is received, grab up to 1024-bytes which should be
#        longer than the longest possible command plus the packet ID.
#
#      * Extract the 16-byte hash tag from the incoming packet.
#
#      * Extract the IV and encrypted message from the incoming packet.
#
#      * Run the hash function on the full ciphertext and compares it to the
#        hash tag extracted in the step above.  The comparison is done using
#        a method from the hmac library that does an equal time compare to
#        guard against timing attacks.
#
#      * If the message is authentic, decrypt it and extract the packet ID
#        and the plaintext message.  The packet ID is the last 26-bytes of
#        decrypted message.
#
#      * If the packet ID does not match any previous packet ID's, then
#        print out the message.  This step guard against replay attacks.
#
#      * All messages are printed using a function that adds a carriage
#        return to the end of the string and then flushes the I/O buffer.
#
#      * Successful exit requires exit with code 0
#
#  TODO:
#      * The code currently only allows one connection.  Ww will need to
#        expand this so multiple ATM's can connect.
#      * Need to prevent multiple banks from being opened.
#
# ----------------------------------------------------------------------------
channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
channel.bind(('localhost', 3000))
channel.listen(1)

while True:
    connection, address = channel.accept()
    pkt = connection.recv(1024)
    if (len(pkt) > 0) and (len(pkt) < 1024):
        h_tag = pkt[0:16]
        c_tmp = pkt[16:]
        
        iv = c_tmp[:AES.block_size]
        c_msg = c_tmp[AES.block_size:]

        hash = HMAC.new(key_mac)
        hash.update(c_tmp)
        cipher = AES.new(key_enc, AES.MODE_CFB, iv)

        if compare_digest(h_tag, hash.digest()):
            p_tmp = cipher.decrypt(c_msg)
            pkt_id = p_tmp[-26:]
            p_msg = p_tmp[:-26]
            if pkt_id not in id_list:
                if p_msg == 'eject eject eject':
                    print_flush('Goodbye!')
                    break
                else:
                    id_list.append(pkt_id)
                    print_flush(p_msg)
            else:
                print_flush('protocol_error')
        else:
            print_flush('protocol_error')
    else:
        print_flush('protocol_error')

exit(0)
