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
#      * Continually isten to the port and wait for a packet to arrive.  This
#        code currently is only allowing one connection.  Will need to expand
#        so multiple ATM's can connect.
#
#      * Extract the hash tag from the incoming packet.  This needs to remain
#        in hexadecimal form.
#
#      * Extract the IV and encrypted message from the incoming packet.  This
#        needs to be converted to binary.
#
#      * Run the hash function on the full ciphertext and compares it to the
#        hash tag extracted in the step above.
#
#      * If the message is authentic, decrypt it and extract the packet ID
#        and the plaintext message.
#
#      * If the packet ID does not match any previous packet ID's, then
#        print out the message.  This step prevents replay attacks.
#
#  Need to prevent multiple banks from being opened.
# ----------------------------------------------------------------------------
channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
channel.bind(('localhost', 3000))
channel.listen(1)

while True:
    connection, address = channel.accept()
    pkt = connection.recv(256)
    if (len(pkt) > 0) and (len(pkt) < 256):
        h_tag = pkt[0:32]
        c_tmp = binascii.unhexlify(pkt[32:])
        
        iv = c_tmp[0:AES.block_size]
        c_msg = c_tmp[AES.block_size:]

        hash = HMAC.new(key_mac)
        hash.update(c_tmp)
        cipher = AES.new(key_enc, AES.MODE_CFB, iv)
        
        if (h_tag == hash.hexdigest()):
            p_tmp = cipher.decrypt(c_msg)
            pkt_id = p_tmp[-26:]
            p_msg = p_tmp[:-26]
            if pkt_id not in id_list:
                if p_msg == 'eject eject eject':
                    print '\nGoodbye!\n'
                    break
                else:
                    id_list.append(pkt_id)
                    print p_msg
        else:
            print('Error processing: packet.dat')
            exit(255)
    
