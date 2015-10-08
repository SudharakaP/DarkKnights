###############################################################################
# Script to implement ATM functionality for Coursera Captsone project
# https://builditbreakit.org/static/doc/fall2015/spec/atm.html
###############################################################################

import sys
from optparse import OptionParser
import os.path
import signal
import json
import datetime
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
from hmac import compare_digest
from helper import *
import binascii, socket

###############################################################################################################
# This method takes a reqeust sent by the ATM in JSON and checks whether it meets the specified requirements. 
# If so returns a JSON object, otherwise return 255.
###############################################################################################################

# Account details (customer name and balance) are stored in this dictionary.
customers = {}

def atm_request(atm_request):

	request = json.loads(atm_request)

	account_name = request['account']

	# Creation of new account if the given account does not exist(balance > 10 already taken care of in atm file).
	if (request['new'] is not None) and (account_name not in customers):
		customers[account_name] = float(request['new'])
		summary = json.dumps({"account":account_name, "initial-balance": request['new']})
		return summary

	# Read balance if account already exist.
	elif (request['get'] is not None) and (account_name in customers):
		summary = json.dumps({"account":account_name, "balance": customers[account_name]})
		return summary

	# Deposit specified amount if account already exist.
	elif (request['deposit'] is not None) and (account_name in customers):
		customers[account_name] += float(request['deposit'])
		summary = json.dumps({"account":account_name, "deposit": customers[account_name]})
		return summary

	# Withdraw specified amount if account already exist.
	elif (request['withdraw'] is not None) and (account_name in customers) and (request['withdraw'] <= customers[account_name]):
		customers[account_name] -= float(request['deposit'])
		summary = json.dumps({"account":account_name, "deposit": customers[account_name]})
		return summary
	else:
		return "255"

# Creates the encrypted message that is to be sent to the atm. Borrowed heavily from Keith's client.py

def message_to_atm(p_msg, auth_file):
	try:
            fi = open(auth_file, 'r')
            k_tmp = binascii.unhexlify(fi.read())
            fi.close()
        except IOError:
            sys.stderr.write('Cannot find file: %s' % self.auth_file) 
            sys.exit(255)

	key_enc = k_tmp[0:AES.block_size]
        key_mac = k_tmp[AES.block_size:]

        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key_enc, AES.MODE_CFB, iv)
        c_msg = iv + cipher.encrypt(p_msg) 

        hash = HMAC.new(key_mac)
        hash.update(c_msg)

        pkt = hash.digest() + c_msg

	return pkt

# Custom error code 255 for any invalid command-line options.
class BankParser(OptionParser):
	def error(self, message):
		sys.exit(255)

def main():

	parser = BankParser()

	parser.add_option('-p', action = 'store', dest = 'PORT', type = 'int', default = 3000)

	parser.add_option('-s', action = 'store', dest = 'AUTH_FILE', default = 'bank.auth')

	(options, args) = parser.parse_args()

    	######################
    	# Input Validation
    	######################
    
    	#Check that length of string arguments is not over 4096 characters
    	for option in [options.AUTH_FILE] + args:
        	if isinstance(option, str) and len(option) > 4096:
            		parser.error('Argument too long for one of the options.')

    	# Check that port number format is valid (beyond default validation provided by optparse)
    	if not 1024 <= int(options.PORT) <= 65535:
        	parser.error('Invalid port number: %d' % options.PORT)
	
	###############################################################################
	# Check whether authentication file exist, if not create it. 
	# Generate two 128-bit key, one for authentication and one for encryption.
	# The AES block size is always 16-bytes (128-bits). 
	# These are written to the file bank.auth in hexadecimal form.
	###############################################################################
	if os.path.isfile(options.AUTH_FILE):
		exit(255) 
	else:
		key_enc = Random.new().read(AES.block_size)
		key_mac = Random.new().read(AES.block_size)

		try:
			fo = open(options.AUTH_FILE, 'w')
			fo.write(binascii.hexlify(key_enc))
			fo.write(binascii.hexlify(key_mac))
			fo.close()
			print "created"
		except IOError:
			print ('Cannot find file: bank.auth')
			exit(255)

	###############################################################################
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
	#      * The code currently only allows one connection.  We will need to
	#        expand this so multiple ATM's can connect.
	#      * Need to prevent multiple banks from being opened.
	#
	################################################################################

	# Maintain a list of previous date/time stamps
	id_list = []

	channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	channel.bind(('localhost', options.PORT))
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
			id_list.append(pkt_id)
			message = atm_request(p_msg)
			if message != '255':
				print message
			
			# Encrypts and sends the message to atm.
			enc_message = message_to_atm(message, options.AUTH_FILE)
		     	connection.sendall(enc_message)
		    else:
		        print_flush('protocol_error')
		else:
		    print_flush('protocol_error')    
            else:
	        print_flush('protocol_error')
        exit(0)
	
if __name__ == "__main__":
	main()


	
	
	
