#!/usr/bin/python

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
import binascii, socket
import re

#--------------------------------------------------------------------------------------------------------------------
# Helper functions that validates the input according to the given specification. 
#
#--------------------------------------------------------------------------------------------------------------------

def is_valid_amount_format(amount, max_amount=4294967295.99):

    """Balances and currency amounts are specified as a number indicating a whole amount and a fractional input separated by a period.
    The fractional input is in decimal and is always two digits and thus can include a leading 0 (should match /[0-9]{2}/).
    The interpretation of the fractional amount v is that of having value equal to v/100 of a whole amount 
    (akin to cents and dollars in US currency).
    Command line input amounts are bounded from 0.00 to 4294967295.99 inclusively
    but an account may accrue any non-negative balance over multiple transactions."""

    pattern = re.compile(r'^(0|[1-9][0-9]*)(\.[0-9]{2})?$')
    if not re.match(pattern, amount) or float(amount) > max_amount:
        return False
    return True

def is_valid_account_format(account):

    """Account names are restricted to same characters as file names
    but they are inclusively between 1 and 250 characters of length, and "." and ".." are valid account names."""

    pattern = re.compile(r'^[_\-\.0-9a-z]{1,250}$')
    if not re.match(pattern, account):
        return False
    return True

def is_valid_filename_format(file_name):

    """File names are restricted to underscores, hyphens, dots, digits, and lowercase alphabetical characters 
    (each character should match /[_\-\.0-9a-z]/).
     File names are to be between 1 and 255 characters long. The special file names "." and ".." are not allowed."""

    if file_name in ['.', '..']:
        return False

    pattern = re.compile(r'^[_\-\.0-9a-z]{1,255}$')
    if not re.match(pattern, file_name):
        return False
    return True


def is_valid_ip_address(ip_address):

    """Validate accordign to spec: 
    i.e., four numbers between 0 and 255 separated by periods."""

    pattern = re.compile(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})')
    match = re.match(pattern, ip_address)
    if not match or not match.groups():
        return False
    valid_numbers = [True for group in match.groups() if 0 <= int(group) <= 255]
    if valid_numbers.count(True) != 4:
        return False
    return True


# ----------------------------------------------------------------------------
#  This function appends a carriage return to the end of the input string,
#  prints the string plus carriage return and then flushes the I/O buffer.
#  This is a project requirement.
# ----------------------------------------------------------------------------
def print_flush (S_in) :
    print S_in + '\n'
    sys.stdout.flush()

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
		customers[account_name] = "%.2f" % float(request['new'])
		summary = json.dumps({"account":account_name, "initial-balance": "%.2f" % float(customers[account_name])})
		return summary

	# Read balance if account already exist.
	elif (request['get'] is not None) and (account_name in customers):
		summary = json.dumps({"account":account_name, "balance": "%.2f" % float(customers[account_name])})
		return summary

	# Deposit specified amount if account already exist.
	elif (request['deposit'] is not None) and (account_name in customers):
		customers[account_name] += "%.2f" % float(request['deposit'])
		summary = json.dumps({"account":account_name, "deposit": "%.2f" % float(request['deposit'])})
		return summary

	# Withdraw specified amount if account already exist.
	elif (request['withdraw'] is not None) and (account_name in customers) and ("%.2f" % float(request['withdraw']) <= "%.2f" % float(customers[account_name])):
		customers[account_name] -= "%.2f" % float(request['withdraw'])
		summary = json.dumps({"account":account_name, "withdraw": "%.2f" % float(request['withdraw'])})
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
			print_flush("created")
		except IOError:
			sys.stderr.write('Cannot find file: bank.auth')
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


	
	
	
