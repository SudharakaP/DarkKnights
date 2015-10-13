#!/usr/bin/python
# ----------------------------------------------------------------------------
#  Team:    DarkKnights
#  Date:    September 24, 2015
#  Members: Johann Roturier, Keith Gover, Sudharaka Palamakumbura,
#           Yannis Pappas, Yogesh Dorbala
#  Script:  Implement bank functionality for the Coursera Captsone project
#  URL:     https://builditbreakit.org/static/doc/fall2015/spec/atm.html
# ----------------------------------------------------------------------------
import sys
from optparse import OptionParser
import os.path
import simplejson as json
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
from hmac import compare_digest
import binascii, socket
import signal
from random import randint

# ----------------------------------------------------------------------------
#  This function appends a carriage return to the end of the input string,
#  prints the string plus carriage return and then flushes the I/O buffer.
#  This is a project requirement.
# ----------------------------------------------------------------------------
def print_flush(S_in) :
    print S_in
    sys.stdout.flush()

# Check if float is equal to an int.
def custom_round(flt):
    if abs(int(flt)-flt) < 0.001:
        return int(flt)
    return flt

# Handles the SIGTERM and SIGINT calls.
def handler(signum, frame):
    sys.exit(0)

def encrypt_pin(key, pin):
    obj = AES.new(key, AES.MODE_CBC, 'iv')
    return obj.encrypt(pin)

def decrypt_pin(key, pin):
    obj = AES.new(key, AES.MODE_CBC, 'iv')
    return obj.decrypt(pin)

# ----------------------------------------------------------------------------
#  This method takes a reqeust sent by the ATM in JSON and checks whether it
#  meets the specified requirements.  If so returns a JSON object, otherwise
#  return 255.
# ----------------------------------------------------------------------------

# Account details (customer name and balance) are stored in this dictionary.
customers = {}
pins = {}

# Temporary dictionary to roll back in case of protocol error. 
customers_temp = {}

# Account name.
account_name = ''

def atm_request(atm_request):

    request = json.loads(atm_request)
    global account_name
    account_name = request['account']
    try:
        pin = request['pin']
    except KeyError:
        return "255"
    if pin is None and not pins.get(account_name):#for account creation
        #sys.stderr.write("NEW: %s - %s \n" % (pin, pins.get(account_name)))
        pin = str(randint(0,9999))

    # ------------------------------------------------------------------------
    #  Creation of new account if the given account does not exist
    #  (balance > 10 already taken care of in atm file).
    # ------------------------------------------------------------------------
    if (request['new'] is not None) and (account_name not in customers):
        customers_temp[account_name] = custom_round(float(request['new']))
        pins[account_name] = str(pin)
        summary = json.dumps({"initial_balance": customers_temp[account_name], "account": account_name, "pin": pin})
        return summary

    # ------------------------------------------------------------------------
    #  Read balance if account already exists and pin matches
    # ------------------------------------------------------------------------
    elif (request['get'] is not None) and (account_name in customers) and (pin == pins.get(account_name)):
        summary = json.dumps({"account": account_name, "balance": customers_temp[account_name]})
        return summary

    # ------------------------------------------------------------------------
    #  Deposit specified amount if account already exists and pin matches
    # ------------------------------------------------------------------------
    elif (request['deposit'] is not None) and (account_name in customers) and (pin == pins.get(account_name)):
        customers_temp[account_name] = custom_round(round(customers[account_name] + float(request['deposit']),2))
        summary = json.dumps({"account":account_name, "deposit": custom_round(float(request['deposit']))})
        return summary

    # ------------------------------------------------------------------------
    #  Withdraw specified amount if account already exists and pin matches
    # ------------------------------------------------------------------------
    elif (request['withdraw'] is not None) and (account_name in customers) and (float(request['withdraw']) <= customers[account_name]) \
        and (pin == pins.get(account_name)):
        customers_temp[account_name] = custom_round(round(customers[account_name] - float(request['withdraw']),2))
        summary = json.dumps({"account":account_name, "withdraw": custom_round(float(request['withdraw']))})
        return summary

    # ------------------------------------------------------------------------
    #  Request is not recognized.
    # ------------------------------------------------------------------------
    else:
        return "255"

# ----------------------------------------------------------------------------
#  Create the encrypted message that is to be sent to the atm.
#
#  TODO:
#      * Do we need to worry about replay attacks?  If so add packet ID.
# ----------------------------------------------------------------------------
def message_to_atm(p_msg, auth_file):
    try:
        fi = open(auth_file, 'r')
        k_tmp = binascii.unhexlify(fi.read())
        fi.close()
    except IOError:
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

# ----------------------------------------------------------------------------
#  Custom error code 255 for any invalid command-line options.
# ----------------------------------------------------------------------------
class BankParser(OptionParser):
    def error(self, message=None):
        sys.exit(255)

def main():

    # Handles the SIGTERM and SIGINT calls.    
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
	
    parser = BankParser()
    parser.add_option('-p', action = 'store', dest = 'PORT', type = 'int', default = 3000)
    parser.add_option('-s', action = 'store', dest = 'AUTH_FILE', default = 'bank.auth')
    (options, args) = parser.parse_args()

    # ------------------------------------------------------------------------
    #  Input Validation
    # ------------------------------------------------------------------------
    
    # Check that length of string arguments is not over 4096 characters
    for option in [options.AUTH_FILE] + args:
        if isinstance(option, str) and len(option) > 4096:
            parser.error('Argument too long for one of the options.')

    # Check that port number format is valid (beyond default validation provided by optparse)
    if not 1024 <= int(options.PORT) <= 65535:
        parser.error('Invalid port number: %d' % int(options.PORT))

    # ------------------------------------------------------------------------
    # Check whether authentication file exist, if not create it:
    #     * Generate two 128-bit keys, one for authentication & one for
    #       encryption.
    #     * The AES block size is always 16-bytes (128-bits).
    #     * These are written to the file bank.auth in hexadecimal form.
    # ------------------------------------------------------------------------
    if os.path.isfile(options.AUTH_FILE):
        sys.exit(255) 
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
            sys.exit(255)

    # ------------------------------------------------------------------------
    #  This block does the following, note the incoming packet is in binary
    #  form:
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
    #      * Run the hash function on the full ciphertext and compares it to
    #        the hash tag extracted in the step above.  The comparison is done
    #        using a method from the hmac library that does an equal time
    #        compare to guard against timing attacks.
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
    #      * After processing the message is returned to the ATM along with
    #        the packet ID from the incoming packet.  This will be compared
    #        in the ATM to the ID it generated and make sure they are the
    #        same.
    #
    #      * Successful exit requires exit with code 0
    #
    #  TODO:
    #      * The code currently only allows one connection.  Do we need to
    #        expand this so multiple ATM's can connect?
    #      * Do we need to prevent multiple banks from being opened?
    #
    # ------------------------------------------------------------------------

    # Maintain a list of previous date/time stamps
    id_list = []

    channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    channel.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    channel.bind(('localhost', options.PORT))
    channel.listen(1)

    while True:
        connection, address = channel.accept()    
        try:
            connection.settimeout(10)
            pkt = connection.recv(1024)
            connection.settimeout(None)
        except socket.error:
            print_flush('protocol_error')
            continue

        if (len(pkt) > 0) and (len(pkt) < 1024):
            h_tag = pkt[0:16]
            c_tmp = pkt[16:]

            iv = c_tmp[:AES.block_size]
            c_msg = c_tmp[AES.block_size:]

            hash = HMAC.new(key_mac)
            hash.update(c_tmp)

            try:
                cipher = AES.new(key_enc, AES.MODE_CFB, iv)
            except ValueError:
                print_flush('protocol_error')
                continue

            if compare_digest(h_tag, hash.digest()):
                p_tmp = cipher.decrypt(c_msg)
                pkt_id = p_tmp[-26:]
                p_msg = p_tmp[:-26]
                if pkt_id not in id_list:
                    id_list.append(pkt_id)
                    message = atm_request(p_msg)
                    if message != '255':
                        temp_message = json.loads(message)
                        try:
                            del temp_message['pin']
                        except KeyError:
                            pass
                        temp_message = json.dumps(temp_message)
                        print_flush(str(temp_message))

                    # Append packet ID, encrypt and sends the message to atm.
                    message = message + pkt_id
                    enc_message = message_to_atm(message, options.AUTH_FILE)

                    # Update the customer dictionary only if confimation sent to ATM
                    sent = connection.sendall(enc_message)
                    if sent is None:
                        try:
                            customers[account_name] = customers_temp[account_name]
                        except KeyError: #customers_temp may not have been populated if account verification failed
                            pass

                else:
                    print_flush('protocol_error')
            else:
                print_flush('protocol_error')    
        else:
            print_flush('protocol_error')
    sys.exit(0)
        
if __name__ == "__main__":
    main()
