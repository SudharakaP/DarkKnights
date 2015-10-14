#!/usr/bin/python
# ----------------------------------------------------------------------------
#  Team:    DarkKnights
#  Date:    September 24, 2015
#  Members: Johann Roturier, Keith Gover, Sudharaka Palamakumbura,
#           Yannis Pappas, Yogesh Dorbala
#  Script:  Implement ATM functionality for the Coursera Captsone project:
#  URL:     https://builditbreakit.org/static/doc/fall2015/spec/atm.html
# ----------------------------------------------------------------------------
import sys
import os
import json
import binascii
import socket
import datetime
from optparse import OptionParser
from Crypto.Hash import HMAC
from Crypto.Cipher import AES
from Crypto import Random
from hmac import compare_digest
import re

# ----------------------------------------------------------------------------
#  Helper functions that validates the input according to the given
#  specification. 
# ----------------------------------------------------------------------------
def is_valid_amount_format(amount, max_amount=4294967295.99):

    """Balances and currency amounts are specified as a number indicating a whole amount
    and a fractional input separated by a period.  The fractional input is in decimal
    and is always two digits and thus can include a leading 0 (should match /[0-9]{2}/).
    The interpretation of the fractional amount v is that of having value equal to v/100
    of a whole amount (akin to cents and dollars in US currency).
    Command line input amounts are bounded from 0.00 to 4294967295.99 inclusively
    but an account may accrue any non-negative balance over multiple transactions."""

    pattern = re.compile(r'^(0|[1-9][0-9]*)\.\d{2}$')
    if not pattern.match(amount) or float(amount) > max_amount:
        return False
    return True

def is_valid_account_format(account):

    """Account names are restricted to same characters as file names but they are
    inclusively between 1 and 250 characters of length, and "." and ".." are valid
    account names."""

    pattern = re.compile(r'^[_\-\.0-9a-z]{1,250}$')
    if not pattern.match(account):
        return False
    return True

def is_valid_filename_format(file_name):

    """File names are restricted to underscores, hyphens, dots, digits, and lowercase
    alphabetical characters (each character should match /[_\-\.0-9a-z]/).  File names
    are to be between 1 and 255 characters long. The special file names "." and ".."
    are not allowed."""

    if file_name in ['.', '..']:
        return False

    pattern = re.compile(r'^[_\-\.0-9a-z]{1,255}$')
    if not pattern.match(file_name):
        return False
    return True

def is_valid_ip_address(ip_address):

    """Validate accordign to spec: 
    i.e., four numbers between 0 and 255 separated by periods."""

    pattern = re.compile(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})')
    match = pattern.match(ip_address)
    if not match or not match.groups():
        return False
    valid_numbers = [True for group in match.groups() if 0 <= int(group) <= 255]
    if valid_numbers.count(True) != 4:
        return False
    return True

def is_valid_port_number(port_number):
    """Port number should be 4 or 5 digits between 1024 and 65535."""
    pattern = re.compile(r'^[1-9][0-9]{3,4}$')
    if not pattern.match(port_number):
        return False
    if not 1024 <= int(port_number) <= 65535:
        return False
    return True

# ----------------------------------------------------------------------------
#  This function appends a carriage return to the end of the input string,
#  prints the string plus carriage return and then flushes the I/O buffer.
#  This is a project requirement.
# ----------------------------------------------------------------------------
def print_flush (S_in) :
    print S_in
    sys.stdout.flush()

# ----------------------------------------------------------------------------
#  Parse ATM CLI options
# ----------------------------------------------------------------------------
class ATMOptionParser(OptionParser):
    def error(self, msg=None):
        # if msg:
        #     sys.stderr.write(msg)
        sys.exit(255)

# ----------------------------------------------------------------------------
#  ATM class that offloads work to Bank server, which will return 255 or
#  JSON-encoded string.
# ----------------------------------------------------------------------------
class ATM:

    def __init__(self, ip_address=None, port=None, auth_file=None):

        self.bank_ip_address = ip_address
        self.bank_port = int(port)
        self.auth_file = auth_file # TODO: Use this to encrypt and/or generate card file


    def create_card(self, account, card, pin):

        """Create card. Spec: Card files are created when atm is invoked with -n to
        create a new account.  This must happen afer the bank has confirmed that the
        account does not already exist.  The default value is the account name
        prepended to ".card" ("<account>.card").  For example, if the account name
        was 55555, the default card file is "55555.card"."""

        if card is None:
            card = "%s.card" % account

        try:
            f = open(card, 'w')
        except IOError:
            return False
        
        try:
            fi = open(self.auth_file, 'r')
            k_tmp = binascii.unhexlify(fi.read())
            fi.close()
        except IOError:
            # sys.stderr.write('Cannot find file: %s' % self.auth_file)
            sys.exit(255)

        auth_enc = k_tmp[0:AES.block_size]
        iv = Random.new().read(AES.block_size)

        try:
            cipher = AES.new(auth_enc, AES.MODE_CFB, iv)
        except ValueError:
            # sys.stderr.write('Wrong AES parameters')
            sys.exit(63)
        
        enc_pin = iv + cipher.encrypt(str(pin))
        
        try:
            f.write(enc_pin)
        except IOError:
            return False
        return True

    def get_pin(self, card=None, account=None):

        if not card: #No card specified
            card = "%s.card" % account
            if not os.path.isfile(card): #No existing card for account
                return

        try:
            f = open(card, 'r')
        except IOError:
            # sys.stderr("Cannot open card file.")
            sys.exit(255)

        try:
            fi = open(self.auth_file, 'r')
            k_tmp = binascii.unhexlify(fi.read())
            fi.close()
        except IOError:
            # sys.stderr.write('Cannot find file: %s' % self.auth_file)
            sys.exit(255)

        key_enc = k_tmp[0:AES.block_size]

        enc_pin = f.read()
        iv = enc_pin[0:AES.block_size]
	pin = enc_pin[AES.block_size:]
	f.close()        

        try:
            cipher = AES.new(key_enc, AES.MODE_CFB, iv)
        except ValueError:
            # sys.stderr.write('Wrong AES parameters')
            sys.exit(63)

	return cipher.decrypt(pin)

    def is_valid_account(self, account, card):

        """Check that account matches associated card."""

        # ------------------------------------------------------------------------
        #  The default value is the account name prepended to ".card"
        #  ("<account>.card").  For example, if the account name was 55555, the
        #  default card file is "55555.card".
        # ------------------------------------------------------------------------
        if card is None:
            card = "%s.card" % account

        card_info = None
        msg = None
        try:
            card_file = open(card, 'r')
        except IOError as e:
            msg = '%s: %s' % (e.strerror, card)
            return (False, msg)
        else:
            card_info = card_file.read()
            card_file.close()
            if card_info != account:
                msg = 'Account does not match card.'
                return (False, msg)
            return (True, 'OK - but probably not really :-)')

    def sanitize_query(self, options=None, pin=None):

        """Sanitize query by transforming relevant options from options object into
        JSON-encoded string."""

        query = dict(zip(['account', 'new', 'deposit', 'withdraw', 'get', 'new', 'pin'], 
                        [options.account, options.new, options.deposit, options.withdraw, options.get, options.new, pin]
                        ))
        #print query
        return json.dumps(query)

    def communicate_with_bank(self, p_msg):

        """Send validated, encrypted and authenticated query to bank.
        Based on kgover's client.py code but adds call to receive response.
        Expects the encrypted and authenticated response to be a JSON-encoded string."""
        try:
            fi = open(self.auth_file, 'r')
            k_tmp = binascii.unhexlify(fi.read())
            fi.close()
        except IOError:
            # sys.stderr.write('Cannot find file: %s' % self.auth_file)
            sys.exit(255)

        key_enc = k_tmp[0:AES.block_size]
        key_mac = k_tmp[AES.block_size:]

        iv = Random.new().read(AES.block_size)

        try:
            cipher = AES.new(key_enc, AES.MODE_CFB, iv)
        except ValueError:
            # sys.stderr.write('Wrong AES parameters')
            sys.exit(63)

        outgoing_pkt_id = str(datetime.datetime.now())
        p_msg = p_msg + outgoing_pkt_id
        pkt_len = '%d' % len(p_msg)
        c_msg = iv + cipher.encrypt(p_msg.zfill(987) + pkt_len.zfill(5)) 

        hash = HMAC.new(key_mac)
        hash.update(c_msg)

        pkt = hash.digest() + c_msg

        # Create a socket (SOCK_STREAM means a TCP socket)
        try:    
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            # sys.stderr.write('Socket error')
            sys.exit(63)

        # Connect to server and send data           
        sock.connect((self.bank_ip_address, self.bank_port))
        sent = sock.sendall(pkt)
        if sent is not None:
            # sys.stderr.write("Sending packets failed")
            sys.exit(63)
        
        # Receive data from the server and shut down#
        try:
            sock.settimeout(10)
            pkt = sock.recv(1024)
            sock.settimeout(None)
        except socket.error:
            # sys.stderr.write("No packets recieved")
            sys.exit(63)

        # --------------------------------------------------------------------
        #  * Extract the hash tag from the incoming packet.
        #
        #  * Extract the IV and encrypted message from the incoming packet.
        #
        #  * Run the hash function on the full ciphertext and compares it to
        #    the hash tag extracted in the step above.  This is using a
        #    constant time function form the hmac library to guard against
        #    timing attacks.
        #
        #  * Check the hash of the bank's response and if valid, decrypt it.
        #    The decrypted message has three parts starting from the end of
        #    the string:
        #
        #        a. 5 bytes ....... length of the plaintext message
        #        b. 26 bytes ...... Packet ID (datetime stamp)
        #        c. 961 bytes ..... Plaintext message zero padded
        #
        #    The zero padding will need to be stripped off the 961 bytes by
        #    using the first 5 bytes.
        #
        #  * Check the packet ID being returned from the bank and make sure
        #    it matches the packet ID used for the outgoing packet.  This will
        #    defend against replay attacks on the ATM.
        #
        # --------------------------------------------------------------------
        if len(pkt) > 0:
            h_tag = pkt[0:16]
            c_tmp = pkt[16:]
            iv = c_tmp[0:AES.block_size]

            c_msg = c_tmp[AES.block_size:]

            hash = HMAC.new(key_mac)
            hash.update(c_tmp)

            try:
                cipher = AES.new(key_enc, AES.MODE_CFB, iv)
            except ValueError:
                # sys.stderr.write('Wrong AES parameters.')
                sys.exit(63)

            if compare_digest(h_tag, hash.digest()):
                #TODO: catch potential error
                p_tmp = cipher.decrypt(c_msg)
                pkt_len = p_tmp[-5:]
                incoming_pkt_id = p_tmp[-31:-5]
                p_msg = p_tmp[987-int(pkt_len):-31]
                if incoming_pkt_id == outgoing_pkt_id:
                    return p_msg
                else:
                    # sys.stderr.write('Packet Comparison failed.')
                    sys.exit(63)
            else:
                # sys.stderr.write('Digest comparison failed.')
                sys.exit(63)

def main():

    parser = ATMOptionParser()
    parser.add_option("-a", action="store", dest="account")
    parser.add_option("-n", action="store", dest="new")
    parser.add_option("-d", action="store", dest="deposit")
    parser.add_option("-w", action="store", dest="withdraw")
    parser.add_option("-g", action="store_true", dest="get")
    parser.add_option("-p", action="store", dest="port", default='3000', type="string")
    parser.add_option("-i", action="store", dest="ip_address", default="127.0.0.1", type="string")
    parser.add_option("-s", action="store", dest="auth", default="bank.auth")
    parser.add_option("-c", action="store", dest="card")

    (options, args) = parser.parse_args()

    # ------------------------------------------------------------------------
    #  Basic input validation
    # ------------------------------------------------------------------------

    # Check for any repeated cmd-line options
    if len(sys.argv) != len(set(sys.argv)):
        parser.error('Repeated cmd-lin arguments')

    # Check to see if there's any additional arguments
    if len(args) > 0:
        parser.error('Additional argument error')

    # Check that length of string arguments is not over 4096 characters
    for option in [options.account, options.new, options.deposit, options.withdraw, options.ip_address, options.auth, options.card] + args:
        if isinstance(option, str) and len(option) > 4096:
            parser.error('Argument too long for one of the options.')

    # Check that required parameter is passed
    if not options.account:
        parser.error('"-a" is required.')

    # Check that valid account name format is provided
    if not is_valid_account_format(options.account):
        parser.error('Invalid account name: %s' % options.account)

    # Check that at one mode of operation is specified
    if (not options.new) and (not options.deposit) and (not options.withdraw) and (not options.get):
        parser.error('One mode of operation must be specified.')

    # Check that two modes of operation are not specified
    if (options.new and options.deposit) or (options.new and options.withdraw) or (options.new and options.get) \
        or (options.deposit and options.withdraw) or (options.deposit and options.get) or (options.withdraw and options.get):
         parser.error('Only one mode of operation must be specified.')

    # Check that IP address format is valid
    if not is_valid_ip_address(options.ip_address):
        parser.error('Invalid IP address: %s' % options.ip_address)

    # Check that port number format is valid
    if not is_valid_port_number(options.port):
        parser.error('Invalid port number: %s' % options.port)

    # Check that potential balance format is valid
    if options.new:
        if not is_valid_amount_format(options.new) or not float(options.new) >= 10:
            parser.error('Invalid balance amount: %s' % options.new)

    # Check that potential deposit format is valid
    if options.deposit:
        if not is_valid_amount_format(options.deposit) or not float(options.deposit) > 0:
            parser.error('Invalid deposit amount: %s' % options.deposit)

    # Check that potential withdrawal format is valid
    if options.withdraw:
        if not is_valid_amount_format(options.withdraw) or not float(options.withdraw) > 0:
            parser.error('Invalid withdrawal amount: %s' % options.withdraw)

    # Validate the card file format
    if options.card and not is_valid_filename_format(options.card):
        parser.error('Invalid card file format: %s' % options.card)

    # Validate that the specified card file does not already exist for new accounts
    if options.new and options.card and os.path.isfile(options.card):
        parser.error('Card already exists: %s' % options.card)

    # ------------------------------------------------------------------------
    #  Core functionality
    # ------------------------------------------------------------------------

    # Create ATM instance that may communicate with the bank upon potential successful card/account validation
    atm = ATM(ip_address=options.ip_address, port=options.port, auth_file=options.auth)

    # Get account pin if available for existing accounts associated with valid cards
    pin = None
    if (options.withdraw) or (options.deposit) or (options.get):
        if options.card and not os.path.isfile(options.card):
            parser.error('Invalid card.')
        pin = atm.get_pin(card=options.card, account=options.account)
    # Actual account validation against card for withdraw, deposit, get (balance) operations
    #if (options.withdraw) or (options.deposit) or (options.get):
    #    valid_account, msg = atm.is_valid_account(account=options.account, card=options.card)
    #    if not valid_account:
    #        parser.error(msg)

    # Prepare for communication
    query = atm.sanitize_query(options=options, pin=pin)

    #Communicate with server and post-process decrypted JSON response
    raw_response = atm.communicate_with_bank(query)
    
    if raw_response == '255':
        sys.exit(255)

    #Create new card for new account
    if raw_response != '255' and options.new:
        response = json.loads(raw_response)
        pin = response.get('pin')
        del response['pin']
        raw_response = json.dumps(response)
        created_card = atm.create_card(account=options.account, card=options.card, pin=pin)
        if not created_card:
            parser.error('Could not create card.')

    # Successful transaction, print transaction result returned from bank
    print_flush(raw_response)
    sys.exit(0)

if __name__ == "__main__":
    main()
