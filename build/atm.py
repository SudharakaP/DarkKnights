#!/usr/bin/python
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

def is_valid_amount_format(amount, max_amount=4294967295.99):
	
    pattern = re.compile(r'^(0|[1-9][0-9]*)\.\d{2}$')
    if not pattern.match(amount) or float(amount) > max_amount:
        return False
    return True

def is_valid_account_format(account):

    pattern = re.compile(r'^[_\-\.0-9a-z]{1,250}$')
    if not pattern.match(account):
        return False
    return True

def is_valid_filename_format(file_name):

    if file_name in ['.', '..']:
        return False

    pattern = re.compile(r'^[_\-\.0-9a-z]{1,255}$')
    if not pattern.match(file_name):
        return False
    return True

def is_valid_ip_address(ip_address):

    pattern = re.compile(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})')
    match = pattern.match(ip_address)
    if not match or not match.groups():
        return False
    valid_numbers = [True for group in match.groups() if 0 <= int(group) <= 255]
    if valid_numbers.count(True) != 4:
        return False
    return True

def is_valid_port_number(port_number):

    pattern = re.compile(r'^[1-9][0-9]{3,4}$')
    if not pattern.match(port_number):
        return False
    if not 1024 <= int(port_number) <= 65535:
        return False
    return True

def print_flush (S_in) :
    print S_in
    sys.stdout.flush()

class ATMOptionParser(OptionParser):
    def error(self, msg=None):
        sys.exit(255)

class ATM:

    def __init__(self, ip_address=None, port=None, auth_file=None):

        self.bank_ip_address = ip_address
        self.bank_port = int(port)
        self.auth_file = auth_file

    def create_card(self, account, card, pin):

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
            sys.exit(255)

        auth_enc = k_tmp[0:AES.block_size]
        iv = Random.new().read(AES.block_size)

        try:
            cipher = AES.new(auth_enc, AES.MODE_CFB, iv)
        except ValueError:
            sys.exit(255)
        
        enc_pin = iv + cipher.encrypt(str(pin))
        
        try:
            f.write(enc_pin)
        except IOError:
            return False
        return True

    def get_pin(self, card=None, account=None):

        if not card: 
            card = "%s.card" % account
            if not os.path.isfile(card): 
                return

        try:
            f = open(card, 'r')
        except IOError:
            sys.exit(255)

        try:
            fi = open(self.auth_file, 'r')
            k_tmp = binascii.unhexlify(fi.read())
            fi.close()
        except IOError:
            sys.exit(255)

        key_enc = k_tmp[0:AES.block_size]

        enc_pin = f.read()
        iv = enc_pin[0:AES.block_size]
	pin = enc_pin[AES.block_size:]
	f.close()        

        try:
            cipher = AES.new(key_enc, AES.MODE_CFB, iv)
        except ValueError:
            sys.exit(255)

	return cipher.decrypt(pin)

    def sanitize_query(self, options=None, pin=None):

        query = dict(zip(['account', 'new', 'deposit', 'withdraw', 'get', 'new', 'pin'], 
                        [options.account, options.new, options.deposit, options.withdraw, options.get, options.new, pin]
                        ))
        return json.dumps(query)

    def communicate_with_bank(self, p_msg):

        try:
            fi = open(self.auth_file, 'r')
            k_tmp = binascii.unhexlify(fi.read())
            fi.close()
        except IOError:
            sys.exit(255)

        key_enc = k_tmp[0:AES.block_size]
        key_mac = k_tmp[AES.block_size:]

        iv = Random.new().read(AES.block_size)

        try:
            cipher = AES.new(key_enc, AES.MODE_CFB, iv)
        except ValueError:
            sys.exit(63)

        outgoing_pkt_id = str(datetime.datetime.now())
        p_msg = p_msg + outgoing_pkt_id
        pkt_len = '%d' % len(p_msg)
        c_msg = iv + cipher.encrypt(p_msg.zfill(987) + pkt_len.zfill(5)) 

        hash = HMAC.new(key_mac)
        hash.update(c_msg)

        pkt = hash.digest() + c_msg

        try:    
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            sys.exit(63)

        sock.connect((self.bank_ip_address, self.bank_port))
        sent = sock.sendall(pkt)
        if sent is not None:
            sys.exit(63)
        
        try:
            sock.settimeout(10)
            pkt = sock.recv(1024)
            sock.settimeout(None)
        except socket.error:
            sys.exit(63)

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
                sys.exit(63)

            if compare_digest(h_tag, hash.digest()):
                p_tmp = cipher.decrypt(c_msg)
                pkt_len = p_tmp[-5:]
                incoming_pkt_id = p_tmp[-31:-5]
                p_msg = p_tmp[987-int(pkt_len):-31]
                if incoming_pkt_id == outgoing_pkt_id:
                    return p_msg
                else:
                    sys.exit(63)
            else:
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

    # Check whether option -g takes a value
    if sys.argv[-2] == "-g":
        parser.error('Cmd-line option -g takes a value')

    if len(args) > 0:
        parser.error('Additional argument error')

    for option in [options.account, options.new, options.deposit, options.withdraw, options.ip_address, options.auth, options.card] + args:
        if isinstance(option, str) and len(option) > 4096:
            parser.error('Argument too long for one of the options.')

    if not options.account:
        parser.error('"-a" is required.')

    if not is_valid_account_format(options.account):
        parser.error('Invalid account name: %s' % options.account)

    if (not options.new) and (not options.deposit) and (not options.withdraw) and (not options.get):
        parser.error('One mode of operation must be specified.')

    if (options.new and options.deposit) or (options.new and options.withdraw) or (options.new and options.get) \
        or (options.deposit and options.withdraw) or (options.deposit and options.get) or (options.withdraw and options.get):
         parser.error('Only one mode of operation must be specified.')

    if not is_valid_ip_address(options.ip_address):
        parser.error('Invalid IP address: %s' % options.ip_address)

    if not is_valid_port_number(options.port):
        parser.error('Invalid port number: %s' % options.port)

    if options.new:
        if not is_valid_amount_format(options.new) or not float(options.new) >= 10:
            parser.error('Invalid balance amount: %s' % options.new)

    if options.deposit:
        if not is_valid_amount_format(options.deposit) or not float(options.deposit) > 0:
            parser.error('Invalid deposit amount: %s' % options.deposit)

    if options.withdraw:
        if not is_valid_amount_format(options.withdraw) or not float(options.withdraw) > 0:
            parser.error('Invalid withdrawal amount: %s' % options.withdraw)

    if options.card and not is_valid_filename_format(options.card):
        parser.error('Invalid card file format: %s' % options.card)

    if options.new and options.card and os.path.isfile(options.card):
        parser.error('Card already exists: %s' % options.card)


    atm = ATM(ip_address=options.ip_address, port=options.port, auth_file=options.auth)

    pin = None
    if (options.withdraw) or (options.deposit) or (options.get):
        if options.card and not os.path.isfile(options.card):
            parser.error('Invalid card.')
        pin = atm.get_pin(card=options.card, account=options.account)

    query = atm.sanitize_query(options=options, pin=pin)

    raw_response = atm.communicate_with_bank(query)
    
    if raw_response == '255':
        sys.exit(255)

    if raw_response != '255' and options.new:
        response = json.loads(raw_response)
        pin = response.get('pin')
        del response['pin']
        raw_response = json.dumps(response)
        created_card = atm.create_card(account=options.account, card=options.card, pin=pin)
        if not created_card:
            parser.error('Could not create card.')

    print_flush(raw_response)
    sys.exit(0)

if __name__ == "__main__":
    main()
