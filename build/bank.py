#!/usr/bin/python
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

def print_flush(S_in) :
    print S_in
    sys.stdout.flush()

def custom_round(flt):
    if abs(int(flt)-flt) < 0.001:
        return int(flt)
    return flt

def handler(signum, frame):
    sys.exit(0)

def encrypt_pin(key, pin):
    obj = AES.new(key, AES.MODE_CBC, 'iv')
    return obj.encrypt(pin)

def decrypt_pin(key, pin):
    obj = AES.new(key, AES.MODE_CBC, 'iv')
    return obj.decrypt(pin)


customers = {}
pins = {}

customers_temp = {}

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
        pin = str(randint(0,9999))

    if (request['new'] is not None) and (account_name not in customers):
        customers_temp[account_name] = custom_round(float(request['new']))
        pins[account_name] = str(pin)
        summary = json.dumps({"initial_balance": customers_temp[account_name], "account": account_name, "pin": pin})
        return summary

    elif (request['get'] is not None) and (account_name in customers) and (pin == pins.get(account_name)):
        summary = json.dumps({"account": account_name, "balance": customers_temp[account_name]})
        return summary

    elif (request['deposit'] is not None) and (account_name in customers) and (pin == pins.get(account_name)):
        customers_temp[account_name] = custom_round(round(customers[account_name] + float(request['deposit']),2))
        summary = json.dumps({"account":account_name, "deposit": custom_round(float(request['deposit']))})
        return summary

    elif (request['withdraw'] is not None) and (account_name in customers) and (float(request['withdraw']) <= customers[account_name]) \
        and (pin == pins.get(account_name)):
        customers_temp[account_name] = custom_round(round(customers[account_name] - float(request['withdraw']),2))
        summary = json.dumps({"account":account_name, "withdraw": custom_round(float(request['withdraw']))})
        return summary

    else:
        return "255"

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

class BankParser(OptionParser):
    def error(self, message=None):
        sys.exit(255)

def main():

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
	
    parser = BankParser()
    parser.add_option('-p', action = 'store', dest = 'PORT', type = 'int', default = 3000)
    parser.add_option('-s', action = 'store', dest = 'AUTH_FILE', default = 'bank.auth')
    (options, args) = parser.parse_args()

    
    for option in [options.AUTH_FILE] + args:
        if isinstance(option, str) and len(option) > 4096:
            parser.error('Argument too long for one of the options.')

    if not 1024 <= int(options.PORT) <= 65535:
        parser.error('Invalid port number: %d' % int(options.PORT))

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

                    message = message + pkt_id
                    enc_message = message_to_atm(message, options.AUTH_FILE)

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
