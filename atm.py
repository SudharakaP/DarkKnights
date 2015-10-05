#!/usr/bin/python

import sys
import re
from optparse import OptionParser


#####################################################################################################################
#Helper functions: These might better located in a separate module as the bank may have to do some validation as well
#####################################################################################################################

def is_valid_amount_format(amount, max_amount=4294967295.99):

    """Balances and currency amounts are specified as a number indicating a whole amount and a fractional input separated by a period.
    The fractional input is in decimal and is always two digits and thus can include a leading 0 (should match /[0-9]{2}/).
    The interpretation of the fractional amount v is that of having value equal to v/100 of a whole amount (akin to cents and dollars in US currency). 
    Command line input amounts are bounded from 0.00 to 4294967295.99 inclusively but an account may accrue any non-negative balance over multiple transactions."""

    pattern = re.compile(r'^(0|[1-9][0-9]*)(\.[0-9]{2})?$')
    if not re.match(pattern, amount) or float(amount) > max_amount:
        return False
    return True


def is_valid_account_format(account):

    """Account names are restricted to same characters as file names but they are inclusively between 1 and 250 characters of length, and "." and ".." are valid account names."""

    pattern = re.compile(r'^[_\-\.0-9a-z]{1,250}$')
    if not re.match(pattern, account):
        return False
    return True

def is_valid_filename_format(file_name):

    """File names are restricted to underscores, hyphens, dots, digits, and lowercase alphabetical characters (each character should match /[_\-\.0-9a-z]/).
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

######################
#Parse ATM CLI options
######################

class ATMOptionParser(OptionParser):

    def error(self, msg=None):
        if msg:
            sys.stderr.write(msg)
        sys.exit(255)

#############################
#Offload work to Bank server
#TODO: must agree on Protocol
#############################

class ATM:

    def __init__(self, ip_address=None, port=None, auth_file=None):
        self.ip_address = ip_address
        self.port = port
        self.auth_file = auth_file #Use this to encrypt and/or generate card file?

    def create_account(self, account, card):

        #The default value is the account name prepended to ".card" ("<account>.card"). For example, if the account name was 55555, the default card file is "55555.card".
        is card is None:
            card = "%s.card" % account

        with open(card, 'w') as f:
            try:
                f.write(account)
            except IOError:
                return False
            return True

    def is_valid_account(self, account, card):

        """FIXME: this will have to be hardened"""

        #The default value is the account name prepended to ".card" ("<account>.card"). For example, if the account name was 55555, the default card file is "55555.card".
        if card is None:
            card = "%s.card" % account

        card_info = None
        msg = None
        try:
            card_file = open(card, 'rb')
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


    def establish_secure_channel(self):
    #TODO...
        pass


    def withdraw(self, amount):
        pass

    def deposit(self, amount):
        pass

    def get_current_balance(self, amount):
        pass


def main():

    parser = ATMOptionParser()
    parser.add_option("-a", action="store", dest="account")
    parser.add_option("-n", action="store", dest="new")
    parser.add_option("-d", action="store", dest="deposit")
    parser.add_option("-w", action="store", dest="withdraw")
    parser.add_option("-g", action="store_true", dest="get")
    parser.add_option("-p", action="store", dest="port", default=3000, type="int")
    parser.add_option("-i", action="store", dest="ip_address", default="127.0.0.1", type="string")
    parser.add_option("-s", action="store", dest="auth", default="bank.auth")
    parser.add_option("-c", action="store", dest="card")

    (options, args) = parser.parse_args()
    #Check that length of string arguments is not over 4096 characters
    for option in [options.account, options.new, options.deposit, options.withdraw, options.ip_address, options.auth, options.card] + args:
        if isinstance(option, str) and len(option) > 4096:
            parser.error('Argument too long for one of the options.')

    #Check that required parameter is passed
    if not options.account:
        parser.error('"-a" is required.')

    #Check that valid account name format is provided
    if not is_valid_account_format(options.account):
        parser.error('Invalid account name: %s' % options.account)

    #Check that at one mode of operation is specified
    if (not options.new) and (not options.deposit) and (not options.withdraw) and (not options.get):
        parser.error('One mode of operation must be specified.')

    #Check that two modes of operation are not specified
    if (options.new and options.deposit) or (options.new and options.withdraw) or (options.new and options.get) \
        or (options.deposit and options.withdraw) or (options.deposit and options.get) or (options.withdraw and options.get):
         parser.error('Only one mode of operation must be specified.')

    #Check that IP address format is valid
    if not is_valid_ip_address(options.ip_address):
        parser.error('Invalid IP address: %s' % options.ip_address)

    #Check that port number format is valid (beyond default validation provided by optparse)
    if not 1024 <= int(options.port) <= 65535:
        parser.error('Invalid port number: %d' % options.port)

    #Check that potential balance format is valid
    if options.new:
        if not is_valid_amount_format(options.new) or not float(options.new) >= 10:
            parser.error('Invalid balance amount: %s' % options.new)

    #Check that potential deposit format is valid
    if options.deposit:
        if not is_valid_amount_format(options.deposit) or not float(options.deposit) >= 10:
            parser.error('Invalid deposit amount: %s' % options.deposit)

    #Check that potential withdrawal format is valid
    if options.withdraw:
        if not is_valid_amount_format(options.withdraw) or not float(options.withdraw) >= 10:
            parser.error('Invalid withdrawal amount: %s' % options.withdraw)

    #Validate the card file format
    if options.card and not is_valid_filename_format(options.card):
        parser.error('Invalid card file format: %s' % options.card)

    #Create ATM instance that will do account validation and communicate with the bank upon successful validation
    atm = ATM(ip_address=options.ip_address, port=options.port, auth_file=options.auth)

    #Create new card for a potential new account
    if options.new:
        created_account = atm.create_account(account=options.account, card=options.card)
        if not created_account:
            parser.error('Could not create account.')

    #Validate account by checking the card file (it seems that the bank does not need to know about the card file)
    valid_account, msg = atm.is_valid_account(account=options.account, card=options.card)
    if not valid_account:
        parser.error(msg)

    #TODO:
    #atm.establish_secure_channel()


if __name__ == "__main__":
    main()

