# ----------------------------------------------------------------------------
#  Source:    helper.py
#  Author:    Keith R. Gover
#  Date:      October 05, 2015
#  Modified:  October 07, 2015
#  File:      Python module with various helper functions
#  Remarks:   University of Maryland: Cybersecurity Capstone Project
# ----------------------------------------------------------------------------

import sys
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
