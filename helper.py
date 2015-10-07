# ----------------------------------------------------------------------------
#  Source:    helper.py
#  Author:    Keith R. Gover
#  Date:      October 05, 2015
#  Modified:  October 07, 2015
#  File:      Python module with various helper functions
#  Remarks:   University of Maryland: Cybersecurity Capstone Project
# ----------------------------------------------------------------------------
import sys

# ----------------------------------------------------------------------------
#  This function appends a carriage return to the end of the input string,
#  prints the string plus carriage return and then flushes the I/O buffer.
#  This is a project requirement.
# ----------------------------------------------------------------------------
def print_flush (S_in) :
    print S_in + '\n'
    sys.stdout.flush()
