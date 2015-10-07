import sys
from optparse import OptionParser
import os.path
import signal
import json

# Custom error code 255 for any invalid command-line options.
class BankParser(OptionParser):
	def error(self, message):
		sys.exit(255)

def main():

	parser = BankParser()

	parser.add_option('-p', action = 'store', dest = 'PORT', type = 'int', default = 3000)

	parser.add_option('-s', action = 'store', dest = 'AUTH_FILE', default = 'bank.auth')

	(options, args) = parser.parse_args()

	# Check whether authentication file exist, if not create it.	
	if os.path.isfile(options.AUTH_FILE):
		exit(255) 
	else:
		auth_file = open(options.AUTH_FILE, 'w')
		auth_file.write(os.urandom(16))		
		print "created"

if __name__ == "__main__":
	main()

# Currently this method takes a dictionary "options" and checks whether it meets the specified requirements. If so returns/prints a JSON object, otherwise return 255.

def atm_request(options):

	customers = {}

	account_name = options.account

	# Creation of new account if the given account does not exist(balance > 10 already taken care of in atm file).
	if (options.new is not None) and (account_name not in customers):
		customers[account_name] = options.new
		summary = json.dumps({"account":account_name, "initial-balance": options.new})
		print summary
		return summary
	else:
		return 255

	# Read balance if account already exist.
	if (options.get is not None) and (account_name in customers):
		summary = json.dumps({"account":account_name, "balance": customers[account_name]})
		print summary
		return summary
	else:
		return 255

	# Deposit specified amount if account already exist.
	if (options.deposit is not None) and (account_name in customers):
		customers[account_name] += options.deposit
		summary = json.dumps({"account":account_name, "deposit": customers[account_name]})
		print summary
		return summary
	else:
		return 255

	# Withdraw specified amount if account already exist.
	if (options.withdraw is not None) and (account_name in customers) and (options.withdraw <= customers[account_name]):
		customers[account_name] -= options.deposit
		summary = json.dumps({"account":account_name, "deposit": customers[account_name]})
		print summary
		return summary
	else:
		return 255
			
		
	


	
	
	
