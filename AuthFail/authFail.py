import urllib2
import socket
import sys
import re

# Keyword in auth.log for invalid login
authFail = "Failed password for invalid user"

# Regex of ip address
ipRegEx = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"

# Website that provide api
apiHostIp = "http://api.hostip.info/get_html.php?ip="

# Dictionary and List initializer
dictBase = {}
listAtt = []

# Ssh port
SSHPORT = 22

# Usage
help = """
   AuthFail by Simone Aonzo
========================================
        Usage:
                python authfail.py FILE [FILE]

	Parse an auth.log file (specified as first parameter)
	
	stats about ip addresses that cause a sshd's auth failure
	
	This software is released under GPLv3 license.
"""

# Check if input string match the regexp
def ipFormatChk (ipStr):
   if re.match(ipRegEx, ipStr):
      return True
   else:
      return False

# Convert a list of tuple into a string
def fromRegexToString (line):
	return (" ".join( re.findall(ipRegEx,line)[0] )).replace(" ",".")

# Check if ip:port is open
def isOpen(ip,port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect( (ip, int(port)) )
		s.shutdown(2)
		return True
	except:
		return False

# Class with data of the attacker
class Attacker(object):
	def __init__(self, ip, hits, isopenssh, country, city):
		self.ip = ip
		self.hits = hits
		self.isopenssh = isopenssh
		self.country = country
		self.city = city


#======================================================================#

if __name__ == "__main__":

	alen = len(sys.argv)
	 
	if (alen < 2) or (alen > 3):
		print help
		quit()
		
	if (alen == 3):
		try:
			fileOUT = open (sys.argv[2], 'w')
		except:
			fileOUT = None
			print "Error! I can't write this file -> " + sys.argv[2]
	else:
		fileOUT = None

	try:
		fileIN = open(sys.argv[1], "r")
	except:
		fileIN = None
		print "Error! I can't read this file -> " + sys.argv[1]
		print "If I can't read auth.log why did you invoke me?!?!"
		sys.exit(1)
		
	line = fileIN.readline()

	# Read each line of the file
	# if found an ip it search the dictionary for the entry
	# if it's present, increment the counter
	# otherwise add the ip and initialize the counter
	while line:
		if (line.find(authFail) != -1):
			ipFound = fromRegexToString (line)
			if ( ipFound in dictBase):
				dictBase[ipFound] = dictBase.get(ipFound)+1
			else :
				dictBase[ipFound] = 1	
		line = fileIN.readline()
		
	# Close the input file
	fileIN.close()

	# Create the classes and add them to the list
	for ip, hits in dictBase.iteritems():
		resp = urllib2.urlopen( apiHostIp+ip ).read()
		country = resp [ resp.find('Country: ') : resp.find('\n') ]
		city = resp [ resp.find('City: ') : resp.find('\n',resp.find('City: ')) ]
		#sshopen = isOpen(ip, SSHPORT)
		sshopen = True
		if ( (sshopen is True) and (fileOUT != None) ):
			fileOUT.write(ip+"\n")
		listAtt.append( Attacker(ip, hits, sshopen, country, city) ) 

	# Free the dictionary
	dictBase.clear()

	# Close the output file
	if (fileOUT != None):
		fileOUT.close()

	# Redefines the sort function with the total order relation
	# for confront two Attacker classes
	listAtt.sort(lambda x, y: cmp(y.hits, x.hits))

	for a in listAtt:
		print "\nIp: "+ a.ip + "\nHits: %d"% a.hits + "\nPort %s open: "%SSHPORT + str(a.isopenssh) + "\n" +	a.country + "\n" + a.city
	
