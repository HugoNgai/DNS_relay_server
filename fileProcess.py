#fileProcess.py

import sys

class file:
	ipDict = dict()

	def __init__(self,path):
		self.path = path
		f = open(self.path,'r')
		for line in f:
			if not line.isspace():
				s = line.split()
				if s[1] in self.ipDict:
					self.ipDict[s[1]].append(s[0])
				else:
					self.ipDict[s[1]] = [s[0]]

		f.close()
		return 

	def getIPaddress(self,domain):
		try:
			return True,self.ipDict[domain]
		except:
			print(sys.exc_info())
			return False,[]


	def addDomain(self,domain,Ipaddress):
		f = open(self.path,'a')
		for ip in Ipaddress:
			f.write(ip + ' ' + domain +'\n')
			if domain in file.ipDict:
				self.ipDict[domain].append(ip)
			else:
				self.ipDict[domain] = [ip]
		f.close()
		return

