#dnsrelay.py

import socket
import sys,getopt
import time

from dataProcess import dnsAnalyze

from network import *
from fileProcess import file

#handle the argv parameter
def argProcess():
	path = "dnsrelay.txt"
	send.start_time = time.clock()
	try:
		option,args = getopt.getopt(sys.argv[1:],"d::")
		for opt,val in option:
			if opt == "-d":
				#debug_level=2
				#arguments in the format -dd dns
				if val == "d":
					if len(args) != 1:
						#invalid arguments
						print("Invalid arguments")
						sys.exit()
					send.dnsServer = args[0]
					print("Set dnsServer as:",args[0])
					send.debug_level = 2
				else:#arguments in the format -d dns path
					if len(args) != 1:#invalid arguments
						print("Invalid arguments")
						sys.exit()
					print("Set dnsServer and path as:",val,args[0])
					send.dnsServer = val
					path = args[0]
					send.debug_level = 1
			else:
				print("Invalid arguments")
				sys.exit()
	except:
		print("Input arguments is not accept")
		sys.exit()

	print("*-----------------------------------*")
	print("Debug_level:",send.debug_level)
	print("Running dnsServer...")
	return path


def main():
	#Initialize the domain and ip address data
	record = file(argProcess())
	#Bind the ip and port
	recv.s.bind(recv.address)
	print("Connected")

	while True:
		#receive data from port 53
		try:
			data,address = recv.s.recvfrom(1024)
		except:
			continue

		#analyze the data received
		dnsFound, response = dnsAnalyze(data,record,send.debug_level,get_time(),send.no)
		send.no += 1

		#if found in the file, then return it
		#else send it to the dns server
		if dnsFound:
			recv.s.sendto(response,address)
		else:
			dnsQuery(data,address,record)

if __name__ == "__main__":
	main()