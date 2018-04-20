#network.py

import threading
import socket
import time 

from dataProcess import dnsAnalyze

class send:
	dnsServer = "10.3.9.5"
	debug_level = 0
	no = 0
	start_time =0

def get_time():
	return round(time.clock() - send.start_time,3)

class recv(object):
	address = ('',53)
	s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

lock = threading.Lock()

def waitResp(data,address,record):
	udpSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	global lock
	if lock.acquire():
		udpSocket.sendto(data,(send.dnsServer,53))
		noResp = True
		while noResp:
			try:
				recvData, recvAddr = udpSocket.recvfrom(2048)
				noResp = False
			except:
				Print("No response")
	#send data to analyze
	dnsAnalyze(recvData,record,send.debug_level,get_time(),send.no)
	send.no += 1
	lock.release()
	#send response to client
	recv.s.sendto(recvData,address)


#build thread and send request to server and wait for response
def dnsQuery(data,address,record):
	thd = threading.Thread(target = waitResp, args = (data,address,record))
	thd.start()