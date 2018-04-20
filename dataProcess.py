#dataProcess.py

'''
	 # DNS Header
	    0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                      ID                       |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |QR|  opcode   |AA|TC|RD|RA|   Z    |   RCODE   |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    QDCOUNT                    |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    ANCOUNT                    |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    NSCOUNT                    |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    ARCOUNT                    |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


	 # Question 
		0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                     ...                       |
	  |                    QNAME                      |
	  |                     ...                       |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    QTYPE                      |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	  |                    QCLASS                     |
	  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

'''

from fileProcess import file
def dnsAnalyze(data,record ,debug_lv,time,no):
    #tranfer bytes to bytearray
    # QR=0?1 => query?response | opcode=0000 => query | AA=0 => query | TC=0 => query | RD=0 => query | RA=0 => query | zero=000 | rcode=0000 => No fault
    dataArray = bytearray(data)
    datalen = len(dataArray)
    ID = ( dataArray[0] <<4) + dataArray[1]
    QR = dataArray[2] & 0x80 
    OPCODE = dataArray[2] & 0x78 
    AA = dataArray[2] & 0x04 
    TC = dataArray[2] & 0x02 
    RD = dataArray[2] & 0x01 
    RA = dataArray[3] & 0x80 
    Z = dataArray[3] & 0x70 
    RCODE = dataArray[3] & 0x0F 
    
    #numbers of query and answer resources
    queryNum = ( dataArray[4] <<4) + dataArray[5]
    ansNum =  (dataArray[6] <<4) + dataArray[7]
    nsNum = ( dataArray[8] <<4) + dataArray[9]
    arNum =  (dataArray[10] <<4) + dataArray[11]

    #get the list of queried domains, and the pointer to the first byte of ans resources
    ansPtr, domain, QTYPE,CLASS,TYPE = getDomain( dataArray, queryNum)

    
    dnsFound = False
    response = ''
    
    #query: get the domain and receive the result  | QTYPE == 4 => ipv4
    if QR==0 and QTYPE ==4:
        domainsIP = list()
        dnsFound, domainsIP = record.getIPaddress( domain )
        
        #change  QR into 1
        dataArray[2] = dataArray[2] | 0x80

        if dnsFound == True:
            if '0.0.0.0' in domainsIP:
            #set the RCODE as 3: the domain name referenced in the query does not exist.
                dataArray[3] = dataArray[3] & 0xF0 #set the RCODE segment into zero
                dataArray[3] = dataArray[3] | 0x03 # then filled it as ERROR

            else:#query is for ip address
                #construct and append the answer resources into the dnspacket
                ansNum = len( domainsIP)# numbers of IP we found
                for IP in domainsIP:
                    ans = constructAns(IP,QTYPE)
                    dataArray+=ans
                    
                    #modify the number of answer's resources
                    if dataArray[7]==0xFF:
                        dataArray[6]+=1
                        dataArray[7]=0
                    else:
                        dataArray[7]+=1;

            response = bytes(dataArray)
            
    elif QR == 128 :# if QR=1 which means it is a response packet
        #check if it's correct, and add into the file if it's not exist
        if hasError(dataArray[3])==False:
            domainsIP = list()#get the IP of the ANS from the packet
            domainsIP = analyseAns(dataArray,ansPtr,ansNum)
            record.addDomain(domain, domainsIP)
            
        response = ''
        dnsFound = False


    if debug_lv == 1:
        print ('\t%.2f %d: %s' %(time,no,domain))
    if debug_lv==2:
        print ('\t%.2f %d: %s, TYPE %d, CLASS %d' %(time,no,domain,TYPE,CLASS))
        print ('\tID %d, QR %d, OPCODE %d, AA %d, TC %d, RD %d, RA%d, Z %d,RCODE %d' %(ID,QR,OPCODE,AA,TC,RD,RA,Z,RCODE))
        print ('\tQDCOUNT %d, ANCOUNT %d, NSCOUNT %d, ARCOUNT %d' %(queryNum,ansNum,nsNum,arNum))
        print ('RECV (%d bytes)' %(datalen) , data)
    
    #when ip=0.0.0.0 produce a response with alert
    return dnsFound, response


#get the IP from the ANS resources of the packet
def analyseAns( dataArray, headPtr, ansNum ):
    IPS = list()

    while ansNum>0:#get IP from each resources
        #handling the name field
        if( dataArray[headPtr]&0xC0) == 0xC0: #the domain is a pointer
            headPtr+=2; #skip 2 bytes
        else: #is a name
            while dataArray[headPtr]!= 0:
                length = dataArray[headPtr]
                headPtr += 1+length;#ptr skip the name
            headPtr+=1 #skip the len=0 segment

        #the TYPE field
        TYPE = (dataArray[headPtr]<<4)+dataArray[headPtr+1]
        headPtr+=4#skip TYPE and CLASS field
        
        headPtr += 4#skip TTL

        RDLENGTH  = (dataArray[headPtr]<<4)+dataArray[headPtr+1]
        headPtr += 2#skip RDLENGTH

        if TYPE ==1: #get an IPV4 address
            ip=''
            for i in range(4):
                ip +='.' + str(dataArray[headPtr + i])
            IPS.append(ip[1:])# add the ip address into ans
            

        headPtr += RDLENGTH     #skip the RDLENGTH
            
        ansNum-=1
    
    return IPS



def constructAns(ip, QTYPE):
    ans = bytearray()
    ans += bytearray.fromhex('C00C')#ptr to the domain name
    #ipv6 
    if QTYPE == 6 :
        ans.append(0)
        ans.append(28)
        RDLength = bytearray.fromhex('0010')
        RDATA = bytearray()
        ip = ip.split(':')
        for byte in ip:
            byte = bytearray.fromhex(byte)
            RDATA.append(byte)
    else: #ipv4 address, then the TYPE is A - 01
        ans.append(0)
        ans.append(1)
        RDLength = bytearray.fromhex('0004')
        RDATA = bytearray()
        ip = ip.split('.')
        for byte in ip:
            byte = int(byte)
            RDATA.append(byte)

    #CLASS
    ans.append(0)
    ans.append(1)

    TTL = hex(172800)
    fillLen = 10-len(TTL) #fill the len to 4 bytes ('0x' in TTL[] should drop)
    zero = '0' * fillLen
    #change TTL into bytearray
    TTL = bytearray.fromhex(zero+TTL[2:])    
        
    ans += TTL + RDLength + RDATA
    return ans


def getDomain( dataArray, queryNum):
    headPtr=12
    aDomain=''

    while queryNum>0:
        RDLength = 0
        aDomain=''
        while dataArray[headPtr]!= 0:
            aDomain += '.'
            length = dataArray[headPtr]
            aDomain += dataArray[headPtr+1: headPtr+1+length].decode()
            headPtr += 1+length;#ptr forward
            
        headPtr+=1 #skip the len=0 segment   
        aDomain = aDomain[1:]
        queryNum -= 1

    QTYPE = -1
    TYPE = (dataArray[headPtr]<<4)+dataArray[headPtr+1]
    if TYPE==1:#query type is ipv4
        QTYPE = 4
    elif TYPE == 28:#query type is ipv6
        QTYPE = 6

    headPtr += 2 #skip the query type
    CLASS = (dataArray[headPtr]<<4)+dataArray[headPtr+1]
    headPtr += 2 #skip the query class

    return headPtr, aDomain, QTYPE,CLASS,TYPE


#judge whether the query has error
def hasError(data):
    #the query has error
    #the rcode frame is not 0 => 0 = correct
    if ( data & 0x0F ) >0: 
        judge = True
    else:
        judge = False
    return judge