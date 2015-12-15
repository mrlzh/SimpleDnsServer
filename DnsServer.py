#coding=utf-8
import socket
import time
import Queue
import threading

class DNSQuery(threading.Thread):
	SWITH=True
	LOCK = threading.Lock()
	def __init__(self,threadnum,serverhandle,workqueue,domaininfo):
		threading.Thread.__init__(self)
		self.threadname='T'+str(threadnum)
		self.serverhandle=serverhandle
		self.workqueue=workqueue
		self.domaininfo=domaininfo

	def getdomain(self,data):
		datadomain=''
		tipo = (ord(data[2]) >> 3) & 15	 # Opcode bits
		if tipo == 0:										 # Standard query
			ini=12
			lon=ord(data[ini])
			while lon != 0:
				datadomain+=data[ini+1:ini+lon+1]+'.'
				ini+=lon+1
				lon=ord(data[ini])
		return datadomain

	def run(self):
		while self.SWITH:
			try:
				data, addr=self.workqueue.get(timeout=5)
			except:
				continue
			try:
				datadomain=self.getdomain(data)
				packet=''
				if self.domaininfo.has_key(datadomain[:-1]):
					ip=self.domaininfo[datadomain[:-1]]
					packet+=data[:2] + "\x81\x80"
					packet+=data[4:6] + data[4:6] + '\x00\x00\x00\x00'
					packet+=data[12:]
					packet+='\xc0\x0c'
					packet+='\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04'
					packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.')))
					self.LOCK.acquire()
					print '[%4s] [%16s] [%20s] : [%s] -> [%s]' % (self.threadname,addr[0],time.strftime('%Y-%m-%d %X', time.localtime() ),datadomain[:-1], ip)
					self.LOCK.release()
				else:
					ip='1.1.1.1'
					packet+=data[:2] + "\x81\x80"
					packet+=data[4:6] + data[4:6] + '\x00\x00\x00\x00'
					packet+=data[12:]
					packet+='\xc0\x0c'
					packet+='\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04'
					packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.')))
					self.LOCK.acquire()
					print '[%4s] [%16s] [%20s] : [%s] -> [%s]' % (self.threadname,addr[0],time.strftime('%Y-%m-%d %X', time.localtime() ),datadomain[:-1], ip)
					self.LOCK.release()
				self.serverhandle.sendto(packet, addr)
			except:
				continue
		self.LOCK.acquire()
		print self.threadname,'over!'
		self.LOCK.release()


if __name__=='__main__':
	DOMAININFO={'aaaa.test.cn':'123.123.123.123','kkk.test.cn':'111.111.111.111'}
	THREADNUM=20
	WORKQUEUE=Queue.Queue()
	udpserver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udpserver.bind(('',53))
	print "Listening......"
	try:
		for i in range(1,THREADNUM+1):
			DNSQuery(i,udpserver,WORKQUEUE,DOMAININFO).start()
		while 1:
			data, addr = udpserver.recvfrom(1024)
			WORKQUEUE.put((data, addr))
	except:
		DNSQuery.SWITH=False
		udpserver.close()
		print '\n\nUser Requested ctrl+c! \nClosing Connections -> [OK] '