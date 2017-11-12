
import sys,math

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os, json, base64	
import socket
import struct

def random_bytes(count):
  b = os.urandom(count)
  print 'generated %s'%b
  return b

def encrypt_bytes(fbytes, key, iv):
  backend = default_backend()
  cipher = Cipher( algorithms.AES(key), modes.GCM(iv), backend=backend )
  encryptor = cipher.encryptor()
  ct = encryptor.update(fbytes)+encryptor.finalize()
  tag = encryptor.tag
  return (ct, tag)
		
if __name__ == '__main__':      
    
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_address = ('127.0.0.1', 65000)
    print >>sys.stderr, 'starting up on %s port %s' % server_address
    sock.bind(server_address)

    # Listen for incoming connections
    sock.listen(1)
    key = b'1234567890123456'
   
    iv = b'123456789012'
   
    while True:
        # Wait for a connection
        print >>sys.stderr, 'waiting for a connection'
        connection, client_address = sock.accept()

        try:
            print >>sys.stderr, 'connection from', client_address

	    print 'waiting for data from client'
	    data = connection.recv(1)
	    print data
	    if data == '0':
		print 'first branch'
		with open('enclave.secret.meta','rb') as f:
			raw_so = f.read()
		(ct, tag) = encrypt_bytes(raw_so, key, iv)
		print len(tag)
		print len(ct)
		print 'tag: %s'%tag
		#connection.sendall('-'*50)
		print 'ct: %s'%ct
		#connection.sendall(ct)
		length = struct.pack('<I',len(ct))
		print 'full message %s'%(length+tag+ct).encode('hex')
		connection.sendall(length+tag+ct)

	    else:
		print 'second branch'
		with open('enclave.secret.dat','rb') as f:
			raw_so = f.read()
		(ct, tag) = encrypt_bytes(raw_so, key, iv)
		print len(tag)
		print len(ct)
		print 'tag: %s'%tag.encode('hex')
		#print 'ct: %s'%ct
		length = struct.pack('<I',len(ct))
		print 'message start %s'%(length+tag).encode('hex')
		print 'first 16 bytes of ct %s'%(ct[:16]).encode('hex')
		#print 'full message %s'%(length+tag+ct).encode('hex')
		connection.sendall(length+tag+ct)
			
		
       
        finally:
            # Clean up the connection
            connection.close()

