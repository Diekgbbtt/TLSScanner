
""" SSL Fuzzer """

__version__ = "0.0.1"
__author__ = "Diego Gobbetti"

"""
class that scans ssl/tls protocol of the server for vulnerabilties, 
based on version, certificate, ciphers and other common vulnerable implementations options and try some attacks.

scan can be set on different modes

	self._scan_protocol_versions()
		self._scan_compression()
		self._scan_secure_renegotiation()
		self._scan_cipher_suite_accepted()
		self._check_ocsp()
		self._check_bad_sni_response()
		self._check_heartbeat()
		self._check_session_ticket()
		self._check_hsts()

"""

"""
create socket

check reachability

connnect

Create AsyncSniffer

execute_scan



"""


import socket, sys, os, ssl

import logging
import warnings
import threading

from scapy.all import AsyncSniffer, SuperSocket
from scapy.layers.tls.all import *
from scapy.layers.tls.crypto import groups as curves
from scapy.layers.inet import * # IP, TCP

"""
from ecdsa import NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, SECP256k1
from ecdsa.keys import SigningKey
"""
TLS12_CIPHERS = [52243, 52245, 4866,4867,4865,49196,49200,159,52393,52392,52394,49195,49199,158,49188,49192,107,49187,49191,49162,49172,57,49161,49171,51,157,156,61,60,53,47,255]
TLS13_CIPHERS = [4869, 4868, 4867, 4866, 4865]
TLS10_CIPHERS = [5, 4, 10, 60, 61, 22, 51, 107, 49169, 49170, 49171, 49172]
TLS11_CIPHERS = [60, 61, 51, 107, 49169, 49171, 49172]
ciphers = {
		769: TLS10_CIPHERS,
		770: TLS11_CIPHERS,
		771: TLS12_CIPHERS,
		772: TLS13_CIPHERS
}

SUPP_CV_GROUPS = [24, 23, 22, 21, 29] # da aggiungere X25519Kyber768Draft00
SUPP_CV_GROUPS_test  = [24, 23, 29] 
SIGN_ALGS = [1027,1283,1539,2055,2053,2054,1025,1281,1537]

warnings.filterwarnings("ignore")
logging.getLogger("scapy").setLevel(logging.CRITICAL)

class TLSscanner():

		def __init__(self, target, dstport=443, sourceAddress=None, groups=SUPP_CV_GROUPS_test, sign_algs=SIGN_ALGS):
			self.target = target
			self.port = dstport
			if sourceAddress is not None:
				self.sourceAddress = sourceAddress
			else:
				self.sourceAddress = None
			self.groups = groups
			self.sign_algs = sign_algs
		
		def scan(self):
			# self.create_sniffer()
			self.get_supportedProtocols()
			self.get_supportedCipherSuites()
			self.sock.close()

		def connect(self):
			self.create_socket()
			self.getIPv4()
			if(not self.check_reach()):
				print("Connection failed")
				sys.exit(1)
			

		def create_socket(self):
			self.sock = SuperSocket(family=socket.AF_INET,type=socket.SOCK_STREAM)
			
			if self.sourceAddress is not None:
				self.sock.ins.bind(self.sourceAddress)
			
			return None
		def close_socket(self):
			if self.sock:
				self.sock.close() 
			return None
		
		def getIPv4(self):
			self.targetIP= socket.gethostbyname(self.target)
			print(self.targetIP)


		def check_reach(self):
			try:
				self.sock.ins.connect((self.targetIP, self.port))
				return True
			except socket.error as e:
				if isinstance(e, socket.timeout):
					print("Connection timed out")
				elif e.errno == socket.errno.ECONNREFUSED:
					print("Connection refused")
				elif e.errno == socket.errno.EHOSTUNREACH:
					print("Host unreachable")
				elif e.errno == socket.errno.ENETUNREACH:
					print("Network unreachable")
				elif e.errno == socket.errno.EADDRNOTAVAIL:
					print("Address not available")
				else:
					print(f"Socket error: {e}")
				return False
		
		def get_tlsInfo(self, packet):
			return None
		
		def create_sniffer(self, prn=None):
			if prn is None:
				prn = self.get_tlsInfo
			self.sniffer = AsyncSniffer(prn=prn, iface="en0", store=False, session=TCPSession, filter=f"src host {self.target}", stop_filter=lambda x: x.haslayer('TLS') or (x.haslayer('TCP') and x[TCP].flags == 20))
			# not TLSSession to fetch both tls 1.2 and 1.3, as with aead ciphers in 1.3 scapy doesn't dissects messages correctly

		def get_supportedProtocols(self):
			self.supportedProtocols, self.NotsupportedProtocols = [], []
			self.create_sniffer(prn=lambda x: self.check_protos(version=i, srv_hello=x))

			for i in range(769, 773):
				self.connect()
				self.sniffer.start()
				ch_pk = self.craft_clientHello(version=i)
				print(f"client_hello version {i} : \n {ch_pk.show()}")
				self.send(ch_pk)
				self.sniffer.join()
			for sp in self.supportedProtocols:
					print(f"{sp} supported")
			for sp in self.NotsupportedProtocols:
					print(f"{sp} not supported")
	
	
		def check_protos(self, version, srv_hello):
			try:

				if srv_hello.haslayer('TLS'):
					print(f"response with TLS record received")
					if srv_hello['TLS'].type == 22:
						print(f"srv_hello received: \n {srv_hello[TLS].summary()} \n {srv_hello[TLS].show()}")
						self.supportedProtocols.append(version)
					elif srv_hello['TLS'].type == 21:
						if (srv_hello['TLS'].msg[0].level == 2 and srv_hello['TLS'].msg[0].descr == 70):
							print(f"{version} not supported")
							print(f"not supported version srv_hello: \n {srv_hello[TLS].show()}")
							self.NotsupportedProtocols.append(version)
					else:
						pass

					self.sock.close()
				elif(srv_hello.haslayer('TCP') and srv_hello[TCP].flags == 20):
					# print("not TLS pkt received \n")
					# print(f"{srv_hello[TCP].flags}")
					# srv_hello.show()
					self.NotsupportedProtocols.append(version)
					self.sock.close()
				else:
					pass
				
				return None
	
			except:
				print("not expected pkg received")
				return None

		def get_supportedCipherSuites(self):
			# self.sniffer.kwargs['stop_filter'] = lambda x: x.haslayer('TLS') or (x.haslayer('TCP') and x[TCP].flags == 20)
			# self.sniffer.kwargs['prn'] = lambda x: self.check_cipher(cipher=cipher, version=sp, srv_hello=x)
			threads = []
			self.ciphers_info = {}
			for sp in self.supportedProtocols:
				self.ciphers_info[sp] = {"supportedCiphers": [], "notsupportedCiphers": []}
			for sp in self.ciphers_info:
				for cipher in ciphers[sp]:
					thread = threading.Thread(target=self.check_cipher_thread, args=(sp, cipher))
					threads.append(thread)
					thread.start()
					time.sleep(0.01)
					"""
					self.connect()
					self.sniffer.start()
					ch_pk = self.craft_clientHello(version=sp, cipher=cipher)
					print(f"client_hello version {sp} : \n {ch_pk.show()}")
					self.send(ch_pk)
					self.sniffer.join()
					time.sleep(3)
					"""
				time.sleep(2)

			for thread in threads:
				thread.join()
			
			for tls_version in self.ciphers_info:
				print(f"Ciphers information for TLS version {tls_version} : \n")
				for cipher in self.ciphers_info[tls_version]["supportedCiphers"]:
					print(f"cipher {cipher} supported")
				for cipher in self.ciphers_info[tls_version]["notsupportedCiphers"]:
					print(f"cipher {cipher} not supported")
				print("\n\n")
		

		def check_cipher_thread(self, sp, cipher):
			# self.connect()
			sock= SuperSocket(family=socket.AF_INET,type=socket.SOCK_STREAM)
			# sock.ins.bind(('127.0.0.1', sock.ins.getsockname()[1]))
			sock.ins.connect((self.targetIP, self.port))

			sniffer = AsyncSniffer(prn=lambda x: self.check_cipher(cipher=cipher, version=sp, srv_hello=x), iface="en0", store=False, session=TCPSession, filter=f"src host {self.target} and port {sock.ins.getsockname()[1]}", timeout=10, stop_filter=lambda x: (x.haslayer(TLS) or (x.haslayer(TCP) and (x[TCP].flags == 20 or x[TCP].flags == 11))))
			#self.create_sniffer(prn=lambda x: self.check_cipher(cipher=cipher, version=sp, srv_hello=x))
			sniffer.start()
			ch_pk = self.craft_clientHello(version=sp, cipher=cipher)
			# print(f"client_hello version {sp} : \n {ch_pk.show()}")
			# self.send(ch_pk)
			sock.send(bytes(ch_pk))
			sniffer.join()
			sock.close()


		def check_cipher(self, cipher, version, srv_hello):
			try:
				if srv_hello.haslayer('TLS'):
					print(f"response with TLS record received")
					if srv_hello['TLS'].type == 22:
						print(f"srv_hello received: \n {srv_hello[TLS].summary()} \n {srv_hello[TLS].show()}")
						self.ciphers_info[version]["supportedCiphers"].append(cipher)
					elif srv_hello['TLS'].type == 21:
						if (srv_hello['TLS'].msg[0].level == 2): # and srv_hello['TLS'].msg[0].descr == 70
							print(f"{cipher} not supported")
							print(f"not supported cipher srv_hello: \n {srv_hello[TLS].show()}")
							self.ciphers_info[version]["notsupportedCiphers"].append(cipher)
					else:
						pass
					self.close_socket()
				
				elif(srv_hello.haslayer('TCP') and srv_hello[TCP].flags == 20):
					# print("not TLS pkt received \n")
					# print(f"{srv_hello[TCP].flags}")
					# srv_hello.show()
					self.ciphers_info[version]["notsupportedCiphers"].append(cipher)
					self.close_socket()
				else:
					self.close_socket()
					pass
				return None
			
			except:
				print("not expected pkg received")
				return None

		
		def craft_clientHello(self, version=771, cipher=None, pubkeys=None, pskkxmodes=1):
				
			try:
				ch_pk = TLS(version=version, type=22, msg=[TLSClientHello(version=(771 if version>771 else version), ciphers=(cipher if cipher else ciphers[version]), random_bytes=os.urandom(32) , ext=[ \
										TLS_Ext_ServerName(servernames=[ServerName(nametype=0, servername=self.target.encode('utf-8'))]), TLS_Ext_SupportedGroups(groups=self.groups), \
										TLS_Ext_SignatureAlgorithms(sig_algs=self.sign_algs), TLS_Ext_SupportedVersion_CH(versions=[version]), \
										TLS_Ext_PSKKeyExchangeModes(kxmodes=[pskkxmodes]), TLS_Ext_SupportedPointFormat(ecpl=[0], type=11, len=2, ecpllen=1), \
										TLS_Ext_EncryptThenMAC(), TLS_Ext_ExtendedMasterSecret(), TLS_Ext_KeyShare_CH(client_shares=[])])])
			except scapy.error.PacketError as e:
				print( "Error during client hello packet creation \n Check ciphers, groups and signature algorithms used \n After that report this error to the developer \n") 
				print(f"Packet creation error: {e}")
				sys.exit(1)
			except ssl.SSLError as e:
				print( "Error during client hello packet creation \n Check ciphers, groups and signature algorithms used \n After that report this error to the developer \n") 
				print(f"SSL error: {e}")
				sys.exit(1)
			except IndexError as e:
				print( "Error during client hello packet creation \n Check ciphers, groups and signature algorithms used \n After that report this error to the developer \n") 
				print(f"Index error: {e}")
				sys.exit(1)
			except scapy.error.Scapy_Exception as e:
				print( "Error during client hello packet creation \n Check ciphers, groups and signature algorithms used \n After that report this error to the developer \n") 
				print(f"Scapy error: {e}")
				sys.exit(1)
			except Exception as e:
				print( "Error during client hello packet creation \n Check ciphers, groups and signature algorithms used \n After that report this error to the developer \n") 
				print(e)
				sys.exit(1)
				
			pubkeys = self.generate_keys()

			for curve, pu_key in zip(list(self.groups), pubkeys):
				ch_pk[TLSClientHello].ext[8].client_shares.append(KeyShareEntry(group=curve, key_exchange=pu_key, kxlen=len((pu_key))))

			ch_pk[TLS].len = len(raw(ch_pk[TLSClientHello]))

			return ch_pk
		
		def generate_keys(self): # per ora  non salviamo chiave priv
			pubks_list =[]
			for curve in self.groups:
				try:
					if(curves._tls_named_curves[curve] == "x25519"):
						pv_key = x25519.X25519PrivateKey.generate()
						pu_key = pv_key.public_key()
						pu_key_raw = pu_key.public_bytes(encoding=serialization.Encoding.Raw,
								format=serialization.PublicFormat.Raw)
					else:

						pv_key = ec.generate_private_key(ec._CURVE_TYPES[curves._tls_named_curves[curve]])
						pu_key = pv_key.public_key()
						pu_key_raw = pu_key.public_bytes(
							encoding=serialization.Encoding.X962,
							format=serialization.PublicFormat.UncompressedPoint)
				
				except Exception as e:
					print("not supported curve type \n")
					print(f"Exception: {e}")
					sys.exit(1)


				pubks_list.append(pu_key_raw)

			return pubks_list
		
		def get_curve(self, curve_name):
			curve_map = {
				"secp192r1": NIST192p,
				"secp224r1": NIST224p,
				"secp256r1": NIST256p,
				"secp384r1": NIST384p,
				"secp521r1": NIST521p,
				"secp256k1": SECP256k1,
			}
			return curve_map.get(curve_name)
		
				
		def send(self, ch):
			self.sock.send(bytes(ch))
		
			
		""" 
		def get_supportedCiphers(self):


		def scanCertificates(self):

		def scan_securityOptions(self):

			def scan_session_ticket(self):
			
			def scan_hsts(self):
			
			def scan_ocsp(self):

			def scan_compression(self):

			def scan_secure_renegotiation(self):
			
			def scan_heartbeat(self):
		
		def attack_1(self):

		def attack_2(self):



		"""


if __name__ == "__main__":
	scanner = TLSscanner(target="www.ikea.com")
	scanner.scan()






				
