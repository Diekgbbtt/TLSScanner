
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

from scapy.all import AsyncSniffer, SuperSocket
from scapy.layers.tls.all import *
from scapy.layers.tls.crypto import groups as curves
from scapy.layers.inet import * # IP, TCP

"""
from ecdsa import NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, SECP256k1
from ecdsa.keys import SigningKey
"""

TLS12_CIPHERS = [4866,4867,4865,49196,49200,159,52393,52392,52394,49195,49199,158,49188,49192,107,49187,49191,103,49162,49172,57,49161,49171,51,157,156,61,60,53,47,255]
TLS13_CIPHERS = [4869, 4868, 4867, 4866, 4865]
TLS10_CIPHERS = TLS12_CIPHERS
TLS11_CIPHERS = TLS12_CIPHERS
SUPP_CV_GROUPS = [24, 23, 22, 21, 29] # da aggiungere X25519Kyber768Draft00
SUPP_CV_GROUPS_test  = [24, 23, 29] 
SIGN_ALGS = [1027,1283,1539,2055,2053,2054,1025,1281,1537]



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
			self.connect()
			self.create_sniffer()
			self.get_supportedProtocols()
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

		def getIPv4(self):
			self.targetIP= socket.gethostbyname(self.target)
			print(f"targetIP: {self.targetIP}")



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
			self.sniffer = AsyncSniffer(prn=prn, iface="en0", store=False, filter=f"src host {self.targetIP}")
			self.sniffer
			# not TLSSession to fetch both tls 1.2 and 1.3, as with aead ciphers in 1.3 scapy doesn't dissects messages correctly

		def get_supportedProtocols(self):
			self.supportedProtocols, self.NotsupportedProtocols = [], []
			self.create_sniffer(prn=self.check_protos)
			self.sniffer.start()
			for i in range(769, 773):
				ch_pk = self.craft_clientHello(version=i)
				self.send(ch_pk)
				time.sleep(3)
			self.sniffer.stop()
		
		def check_protos(self, srv_hello):
			try:

				if srv_hello.haslayer('TLS'):
					print(f"srv_hello: {srv_hello[TLS].show()}")
					if srv_hello['TLS'].type == 22:
						print(f"srv_hello: {srv_hello[TLS].show()}")
						self.supportedProtocols.append(srv_hello['TLS'].version)
					elif srv_hello['TLS'].type == 21:
						if srv_hello['TLS'].msg[0].level == 2:
							print(f"{srv_hello[TLS].version} not supported")
							self.NotsupportedProtocols.append(srv_hello['TLS'].version)
					else:
						pass
					self.sock.close()
					self.connect()
			
			except:
				print("not expected pkg received")
			"""
			for v in self.supportedProtocols:
				print(f"Supported protocol: {v} \n")
			for v in self.NotsupportedProtocols:
				print(f"Not supported protocol: {v} \n")
			"""
	
		def craft_clientHello(self, version=771, ciphers=TLS12_CIPHERS, pubkeys=None, pskkxmodes=1):
			
			if version != 771:
				if version == 769:
					ciphers = TLS10_CIPHERS
				elif version == 770:
					ciphers = TLS11_CIPHERS
				elif version == 772:
					ciphers = TLS13_CIPHERS
				
			try:
				ch_pk = TLS(version=769, type=22, msg=[TLSClientHello(version=771, ciphers=ciphers, random_bytes=os.urandom(32) , ext=[ \
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
	scanner = TLSscanner(target="www.target.com")
	scanner.scan()






				
