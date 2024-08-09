
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



def get_ciphers_for_version(protocol):
    context = ssl.SSLContext(protocol)
    return [int(cipher['id'], 16) for cipher in context.get_ciphers()]

TLS10_CIPHERS = get_ciphers_for_version(ssl.PROTOCOL_TLSv1)
TLS11_CIPHERS = get_ciphers_for_version(ssl.PROTOCOL_TLSv1_1)
TLS12_CIPHERS = get_ciphers_for_version(ssl.PROTOCOL_TLSv1_2)
TLS13_CIPHERS = get_ciphers_for_version(ssl.PROTOCOL_TLSv1_3)

SUPP_CV_GROUPS = [24, 23, 22, 21, 29] # da aggiungere X25519Kyber768Draft00
SIGN_ALGS = [1027,1283,1539,2055,2053,2054,1025,1281,1537]


ssl.SUPPORTED_GROUPS




class TLSscanner():

		def __init__(self, target, dstport=443, sourceAddress=None, groups=SUPP_CV_GROUPS, sign_algs=SIGN_ALGS):
			self.target = target
			self.port = dstport
			if sourceAddress is not None:
				self.sourceAddress = sourceAddress
			self.groups = groups
			self.sign_algs = sign_algs
		


		def send(self, ch):
			self.sock.send(bytes(ch))

		

		def create_socket(self):
			self.sock = SuperSocket(family=socket.AF_INET,type=socket.SOCK_STREAM)
			
			if self.sourceAddress is not None:
				self.sock.ins.bind(self.sourceAddress)
			
			return None
		

		def getIPv4(self):
			self.targetIP= self.sock.ins.gethostbyname(self.target)
		

		def check_reach(self):
			
			try:
				self.sock.connect((self.targetIP, self.port))
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

		def connect(self):
			self.create_socket()
			self.getIPv4()
			if(self.check_reach()):
				self.sock.connect((self.targetIP, self.port))
			else: 
				print("Connection failed")
				sys.exit(1)

		def create_sniffer(self):
			self.sniffer = AsyncSniffer(prn=self.get_tlsInfo, session=TLSSession, iface="en0", store=False, filter=f"src host {self.targetIP}")
			

		def craft_clientHello(self, version=771, ciphers=TLS12_CIPHERS, pubkeys=None, pskkxmodes=1):
			
			if version != 771:
				if version == 769:
					ciphers = TLS10_CIPHERS
				elif version == 770:
					ciphers = TLS11_CIPHERS
				elif version == 772:
					ciphers = TLS13_CIPHERS
				
			try:
				ch_pk = TLS(version=769, type=22, msg=[TLSClientHello(version=version, ciphers=ciphers, random_bytes=os.urandom(32) , ext=[ \
										TLS_Ext_ServerName(servernames=[ServerName(nametype=0, servername=self.target.encode('utf-8'))]), TLS_Ext_SupportedGroups(groups=self.groups), \
										TLS_Ext_SignatureAlgorithms(sig_algs=self.sign_algs), TLS_Ext_SupportedVersion_CH(versions=[version]), \
										TLS_Ext_PSKKeyExchangeModes(kxmodes=[pskkxmodes]), TLS_Ext_SupportedPointFormat(ecpl=[0], type=11, len=2, ecpllen=1), \
										TLS_Ext_KeyShare_CH(client_shares=[])])])
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
				ch_pk[TLSClientHello].ext[6].client_shares.append(KeyShareEntry(group=curve, key_exchange=pu_key, kxlen=len((pu_key))))

			ch_pk[TLS].len = len(raw(ch_pk[TLSClientHello]))

			return ch_pk
		
		def generate_keys(self): # per ora  non salviamo chiave priv
			pubks_list =[]
			for curve in self.groups:
					try:
						if(curves._tls_named_curves[curve] == "x25519"):
							pv_key = x25519.X25519PrivateKey.generate()
							pu_key = pv_key.public_key()
						else:
							pv_key = ec.generate_private_key(ec._CURVE_TYPES[curves._tls_named_curves[curve]])
							pu_key = pv_key.public_key()
					except:
						print("not supported curve type")
						sys.exit(1)

					pu_key_raw = pu_key.public_bytes(encoding=serialization.Encoding.Raw,
							format=serialization.PublicFormat.Raw)

					pubks_list.append(pu_key_raw)

			return pubks_list

			


		def scan(self):
			self.connect()
			self.create_sniffer()
			self.sniffer.start()
			self.get_supportedProtocols()


			self.sniffer.stop()
			self.sniffer.close()
			self.sock.close()





		def get_supportedProtocols(self):
			self.sniffer.prn = self.check_protos
			for i in range(769, 773):
				ch_pk = self.craft_clientHello(version=i)
				self.send(ch_pk)
				time.sleep(1)

		def check_protos(self, srv_hello):
			try:
				if srv_hello.haslayer('TLS'):
					if srv_hello['TLS'].type == 22:
						self.supportedProtocols.append(srv_hello['TLS'].version)
					elif srv_hello['TLS'].type == 21:
						if srv_hello['TLS'].msg[0].alert_level == 2:
							self.NotsupportedProtocols.append(srv_hello['TLS'].version)
			
			
			except:
				print("not expected pkg received")


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

		



		

		def get_tlsInfo(packet):





					

		def recvall(sock):






				
