
""" SSL Fuzzer """

__version__ = "0.0.1"
__author__ = "Diego Gobbetti"


"""
notes protocols 1.2 and 1.3 :
		TLS 1.2:
			with tls 1.2 if the agreed cipher suite uses ECDHE(ellicptic curves diffie Hillman epheremal)
			like most fo the times, client and server will share ciphering keys without directly sending them, neither 
			ciphered, so the data in the messages following the handshake will be encrypted with a symmetryc encryption algorithm. The handshake process involves the following : with exchange of client_hello-server, client and server agree on a cipher suite, an elliptic curve and signing algorithm,
			server calculate a private/public key pair, based on the agreed curve. Server sends the public key, and a certificate. the certificate includes a public key that it certifies, 
			server hostname and a proof from a CA that the owner of this hostname holds the private key linked to the public key in this certificate(the proof is a firm with the CA private key of the certificate, testable with the CA public written in the certificate).
			Tipically client verifies legitimacy of the certificate recursing the CA chain.
			Since the chosen cipher suite wants ephemeral keys, the private/public key pair used is the one created from the server not the one linked to the certificate, so in public key exchange message the server adds a firm made with a signing alg from teh list of
			signing algs from teh list in client hello and the private key linked to the public key in the certificate, this is why the certificate sent from the serevr can vary depending on the accepted signs algs accepted by the client, furthermore in the certificate decision is 
			involved also the sign alg used by the CA to firm the certificate itself.
			Then, the client sends as well a public key generated the same way the server did, based on the agreed elliptic curve.
			How the private/public exchange key pair are caculated and the preMasterSecret retrieved change depending on the algorithm in the chosen cipher suite(RSA, ECDHE, DHE, ECDH, DH).
			With RSA the client calculate directly the 48 bytes premasterSecret and encrypt it with the public key of the certificate.
			Now both client and server has everything to calculate the shared encription keys, the calculation involves the following steps:
			PreMasterSecret = serverPrivatekey|clientPrivateKey * clientPublicKey|serverPublickey (scalar moltiplication accoding to the chosen ec)
			seed = "master secret" + client_random + server_random
			a0 = seed
			a1 = HMAC-SHA256(key=PreMasterSecret, data=a0)
			a2 = HMAC-SHA256(key=PreMasterSecret, data=a1)
			p1 = HMAC-SHA256(key=PreMasterSecret, data=a1 + seed)
			p2 = HMAC-SHA256(key=PreMasterSecret, data=a2 + seed)
			MasterSecret = p1[all 32 bytes] + p2[first 16 bytes]
			seed = "key expansion" + server_random + client_random
			a0 = seed
			a1 = HMAC-SHA256(key=MasterSecret, data=a0)
			a2 = HMAC-SHA256(key=MasterSecret, data=a1)
			a3 = HMAC-SHA256(key=MasterSecret, data=a2)
			a4 = ...
			p1 = HMAC-SHA256(key=MasterSecret, data=a1 + seed)
			p2 = HMAC-SHA256(key=MasterSecret, data=a2 + seed)
			p3 = HMAC-SHA256(key=MasterSecret, data=a3 + seed)
			p4 = ...
			p = p1 + p2 + p3 + p4 ...
			client write mac key = [first 20 bytes of p]
			server write mac key = [next 20 bytes of p]
			client write key = [next 16 bytes of p]
			server write key = [next 16 bytes of p]
			client write IV = [next 16 bytes of p]
			server write IV = [next 16 bytes of p]



		TLS 1.3:
			- no more session tickets
			- no more renegotiation
			- no more compression
			- no more session resumption
			- no more PSK
			- no more certificate verify
			- no more certificate status

"""
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


import socket, sys, os, ssl

import logging
import warnings
import asyncio

from scapy.all import AsyncSniffer, SuperSocket
from scapy.asn1packet import *
from scapy.asn1fields import *
from scapy.layers.x509 import *
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
			asyncio.run(self.get_supportedCipherSuites())
			self.get_supportedCurves()
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
		
		def create_sniffer(self, prn=None, stop_filter=None):
			if prn is None:
				prn = self.get_tlsInfo
			self.sniffer = AsyncSniffer(prn=prn, iface="en0", store=False, session=TCPSession, filter=f"src host {self.target}", stop_filter= (stop_filter if stop_filter else lambda x: x.haslayer(TLS)))
			# not TLSSession to fetch both tls 1.2 and 1.3, as with aead ciphers in 1.3 scapy doesn't dissects messages correctly

		def get_supportedProtocols(self):
			self.supportedProtocols, self.NotsupportedProtocols = [], []
			self.create_sniffer(prn=lambda x: self.check_protos(version=i, srv_hello=x), stop_filter=lambda x: (x.haslayer(TLS) or (x.haslayer(TCP) and (x[TCP].flags == 20 or x[TCP].flags == 11))))

			for i in range(769, 773):
				self.connect()
				ch_pk = self.craft_clientHello(version=i)
				# print(f"client_hello version {i} : \n {ch_pk.show()}")
				self.sniffer.start()
				self.send(ch_pk)
				self.sniffer.join()
			for sp in self.supportedProtocols:
					print(f"{sp} supported")
			for sp in self.NotsupportedProtocols:
					print(f"{sp} not supported")
	
	
		def check_protos(self, version, srv_hello):
			try:
				if srv_hello.haslayer(TLS):
					# print(f"response with TLS record received")
					if srv_hello[TLS].type == 22:
						print(f"srv hello received: \n {srv_hello[TLS].show()}")
						self.supportedProtocols.append(version)
					elif srv_hello[TLS].type == 21:
						if (srv_hello[TLS].msg[0].level == 2 and srv_hello[TLS].msg[0].descr == 70):
							# print(f"{version} not supported")
							# print(f"not supported version srv_hello: \n {srv_hello[TLS].show()}")
							self.NotsupportedProtocols.append(version)
					else:
						pass

					self.sock.close()
				elif(srv_hello.haslayer(TCP) and srv_hello[TCP].flags == 20):
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

		async def get_supportedCipherSuites(self):
			# self.sniffer.kwargs['stop_filter'] = lambda x: x.haslayer('TLS') or (x.haslayer('TCP') and x[TCP].flags == 20)
			# self.sniffer.kwargs['prn'] = lambda x: self.check_cipher(cipher=cipher, version=sp, srv_hello=x)
			tasks = []
			self.ciphers_info = {}
			for sp in self.supportedProtocols:
				self.ciphers_info[sp] = {"supportedCiphers": [], "notsupportedCiphers": []}
			for sp in self.ciphers_info:
				for cipher in ciphers[sp]:
					task = self.check_cipher_support(sp=sp, cipher=cipher)
					tasks.append(task)
				await asyncio.gather(*tasks)
				tasks.clear()
				time.sleep(2)
			
			for tls_version in self.ciphers_info:
				print(f"Ciphers information for TLS version {tls_version} : \n")
				for cipher in self.ciphers_info[tls_version]["supportedCiphers"]:
					print(f"cipher {cipher} supported")
				for cipher in self.ciphers_info[tls_version]["notsupportedCiphers"]:
					print(f"cipher {cipher} not supported")
				print("\n\n")
		

		async def check_cipher_support(self, sp, cipher):
			
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
				if srv_hello.haslayer(TLS):
					print(f"response with TLS record received")
					if srv_hello[TLS].type == 22:
						print(f"srv_hello received: \n {srv_hello[TLS].summary()} \n {srv_hello[TLS].show()}")
						self.ciphers_info[version]["supportedCiphers"].append(cipher)
					elif srv_hello[TLS].type == 21:
						if (srv_hello[TLS].msg[0].level == 2): # and srv_hello['TLS'].msg[0].descr == 70
							print(f"{cipher} not supported")
							# print(f"not supported cipher srv_hello: \n {srv_hello[TLS].show()}")
							self.ciphers_info[version]["notsupportedCiphers"].append(cipher)
					else:
						pass
					self.close_socket()
				
				elif(srv_hello.haslayer(TCP) and (srv_hello[TCP].flags == 20 or srv_hello[TCP].flags == 11)):
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

		async def get_supportedSignalgs(self):
			self.supportedAlgs, self.NotsupportedAlgs = [], []
			tasks = []
			
			for alg in self.sign_algs:
				task = self.check_alg_support(alg=alg)
				tasks.append(task)
				await asyncio.gather(*tasks)
				tasks.clear()

			print("\n")	
			for sa in self.supportedAlgs:
				print(f"alg {sa} supported")
			print("\n")
			for nsa in self.NotsupportedAlgs:
				print(f"alg {nsa} not supported")

		async def check_alg_support(self, alg):
			
			sock = SuperSocket(family=socket.AF_INET,type=socket.SOCK_STREAM)
			# sock.ins.bind(('127.0.0.1', sock.ins.getsockname()[1]))
			sock.ins.connect((self.targetIP, self.port))
			
			sniffer = AsyncSniffer(prn=lambda x: self.check_alg(alg=alg, srv_hello=x), iface="en0", store=False, session=TCPSession, filter=f"src host {self.target} and port {sock.ins.getsockname()[1]}", timeout=10, stop_filter=lambda x: (x.haslayer(TLS) or (x.haslayer(TCP) and (x[TCP].flags == 20 or x[TCP].flags == 11))))
			
			ch_pk = self.craft_clientHello(sign_algs=alg)
			sniffer.start()
			sock.send(bytes(ch_pk))
			sniffer.join()
			sock.close()

		def check_alg(self, srv_hello, alg):
			try:
				if srv_hello.haslayer(TLS):
					print(f"response with TLS record received")
					if srv_hello[TLS].type == 22:
						print(f"srv_hello received: \n {srv_hello[TLS].summary()}")
						self.supportedAlgs.append(alg)
					elif srv_hello[TLS].type == 21:
						if (srv_hello[TLS].msg[0].level == 2): # and srv_hello['TLS'].msg[0].descr == 70
							self.NotsupportedAlgs.append(alg)
							print(f"{alg} not supported")
							# print(f"not supported cipher srv_hello: \n {srv_hello[TLS].show()}")
					else:
						pass
					self.close_socket()
				elif(srv_hello.haslayer(TCP) and (srv_hello[TCP].flags == 20 or srv_hello[TCP].flags == 11)):
					# print("not TLS pkt received \n")
					# print(f"{srv_hello[TCP].flags}")
					# srv_hello.show()
					self.NotsupportedAlgs.append(alg)
					print(f"{alg} not supported")
					self.close_socket()
				else:
					self.close_socket()
					pass
				return None
			
			except:
				print("not expected pkg received")
				return None
			
		
		async def get_supportedCurves(self):
			self.supportedCurves, self.NotsupportedCurves = [], []
			tasks = []
			
			for curve in self.groups:
				task = self.check_curve_support(curve=curve)
				tasks.append(task)
				await asyncio.gather(*tasks)
				tasks.clear()

			print("\n")	
			for sc in self.supportedCurves:
				print(f"curve {sc} supported")
			print("\n")
			for nsc in self.NotsupportedCurves:
				print(f"curve {nsc} not supported")

		async def check_curve_support(self, curve):
			
			sock = SuperSocket(family=socket.AF_INET,type=socket.SOCK_STREAM)
			# sock.ins.bind(('127.0.0.1', sock.ins.getsockname()[1]))
			sock.ins.connect((self.targetIP, self.port))
			
			sniffer = AsyncSniffer(prn=lambda x: self.check_curve(curve=curve, srv_hello=x), iface="en0", store=False, session=TCPSession, filter=f"src host {self.target} and port {sock.ins.getsockname()[1]}", timeout=10, stop_filter=lambda x: (x.haslayer(TLS) or (x.haslayer(TCP) and (x[TCP].flags == 20 or x[TCP].flags == 11))))
			
			ch_pk = self.craft_clientHello(groups=curve)
			sniffer.start()
			sock.send(bytes(ch_pk))
			sniffer.join()
			sock.close()

		def check_curve(self, srv_hello, curve):
			try:
				if srv_hello.haslayer(TLS):
					print(f"response with TLS record received")
					if srv_hello[TLS].type == 22:
						# print(f"srv_hello received: \n {srv_hello[TLS].summary()}")
						self.supportedCurves.append(curve)
					elif srv_hello[TLS].type == 21:
						if (srv_hello[TLS].msg[0].level == 2): # and srv_hello['TLS'].msg[0].descr == 70
							self.NotsupportedCurves.append(curve)
							print(f"{curve} not supported")
							# print(f"not supported cipher srv_hello: \n {srv_hello[TLS].show()}")
					else:
						pass
					self.close_socket()
				elif(srv_hello.haslayer(TCP) and (srv_hello[TCP].flags == 20 or srv_hello[TCP].flags == 11)):
					# print("not TLS pkt received \n")
					# print(f"{srv_hello[TCP].flags}")
					# srv_hello.show()
					self.NotsupportedCurves.append(curve)
					print(f"{curve} not supported")
					self.close_socket()
				else:
					self.close_socket()
					pass
				return None
			
			except:
				print("not expected pkg received")
				return None
		
		def get_certificate(self):

			self.create_sniffer(prn=lambda x: self.fetch_certficate(x), stop_filter=lambda x: (x.haslayer(TLS) and any(isinstance(msg, TLSCertificate) for msg in x[TLS].msg)))
			ch_pk = self.craft_clientHello(version=771)
			self.connect()
			self.sniffer.start()
			self.send(bytes(ch_pk))
			self.sniffer.join()
			time.sleep(1)
			self.get_certificate_info()


		def fetch_certficate(self, srv_hello):
			try:
				if srv_hello.haslayer(TLS):
					# print(f"response with TLS record received")
					if srv_hello[TLS].type == 22:
						# print(f"srv hello received: \n {srv_hello[TLS].show()}")
						if srv_hello[TLS].msg:
							for msg in srv_hello[TLS].msg:
								if isinstance(msg, TLSCertificate):
									print(f"certificate received: \n {msg.show()} \n {msg.certs[0]}")
									self.srv_certificate = Cert(msg.certs[0][1].der)
									print(f"certificate stored: \n {self.srv_certificate.tbsCertificate}")
					elif srv_hello[TLS].type == 21:
						if (srv_hello[TLS].msg[0].level == 2 and srv_hello[TLS].msg[0].descr == 70):
							# print(f"{version} not supported")
							# print(f"not supported version srv_hello: \n {srv_hello[TLS].show()}")
							print("not proper client hello sent")
					else:
						pass

					self.sock.close()
				elif(srv_hello.haslayer(TCP) and srv_hello[TCP].flags == 20):
					# print("not TLS pkt received \n")
					# print(f"{srv_hello[TCP].flags}")
					# srv_hello.show()
					print("not proper client hello sent")
					self.sock.close()
				else:
					pass
				
				return None
	
			except:
				print("not expected pkg received")
				return None

			
		def get_certificate_info(self):
			
			pass
		


		def craft_clientHello(self, version=771, cipher=None, groups=SUPP_CV_GROUPS_test, sign_algs=SIGN_ALGS, pubkeys=None, pskkxmodes=1):
				
			try:
				ch_pk = TLS(version=version, type=22, msg=[TLSClientHello(version=(771 if version>771 else version), ciphers=(cipher if cipher else ciphers[version]), random_bytes=os.urandom(32) , ext=[ \
										TLS_Ext_ServerName(servernames=[ServerName(nametype=0, servername=self.target.encode('utf-8'))]), TLS_Ext_SupportedGroups(groups=groups if groups else self.groups), \
										TLS_Ext_SignatureAlgorithms(sig_algs=(sign_algs if sign_algs else self.sign_algs)), TLS_Ext_SupportedVersion_CH(versions=[version]), \
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
				
			pubkeys = self.generate_keys(crvs=groups)

			if not isinstance(groups, list):
				groups = [groups]

			for curve, pu_key in zip(list(groups), pubkeys):
				ch_pk[TLSClientHello].ext[8].client_shares.append(KeyShareEntry(group=curve, key_exchange=pu_key, kxlen=len((pu_key))))

			ch_pk[TLS].len = len(raw(ch_pk[TLSClientHello]))

			return ch_pk
		
		def generate_keys(self, crvs=SUPP_CV_GROUPS_test): # per ora  non salviamo chiave priv
			pubks_list =[]
			if not isinstance(crvs, list):
				crvs = [crvs]
			for curve in crvs:
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






				
