
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

			
notes certificate format :

web servers certificates are commonly X.509 certificates. 
X.509 is a standard for public key certificates, data is structured in a tree according to 
ASN1(Abstract Syntax Notation One), it defines the fields in a hierarchical way. 
Data is tipically encoded in BER(Basic Encoding Rules) or DER(Distinguished Encoding Rules), mainly DER.
DER data is then wrapped by PEM (Privacy Enhanced Mail) format, that is a base64 encoding of the DER and teh addition of a
---BEGIN CERTIFICATE--- and ---END CERTIFICATE--- header and footer.


notes certificate fields :

• Version: The version of the X.509 certificate standard (usually X.509 v3).
• Serial Number: A unique number assigned by the Certificate Authority (CA) to identify the certificate.
• Signature Algorithm: The algorithm used to sign the certificate (e.g., SHA-256 with RSA).
• Issuer: The entity that issued and signed the certificate (usually a trusted Certificate Authority).
• Validity Period:
  • Not Before: The start date and time when the certificate becomes valid.
  • Not After: The end date and time when the certificate expires.
• Subject: Information about the entity to whom the certificate is issued (often includes):
  • Common Name (CN): The domain name or hostname.
  • Organization (O): The name of the organization.
  • Organizational Unit (OU): The department or division.
  • Country (C): The country of the organization.
  • Locality (L): The city or town.
  • State or Province (ST): The state or province.
• Public Key: The public key corresponding to the private key used by the server.
• Subject Public Key Info: Information about the public key algorithm and the public key itself.
• Key Usage: Specifies the intended purpose of the public key (e.g., digital signature, key encipherment).
• Extended Key Usage: Specifies additional purposes for which the certificate’s public key can be used.
• Subject Alternative Name (SAN): Lists additional domain names, IP addresses, or email addresses.
• Basic Constraints: Indicates whether the certificate is a CA or an end-entity certificate, and path length limits.
• Certificate Policies: Describes the policies under which the certificate was issued.
• CRL Distribution Points: Lists locations where the Certificate Revocation List (CRL) can be found.
• Authority Information Access: Provides the location of the CA’s OCSP responder and/or the issuing CA certificate.
• Issuer Alternative Name: Provides alternative names for the issuer (multiple domain names or email addresses).
• Authority Key Identifier: Identifies the public key corresponding to the private key used to sign the certificate.
• Subject Key Identifier: A hash value that identifies the public key in the certificate (used for path building).
• Signature: The digital signature of the certificate generated by the CA.
• Thumbprint/Fingerprint: A hash (SHA-1 or SHA-256) of the entire certificate, used to uniquely identify it.

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

		

KNOWN COMMON TLS VULNERABILITIES:

1. POODLE (Padding Oracle On Downgraded Legacy Encryption)
Affected Protocol: SSL 3.0
Description: This vulnerability allows an attacker to perform a man-in-the-middle (MITM) attack and decrypt data transmitted between the client and server by exploiting SSL 3.0's fallback mechanism.
Mitigation: Disable SSL 3.0 and enforce the use of more secure TLS versions.
2. Heartbleed (CVE-2014-0160)
Affected Protocol: OpenSSL (TLS Heartbeat Extension)
Description: Heartbleed is a buffer over-read vulnerability that allows attackers to read sensitive information (such as private keys and session cookies) from a server's memory.
Mitigation: Update OpenSSL to a patched version (1.0.1g or later).
3. BEAST (Browser Exploit Against SSL/TLS)
Affected Protocol: TLS 1.0
Description: BEAST is a cipher-block chaining (CBC) vulnerability that enables an attacker to decrypt HTTPS requests by injecting code in a man-in-the-middle attack.
Mitigation: Upgrade to TLS 1.1 or TLS 1.2, or use a different cipher suite (such as RC4).
4. CRIME (Compression Ratio Info-leak Made Easy)
Affected Protocol: TLS (with compression enabled)
Description: CRIME exploits TLS-level data compression (DEFLATE) to leak information from encrypted connections by comparing compressed sizes.
Mitigation: Disable TLS compression.
5. BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext)
Affected Protocol: TLS (with HTTP compression)
Description: BREACH attacks the HTTP compression used over TLS to extract secrets from HTTPS responses.
Mitigation: Disable HTTP compression, use random padding, or employ techniques like separating secrets from user input.
6. FREAK (Factoring RSA Export Keys)
Affected Protocol: TLS
Description: FREAK exploits a vulnerability that forces servers to downgrade RSA keys to export-grade (weaker) encryption, allowing attackers to decrypt communications.
Mitigation: Ensure proper configuration by disabling export cipher suites.
7. Logjam
Affected Protocol: TLS (with Diffie-Hellman key exchange)
Description: Logjam exploits weaknesses in the Diffie-Hellman key exchange, allowing an attacker to downgrade the connection to use weaker, export-grade parameters.
Mitigation: Disable support for weak Diffie-Hellman groups and enforce stronger cryptographic settings.
8. DROWN (Decrypting RSA with Obsolete and Weakened eNcryption)
Affected Protocol: SSLv2 and some TLS servers
Description: DROWN allows attackers to decrypt TLS sessions by exploiting vulnerabilities in servers that still support SSLv2, even if TLS is being used for the actual session.
Mitigation: Disable SSLv2 and ensure all private keys are not shared between SSLv2 and TLS services.
9. Sweet32
Affected Protocol: TLS (with 64-bit block ciphers like 3DES)
Description: Sweet32 exploits the use of 64-bit block ciphers, allowing attackers to recover plaintext from encrypted data through a birthday attack.
Mitigation: Use modern 128-bit or higher block ciphers (such as AES).
10. ROBOT (Return Of Bleichenbacher’s Oracle Threat)
Affected Protocol: TLS (using RSA encryption)
Description: ROBOT is a vulnerability in RSA encryption used in TLS, allowing attackers to recover the plaintext of encrypted messages by sending specially crafted queries.
Mitigation: Apply software patches and disable RSA key exchange in favor of more secure alternatives like Diffie-Hellman or elliptic-curve cryptography (ECC).
11. Ticketbleed (CVE-2016-9244)
Affected Protocol: TLS (in certain implementations like F5 BIG-IP)
Description: Ticketbleed exploits session tickets in TLS, leaking up to 31 bytes of uninitialized memory, potentially exposing sensitive information.
Mitigation: Update to patched versions of affected software.
12. Raccoon Attack (CVE-2020-1968)
Affected Protocol: TLS (with Diffie-Hellman key exchange)
Description: The Raccoon attack is a timing attack on the TLS handshake process when using Diffie-Hellman key exchange, allowing attackers to recover parts of the session key.
Mitigation: Ensure that timing variations in cryptographic operations are reduced and move to safer key exchange mechanisms like elliptic-curve Diffie-Hellman (ECDHE).
13. Zombie POODLE and GOLDENDOODLE
Affected Protocol: TLS 1.2 (certain implementations)
Description: Variants of the POODLE attack that affect certain modern TLS implementations. These attacks can lead to the decryption of data.
Mitigation: Use the latest patched TLS libraries and avoid vulnerable cipher suites.
14. ALPACA (Application Layer Protocol Confusion Attack)
Affected Protocol: TLS (multi-protocol servers)
Description: ALPACA leverages cross-protocol attacks by redirecting traffic intended for one protocol (e.g., HTTPS) to another protocol (e.g., FTPS), potentially leading to session hijacking.
Mitigation: Implement strict protocol-specific validation, isolate services, and ensure SNI (Server Name Indication) is properly used.
15. TLS 1.3 Downgrade Attack
Affected Protocol: TLS 1.3
Description: Attackers can force a downgrade from TLS 1.3 to older, less secure versions like TLS 1.2, which are susceptible to attacks like BEAST or CRIME.
Mitigation: Ensure strict support for TLS 1.3 and use downgrade-resistant mechanisms like the downgrade sentinel in modern libraries.
"""


import socket, sys, os, ssl

import logging
import warnings
import asyncio

from scapy.all import AsyncSniffer, SuperSocket
from scapy.asn1packet import *
from scapy.asn1fields import *
from scapy.layers.x509 import *
from scapy.layers.tls.cert import *
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
			
			except Exception as e:
				print(f"exception during packet dissection occurred: {e}")
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
			
			except Exception as e:
				print(f"exception during packet dissection occurred: {e}")
				return None
		
		def get_certificate(self):

			self.create_sniffer(prn=lambda x: self.fetch_certficate(x), stop_filter=lambda x: x.haslayer(TLSServerHelloDone))
			ocsp_status_req = OCSPStatusRequest(respid=[], reqext=None)
			ch_pk = self.craft_clientHello(version=771, ocsp_status_req=ocsp_status_req)
			self.connect()
			self.sniffer.start()
			self.send(bytes(ch_pk))
			self.sniffer.join()
			time.sleep(5)
			self.sock.close()


		def fetch_certficate(self, srv_hello):
			try:
				if srv_hello.haslayer(TLSCertificate):
					self.srv_certificate = Cert(srv_hello[TLSCertificate].certs[0][1].der)
				if srv_hello.haslayer(TLSCertificateStatus):
					self.srv_certificate.valid_cert = srv_hello.haslayer(OCSP_GoodInfo) # (False if isinstance(srv_hello[OCSP_CertStatus].cert_status, OCSP_GoodInfo) else True)
					if self.srv_certificate.valid_cert:
						self.srv_certificate.revision_date = srv_hello[OCSP_SingleResponse].thisUpdate.datetime
					elif srv_hello.haslayer(OCSP_RevokedInfo):
						self.srv_certificate.valid_cert = False
						self.srv_certificate.valid_cert.revocation_date = srv_hello[OCSP_RevokedInfo].revocationTime
						self.srv_certificate.valid_cert.revocation_reason = srv_hello[OCSP_RevokedInfo].revocationReason
					else:
						self.srv_certificate.valid_cert = "Unknown"

				elif(srv_hello.haslayer(TCP) and srv_hello[TCP].flags == 20):
					# print("not TLS pkt received \n")
					# print(f"{srv_hello[TCP].flags}")
					# srv_hello.show()
					print("not proper client hello sent")
				else:
					pass
				
				return None
	
			except Exception as e:
				print(f"exception during packet dissection occurred: {e}")
				return None


		def check_secure_renegotiation(self):
			self.create_sniffer(prn=lambda x: self.get_session_id_sv_data(x), stop_filter=lambda x: x.haslayer(TLSServerHelloDone))
			ch_pk = self.craft_clientHello(version=771, pskkxmodes=1, renego_info=True)
			self.connect()
			self.sniffer.start()
			self.send(bytes(ch_pk))
			self.sniffer.join()
			time.sleep(5)
			self.sock.close()
			"""
			self.create_sniffer(prn=lambda x: self.is_renegotiation_secure(x), stop_filter=lambda x: x.haslayer(TLSClientHello))
			renego_pk = TLS(version=771, type=22, msg=[TLSClientHello(version=771, ciphers=ciphers[771], random_bytes=os.urandom(32), sid=self.session_id, ext=[TLS_Ext_RenegotiationInfo(renegotiated_connection=self.client_verifiy_data)])])
			self.sniffer.start()
			self.send(bytes(ch_pk))
			self.sniffer.join()
			time.sleep(1)
			self.sock.close()
			"""


		def get_session_id_sv_data(self, srv_hello):

			try:
				if srv_hello.haslayer(TLSServerHello):
						print(f"srv_hello received: \n {srv_hello[TLS].show()}")
						self.session_id = srv_hello[TLS].msg[0].sid
						print(f"session id: {self.session_id}")
				elif srv_hello.haslayer(TLSServerHelloDone):
						print(f"srv_hello_done received: \n {srv_hello[TLS].show()}")
						# print(f"client verify data: {self.client_verifiy_data}")
						"""
						client key exchange and client change cipher spec
						"""
						"""
						The verification data is built from a hash of all handshake messages and verifies the integrity of the handshake process.
						"""
						kx_pk = TLS(version=771, type=22, msg=[TLSClientKeyExchange(key_exchange=TLS_KeyExchange_RSA(rsa_pub_key=self.srv_certificate.public_key), verify_data=self.client_verifiy_data)])
						css_pk = TLS(version=771, type=22, msg=[TLSChangeCipherSpec()])
						cf_pk = TLS(version=771, type=22, msg=[TLSFinished(vdata=b'')])])
						self.send(bytes())
				elif srv_hello.haslayer(TLSAlert):
						print("not proper client hello sent")
				elif(srv_hello.haslayer(TCP) and srv_hello[TCP].flags == 20):
						print("likely not proper client hello sent - connection terminated \n")
				else:
					pass

			except Exception as e:
				print(f"exception during packet dissection occurred: {e}")
				return None

		def is_renegotiation_secure(self, srv_hello):
			pass

		# only if tls1.0/1.1 are supported
		def check_scsv_fallback(self):
			pass

		def craft_clientHello(self, version=771, cipher=None, groups=SUPP_CV_GROUPS_test, sign_algs=SIGN_ALGS, pubkeys=None, pskkxmodes=1, ocsp_status_req=None, renego_info=False):
				
			try:
				ch_pk = TLS(version=version, type=22, msg=[TLSClientHello(version=(771 if version>771 else version), ciphers=(cipher if cipher else ciphers[version]), random_bytes=os.urandom(32) , ext=[ \
										TLS_Ext_ServerName(servernames=[ServerName(nametype=0, servername=self.target.encode('utf-8'))]), TLS_Ext_SupportedGroups(groups=groups if groups else self.groups), \
										TLS_Ext_SignatureAlgorithms(sig_algs=(sign_algs if sign_algs else self.sign_algs)), TLS_Ext_SupportedVersion_CH(versions=[version]), \
										TLS_Ext_PSKKeyExchangeModes(kxmodes=[pskkxmodes]), TLS_Ext_SupportedPointFormat(ecpl=[0], type=11, len=2, ecpllen=1), \
										TLS_Ext_EncryptThenMAC(), TLS_Ext_ExtendedMasterSecret(), TLS_Ext_KeyShare_CH(client_shares=[]), \
										(TLS_Ext_CSR(req=ocsp_status_req, stype=1) if ocsp_status_req else []), (TLS_Ext_RenegotiationInfo(renegotiated_connection=b'') if renego_info else [])])])
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






				
