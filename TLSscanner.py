
""" SSL Fuzzer """

__version__ = "0.0.1"
__author__ = "Diego Gobbetti"

import socket, sys, os, ssl

import logging
import warnings
import asyncio
import binascii

from OpenSSL import SSL

from progress.bar import IncrementalBar

from scapy.all import AsyncSniffer, SuperSocket, sniff
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
TLS13_CIPHERS = [4869, 4868, 4867, 4866, 4865]
TLS12_CIPHERS = [52243, 52245, 4866,4867,4865,49196,49200,159,52393,52392,52394,49195,49199,158,49188,49192,107,49187,49191,49162,49172,57,49161,49171,51,157,156,61,60,53,47,255]
TLS11_CIPHERS = [60, 61, 51, 107, 49169, 49171, 49172]
TLS10_CIPHERS = [5, 4, 10, 60, 61, 22, 51, 107, 49169, 49170, 49171, 49172]
SSL30_CIPHERS = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
    42, 43, 44, 45, 67, 68, 69, 70, 71, 72, 77, 132, 133, 134, 135, 136, 137, 138,
    139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150
]
ciphers = {
		768: SSL30_CIPHERS,
		769: TLS10_CIPHERS,
		770: TLS11_CIPHERS,
		771: TLS12_CIPHERS,
		772: TLS13_CIPHERS
}

SUPP_CV_GROUPS = [24, 23, 29] # da aggiungere X25519Kyber768Draft00
SIGN_ALGS = [1027,1283,1539,2055,2053,2054,1025,1281,1537]


warnings.filterwarnings("ignore")
logging.getLogger("scapy").setLevel(logging.CRITICAL)

class TLSscanner():

		def __init__(self, target, **kwargs):
			self.target = target
			self.port = kwargs.get('dstport', 443)
			self.local = False if self.port == 443 else True
			self.sourceAddress = kwargs.get('sourceAddress') 
			self.groups = kwargs.get('groups', SUPP_CV_GROUPS)
			self.sign_algs = kwargs.get('sign_algs', SIGN_ALGS)
		
		def scan(self):
			# self.create_sniffer()
			self.get_supportedProtocols()
			asyncio.run(self.get_supportedCipherSuites())
			asyncio.run(self.get_supportedCurves())
			asyncio.run(self.get_supportedSignalgs())
			self.get_certificate()
			self.get_certificate_chain()
			with IncrementalBar(message="Scanning for know attacks", suffix='%(index)d/%(max)d [%(elapsed)d / %(eta)d / %(eta_td)s]', color='green', max=5) as bar:
				self.check_secure_renegotiation()
				bar.next()
				self.check_scsv_fallback()
				bar.next()
				self.check_heartbleed()
				bar.next()
				self.check_ccsinjection()
				bar.next()
				self.check_crime()
				bar.next()

		def connect(self, ssl_context=None):
			
			if ssl_context:
				self.sock = socket.socket(family=socket.AF_INET,type=socket.SOCK_STREAM)
				self.ssl_sock = SSL.Connection(ssl_context, self.sock)
				self.getIPv4()
				self.ssl_sock.connect((self.target, self.port))
			else:
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
				self.sock = None
			return None
		
		def getIPv4(self):
			self.targetIP= socket.gethostbyname(self.target)
			# print(self.targetIP)


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
		
		def create_sniffer(self, prn=None, stop_filter=None, pk_fitler=None):
			if prn is None:
				prn = self.get_tlsInfo
			self.sniffer = AsyncSniffer(prn=prn, iface="en0", store=False, session=TCPSession, filter=(pk_fitler if pk_fitler else f"src host {self.target}"), timeout=10, stop_filter= (stop_filter if stop_filter else lambda x: x.haslayer(TLS)))
			# not TLSSession to fetch both tls 1.2 and 1.3, as with aead ciphers in 1.3 scapy doesn't dissects messages correctly

		# get all supported versions of tls/ssl
		# based on supported versions, some vulneabilities are deduced 
		def get_supportedProtocols(self):
			
			self.supportedProtocols =[]
			self.create_sniffer(prn=lambda x: self.check_protos(version=i, srv_hello=x), stop_filter=lambda x: (x.haslayer(TLSServerHello) or x.haslayer(TLSAlert) or (x.haslayer(TCP) and (x[TCP].flags == 20 or x[TCP].flags == 11))))
			with IncrementalBar(message=rf"Scanning supported versions", suffix='%(index)d/%(max)d [%(elapsed)d / %(eta)d / %(eta_td)s]', color='green', max=5) as bar:
				for i in range(768, 773):
					self.connect()
					ch_pk = self.craft_clientHello(version=i)
					# print(f"client_hello version {i} : \n {ch_pk.show()}")
					self.sniffer.start()
					self.send(ch_pk)
					self.sniffer.join()
					bar.next()
			
			"""		
			for sp in self.supportedProtocols:
				print(f"supported version {sp}")
			"""
			
	
	
		def check_protos(self, version, srv_hello):
			try:
				if srv_hello.haslayer(TLSServerHello):
					# print(f"supported version {version}")
					self.supportedProtocols.append(version)
					self.close_socket()
				elif srv_hello.haslayer(TLSAlert):
					if srv_hello[TLSAlert].descr == 70 or srv_hello[TLSAlert].descr == 0:
						self.close_socket()
				
				elif(srv_hello.haslayer(TCP) and (srv_hello[TCP].flags == 20 or srv_hello[TCP].flags == 11)):
					# print("not TLS pkt received \n")
					# print(f"{srv_hello[TCP].flags}")
					# srv_hello.show()
					self.close_socket()
				
				else:
					pass
	
			except:
				print("not expected pkg received")

		async def get_supportedCipherSuites(self):
			# self.sniffer.kwargs['stop_filter'] = lambda x: x.haslayer('TLS') or (x.haslayer('TCP') and x[TCP].flags == 20)
			# self.sniffer.kwargs['prn'] = lambda x: self.check_cipher(cipher=cipher, version=sp, srv_hello=x)
			tasks = []
			self.ciphers_info = {}
			for sp in self.supportedProtocols:
				self.ciphers_info[sp] = {"supportedCiphers": [], "notsupportedCiphers": []}
			with IncrementalBar(message=rf"Checking supported ciphers", suffix='%(index)d/%(max)d [%(elapsed)d / %(eta)d / %(eta_td)s]', color='green', max=sum(len(ciphers[sp]) for sp in self.supportedProtocols)+len(self.supportedProtocols)) as bar:
				for sp in self.ciphers_info:
					for cipher in ciphers[sp]:
						task = self.check_cipher_support(sp=sp, cipher=cipher)
						tasks.append(task)
						bar.next()
					await asyncio.gather(*tasks)
					tasks.clear()
					bar.next()
					time.sleep(0.2)
			"""
			for tls_version in self.ciphers_info:
				print(f"Ciphers information for TLS version {tls_version} : \n")
				for cipher in self.ciphers_info[tls_version]["supportedCiphers"]:
					print(f"cipher {cipher} supported")
				for cipher in self.ciphers_info[tls_version]["notsupportedCiphers"]:
					print(f"cipher {cipher} not supported")
				print("\n\n")
			"""
		

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
					# print(f"response with TLS record received")
					if srv_hello[TLS].type == 22:
						# print(f"srv_hello received: \n {srv_hello[TLS].summary()} \n {srv_hello[TLS].show()}")
						self.ciphers_info[version]["supportedCiphers"].append(srv_hello[TLSServerHello].cipher)
					elif srv_hello[TLS].type == 21:
						if (srv_hello[TLS].msg[0].level == 2): # and srv_hello['TLS'].msg[0].descr == 70
							# print(f"{cipher} not supported")
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
			with IncrementalBar(message=rf"Checking supported algs", suffix='%(index)d/%(max)d [%(elapsed)d / %(eta)d / %(eta_td)s]', color='green', max=(len(self.sign_algs))) as bar:
				for alg in self.sign_algs:
					task = self.check_alg_support(alg=alg)
					tasks.append(task)
					await asyncio.gather(*tasks)
					tasks.clear()
					bar.next()
			"""
			print("\n")	
			for sa in self.supportedAlgs:
				print(f"alg {sa} supported")
			print("\n")
			for nsa in self.NotsupportedAlgs:
				print(f"alg {nsa} not supported")
			"""

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
					# print(f"response with TLS record received")
					if srv_hello[TLS].type == 22:
						# print(f"srv_hello received: \n {srv_hello[TLS].summary()}")
						self.supportedAlgs.append(alg)
					elif srv_hello[TLS].type == 21:
						if (srv_hello[TLS].msg[0].level == 2): # and srv_hello['TLS'].msg[0].descr == 70
							self.NotsupportedAlgs.append(alg)
							# print(f"{alg} not supported")
							# print(f"not supported cipher srv_hello: \n {srv_hello[TLS].show()}")
					else:
						pass
					self.close_socket()
				elif(srv_hello.haslayer(TCP) and (srv_hello[TCP].flags == 20 or srv_hello[TCP].flags == 11)):
					# print("not TLS pkt received \n")
					# print(f"{srv_hello[TCP].flags}")
					# srv_hello.show()
					self.NotsupportedAlgs.append(alg)
					# print(f"{alg} not supported")
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
			with IncrementalBar(message=rf"Checking supported curves", suffix='%(index)d/%(max)d [%(elapsed)d / %(eta)d / %(eta_td)s]', color='green', max=len(self.groups)) as bar:
				for curve in self.groups:
					task = self.check_curve_support(curve=curve)
					tasks.append(task)
					await asyncio.gather(*tasks)
					tasks.clear()
					bar.next()
			"""
			print("\n")	
			for sc in self.supportedCurves:
				print(f"curve {sc} supported")
			print("\n")
			for nsc in self.NotsupportedCurves:
				print(f"curve {nsc} not supported")
			"""

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
					# print(f"response with TLS record received")
					if srv_hello[TLS].type == 22:
						# print(f"srv_hello received: \n {srv_hello[TLS].summary()}")
						self.supportedCurves.append(curve)
					elif srv_hello[TLS].type == 21:
						if (srv_hello[TLS].msg[0].level == 2): # and srv_hello['TLS'].msg[0].descr == 70
							self.NotsupportedCurves.append(curve)
							# print(f"{curve} not supported")
							# print(f"not supported cipher srv_hello: \n {srv_hello[TLS].show()}")
					else:
						pass
					self.close_socket()
				elif(srv_hello.haslayer(TCP) and (srv_hello[TCP].flags == 20 or srv_hello[TCP].flags == 11)):
					# print("not TLS pkt received \n")
					# print(f"{srv_hello[TCP].flags}")
					# srv_hello.show()
					self.NotsupportedCurves.append(curve)
					# print(f"{curve} not supported")
					self.close_socket()
				else:
					self.close_socket()
					pass
				return None
			
			except Exception as e:
				print(f"exception during packet dissection occurred: {e}")
				return None
		
		def get_certificate(self):

			self.create_sniffer(prn=lambda x: self.fetch_certficate_details(x), stop_filter=lambda x: x.haslayer(TLSServerHelloDone))
			ocsp_status_req = OCSPStatusRequest(respid=[], reqext=None)
			ch_pk = self.craft_clientHello(version=771, ocsp_status_req=ocsp_status_req)
			self.connect()
			self.sniffer.start()
			self.send(bytes(ch_pk))
			self.sniffer.join()
			self.sock.close()


		def fetch_certficate_details(self, srv_hello):
			try:
				if srv_hello.haslayer(TLSCertificate):
					self.srv_certificate = Cert(srv_hello[TLSCertificate].certs[0][1].der)
					self.srv_certificate.der = srv_hello[TLSCertificate].certs[0][1].der
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
		
		def get_certificate_chain(self):

			context = SSL.Context(SSL.TLSv1_2_METHOD)  # Use TLSv1.2 for security
			context.set_verify(SSL.VERIFY_NONE, lambda *args: True)

			self.connect(ssl_context=context)

			self.ssl_handshake()

			self.ssl_sock.get_cipher_name()

			cert_list = self.ssl_sock.get_peer_cert_chain()

			if cert_list:
				with IncrementalBar(message=rf"Scanning certificate chain", suffix='%(index)d/%(max)d [%(elapsed)d / %(eta)d / %(eta_td)s]', color='green', max=len(cert_list)) as bar:
					for i in range (1, len(cert_list)):
						self.analyze_certificates(child_cert=cert_list[i-1], parent_cert=cert_list[i], leaf=(True if i==1 else False))
						bar.next()
					bar.next()
				

		def analyze_certificates(self, child_cert, parent_cert, leaf=False):
			
			self.CA_certificate = Cert(parent_cert.to_cryptography().public_bytes(encoding=serialization.Encoding.DER))
			# fetch target certificate details

			if leaf:
				if hasattr(self, 'srv_certificate'):
					self.srv_certificate.is_subject_same_as_issuer = child_cert.get_issuer().CN == parent_cert.get_subject().CN
					self.srv_certificate.is_expired = child_cert.has_expired()
					self.srv_certificate.correct_subject = self.target in child_cert.get_subject().commonName
				else:
					self.srv_certificate = Cert(child_cert.to_cryptography().public_bytes(encoding=serialization.Encoding.DER))
					self.srv_certificate.is_subject_same_as_issuer = child_cert.get_issuer().CN == parent_cert.get_subject().CN
					self.srv_certificate.is_expired = child_cert.has_expired()
					self.srv_certificate.correct_subject = self.target in child_cert.get_subject().commonName

			# verify expiry of parent cert, if expired useless proceed with furhter verifications
			if parent_cert.has_expired(): # verification with cryptography : (parent_cert.not_valid_after_utc() <= datetime.datetime.now(datetime.timezone.utc)):
				self.CA_certificate.is_expired = True
				return
			else:
				self.CA_certificate.is_expired = False


			# verify if it is the cert of a CA
			scapy_parent_cert = Cert(parent_cert.to_cryptography().public_bytes(encoding=serialization.Encoding.DER))
			if not scapy_parent_cert.cA:
				self.CA_certificate.is_CA = False
				return
			else:
				self.CA_certificate.is_CA = True

			# verify correct keyUsage of parent and child cert 
			# For a TLS server certificate, the correct values should be:
			# digitalSignature (for TLS handshake)
			# keyEncipherment (when using RSA key exchange)
			# keyAgreement (when using DH/ECDH key exchange)
			scapy_child_cert = Cert(child_cert.to_cryptography().public_bytes(encoding=serialization.Encoding.DER))
			if leaf:
				if self.ssl_sock.get_cipher_name().startswith(("ECDHE", "ECDH", "DH", "DHE", "AES", "CHACHA")):
					if 'digitalSignature' in scapy_child_cert.keyUsage and 'keyAgreement' or 'keyEncipherment' in scapy_child_cert.keyUsage and len(scapy_child_cert.keyUsage)==2 and 'serverAuth' in scapy_child_cert.extKeyUsage:
						self.srv_certificate.is_keyUsage_correct = True
					else:
						self.srv_certificate.is_keyUsage_correct = False
						# print(f"keyUsage with ECDH/AES/CHACHA cipher suite not correct: {', '.join(usage for usage in scapy_child_cert.keyUsage)}")
				elif self.ssl_sock.get_cipher_name().startswith("RSA"):
					if 'digitalSignature' in scapy_child_cert.keyUsage and 'keyEncipherment' in scapy_child_cert.keyUsage and len(scapy_child_cert.keyUsage)==2 and 'serverAuth' in scapy_child_cert.extKeyUsage:
						self.srv_certificate.is_keyUsage_correct = True
					else:
						self.srv_certificate.is_keyUsage_correct = False
						# print(f"keyUsage with RSA cipher suite not correct: {', '.join(usage for usage in scapy_child_cert.keyUsage)}")
			else:
				if 'digitalSignature' in scapy_child_cert.keyUsage and 'keyCertSign' in scapy_child_cert.keyUsage and 'cRLSign' in scapy_child_cert.keyUsage and len(scapy_child_cert.keyUsage)==3:
					self.CA_certificate.is_keyUsage_correct = True
				else:
					self.CA_certificate.is_keyUsage_correct = False
					# print(f"keyUsage not correct: {', '.join(usage for usage in scapy_child_cert.keyUsage)}")

			# verify extensions of parent cert for missing details in scapy structured cert
			crypto_parent_cert = parent_cert.to_cryptography()
			crypto_child_cert = child_cert.to_cryptography()
			for i in range(0, parent_cert.get_extension_count()):
				match crypto_parent_cert.extensions[i].oid._name:
				# The AuthorityKeyIdentifier (AKI) in the child certificate can be populated in multiple ways according to RFC 5280: 
				# Using the Subject Key Identifier from the parent certificate directly, 
				# Computing a hash of the parent's public key, 
				# Computing a hash of the parent certificate's subject name and serial number
					case "subjectKeyIdentifier":
							if not crypto_parent_cert.extensions[i].value.key_identifier == Cert(crypto_child_cert.public_bytes(encoding=serialization.Encoding.DER)).authorityKeyID:
								self.valid_cert_chain =	False
								# print("SubjectKeyId leaf and AuthorityKeyId parent not matching, chain is not valid")
								continue
							else :
								self.valid_cert_chain = True
	

	        # verify validity of certificate signature
			if(self.check_sign(crypto_child_cert, crypto_parent_cert)==None):
				if leaf:
					self.srv_certificate.is_signature_valid = True
				else :
					self.CA_certificate.is_signature_valid = True
			else:
				if leaf:
					self.srv_certificate.is_signature_valid = False
				else :
					self.CA_certificate.is_signature_valid = False
							
		
		def check_sign(self, crypto_child_cert, crypto_parent_cert):
			return crypto_child_cert.verify_directly_issued_by(crypto_parent_cert)


		def check_secure_renegotiation(self):

			context = SSL.Context(SSL.TLSv1_2_METHOD)  # Use TLSv1.2 for security
			context.set_verify(SSL.VERIFY_NONE, lambda *args: True)
			self.connect(ssl_context=context)
			self.ssl_handshake()

			self.ssl_sock.renegotiate()
			if(self.ssl_handshake()):
				self.ssl_sock.shutdown()
				self.ssl_sock.close()
			else:
				self.is_renegotiation_secure()


		# to be implemented, c
		def is_renegotiation_secure(self):
			pass

		# only if tls1.0/1.1 are supported
		def check_scsv_fallback(self):
			pass

		
		# check heartbleed vulnerabiltiy
		# the Heartbleed bug allowed attackers to read sensitive information directly from the memory of servers using vulnerable OpenSSL versions
		# The vulnerability originated from improper bounds checking on the payload length.
		# Attackers could craft a heartbeat request with a fake payload length (up to 64 KB), even if the payload data sent was smaller or even empty.
		# The server would then respond with more data than requested, leaking sensitive information from its memory buffer.
		
		# https://encryptorium.medium.com/the-heartbleed-vulnerability-cve-2014-0160-69eb175cafa7
		def check_heartbleed(self):
			#context = SSL.Context(SSL.TLSv1_2_METHOD)  # Use TLSv1.2 for security
			#context.set_verify(SSL.VERIFY_NONE, lambda *args: True)
			self.connect()
			sniffer = AsyncSniffer(prn=lambda x: self.check_heartbeat_response(x), iface=("lo0" if self.local else "en0"), filter=("" if self.local else f"host {self.target}"), stop_filter= lambda x: (x.haslayer(TCP) and (x[TCP].flags == 20 or x[TCP].flags == 11)) or x.haslayer(TLSAlert), timeout=10, store=False, session=TLSSession)
			sniffer.start()
			ch_pk = self.craft_clientHello()
			self.send(ch_pk)
			hb_pk = self.h2bin('18 03 03 00 03 01 40 00')
			self.send(hb_pk)
			sniffer.join()
			if self.sock:
				# print(f"Expected response not received and no leakeage of data, server does not seem to be vulnerable to Heartbleed")
				self.heartbleed = False
				self.close_socket()
		
		def check_heartbeat_response(self, pk):
			if pk.haslayer(Raw):
				if pk[Raw].load.startswith(b'\x18') and pk[TCP].sport == 8443:
					# print(f"Server is vulnerable to heartbleed attack, {len(pk[Raw].load)} bytes of data leaked: ")
					self.hexdump(pk[Raw].load)
					self.heartbleed = True
					self.close_socket()
				elif pk[Raw].load.startswith(b'\x15'):
					# print(f"Alert received, Heartbleed likely not possible")
					self.heartbleed = False
					self.close_socket()
			elif pk.haslayer(TLSServerHello):
				# print(f"Server hello received, Heartbleed likely not possible")
				self.heartbleed = False
				self.close_socket()
			elif pk.haslayer(TLSAlert):
				# print(f"TLS Alter received, server does not have heartbeat vulnerability, alert code : {pk[TLSAlert].descr}")
				self.heartbleed = False
				self.close_socket()
		
			elif(pk.haslayer(TCP) and (pk[TCP].flags == 20 or pk[TCP].flags == 11)) and pk[TCP].sport == 8443:
				# print(f"Connection close received, Heartbleed likely not possible")
				self.close_socket()
			else:
				pass

		
		def check_ccsinjection(self):
			self.connect()
			sniffer = AsyncSniffer(prn=lambda x: self.check_ccs_response(x), iface=("lo0" if self.local else "en0"), filter=("" if self.local else f"host {self.target}"), stop_filter= lambda x: x.haslayer(TCP) and (x[TCP].flags == 20 or x[TCP].flags == 11) or (x.haslayer(TLSAlert)), timeout=10, store=False, session=TCPSession)
			ch_pk = self.craft_clientHello()
			self.send(ch_pk)
			sniffer.start()
			ccs_pk = TLS(version=(769 if self.local else 771), msg=[TLSChangeCipherSpec()])
			self.send(ccs_pk)
			sniffer.join()
			if self.sock:
				# print(f"No response received, server likely vulnerable to CCS injection")
				self.ccsinjection = True
				self.close_socket()


		def check_ccs_response(self, pk):
			if pk.haslayer(TLSAlert):
				self.ccsinjection = True
				# print(f"Alert record received as response to the invalid CCS Message, CCS injection likely not possible")
				self.close_socket()
			else:
				pass

		def check_crime(self):
			self.connect()
			sniffer = AsyncSniffer(prn=lambda x: self.check_crime_response(x), iface=("lo0" if self.local else "en0"), filter=f"" if self.local else f"host {self.target}", stop_filter= lambda x: (x.haslayer(TCP) and (x[TCP].flags == 20 or x[TCP].flags == 11)) or (x.haslayer(TLSAlert)) or (x.haslayer(TLSServerHello) and 0x0 in x[TLSServerHello].comp) or (x.haslayer(Raw) and TLS(x[Raw].load).haslayer(TLSServerHello)), timeout=10, store=False, session=TCPSession)
			sniffer.start()
			ch_pk = self.craft_clientHello(cmp=False)
			self.send(ch_pk)
			sniffer.join()

		def check_crime_response(self, pk):
			if pk.haslayer(Raw):
				srv_hello = TLS(pk[Raw].load)
				if srv_hello.haslayer(TLSServerHello):
					if 0x01 in srv_hello[TLSServerHello].comp:
						# print(f"Server is vulnerable to CRIME attack, server supports compression")
						self.crime = True
						self.close_socket()
					else:
						self.crime = False
						# print(f"Server is not vulnerable to CRIME attack, server does not support compression with DEFLATE algorithm")
						self.close_socket()
			elif pk.haslayer(TLSServerHello):
				if 0x01 in pk[TLSServerHello].comp:
					# print(f"Server is vulnerable to CRIME attack, server supports compression")
					self.crime = True
					self.close_socket()
				else:
					# print(f"Server is not vulnerable to CRIME attack, server does not support compression with DEFLATE algorithm")
					self.crime = False
					self.close_socket()
			elif pk.haslayer(TLSAlert):
				# print(f"Alert record received as response to client hello, server does not support compression")
				self.crime = False
				self.close_socket()
			elif(pk.haslayer(TCP) and (pk[TCP].flags == 20 or pk[TCP].flags == 11)):
				# print(f"Connection close received, CRIME likely not possible")
				self.crime = False
				self.close_socket()
			else:
				pass

		def check_ticketBleed(self):
			pass
		
		def ssl_handshake(self):
			try:
				self.ssl_sock.do_handshake()
			except Exception as e:
				if "unexpected record" or "Unexpected EOF" in str(e):
					# print("server likely does not support renegotiation")
					self.is_renegotiation_supported = False
					self.ssl_sock.close()
					return False
				else:
					# print(f"Handshake failed due to exception : {e}")
					self.ssl_sock.close()
					exit(1)


		def craft_clientHello(self, version=771, cipher=None, groups=SUPP_CV_GROUPS, sign_algs=SIGN_ALGS, pubkeys=None, pskkxmodes=1, ocsp_status_req=None, renego_info=False, cmp=False):
			
			version = 771 if self.local else version
			try:
			    
				ch_pk = TLS(version=(771 if version > 771 else version), type=22, msg=[TLSClientHello(version=(771 if version > 771 else version), ciphers=(cipher if cipher else ciphers[version]), random_bytes=os.urandom(32), comp=([0x01] if cmp else [0x00]), ext=[ \
										(TLS_Ext_ServerName(servernames=[ServerName(nametype=0, servername=(self.target.encode('utf-8')))]) if not self.local else []), TLS_Ext_SupportedGroups(groups=groups if groups else self.groups), \
										TLS_Ext_SignatureAlgorithms(sig_algs=(sign_algs if sign_algs else self.sign_algs)), TLS_Ext_SupportedVersion_CH(versions=[version]), \
										TLS_Ext_PSKKeyExchangeModes(kxmodes=[pskkxmodes]), TLS_Ext_SupportedPointFormat(ecpl=[0], type=11, len=2, ecpllen=1), \
										TLS_Ext_EncryptThenMAC(), TLS_Ext_ExtendedMasterSecret(), \
										(TLS_Ext_CSR(req=ocsp_status_req, stype=1) if ocsp_status_req else []), \
										(TLS_Ext_RenegotiationInfo(renegotiated_connection=b'') if renego_info else [])])])
			
				if(version==772):
					ch_pk.msg[0].ext.append(TLS_Ext_KeyShare_CH(client_shares=[]))
					pubkeys = self.generate_keys(crvs=groups)
					if not isinstance(groups, list):
						groups = [groups]
					for curve, pu_key in zip(list(groups), pubkeys):
						ch_pk[TLS_Ext_KeyShare_CH].client_shares.append(KeyShareEntry(group=curve, key_exchange=pu_key, kxlen=len((pu_key))))

			except scapy.error.Scapy_Exception as e:
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
			"""
			if cmp:
				deflate_compr = Comp_Deflate()
				ch_pk[TLS].msg = Raw(deflate_compr.compress(s=bytes(ch_pk[TLSClientHello])))
			"""
			return ch_pk


		
		def generate_keys(self, crvs=SUPP_CV_GROUPS): # per ora  non salviamo chiave priv
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
		
		def h2bin(self, x):
			return binascii.unhexlify(x.replace(' ', '').replace('\n', ''))
		
		def hexdump(self, s: bytes):
			for b in range(0, len(s), 16):
				lin = [c for c in s[b : b + 16]]
				hxdat = ' '.join('%02X' % c for c in lin)
				pdat = ''.join((chr(c) if 32 <= c <= 126 else '.' )for c in lin)
				print('  %04x: %-48s %s' % (b, hxdat, pdat))
			
			print("")

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
	scanner = TLSscanner(target="www.acmilan.com", dstport=443, sourceAddress=None, groups=SUPP_CV_GROUPS, sign_algs=SIGN_ALGS ) 
	scanner.scan()






				
