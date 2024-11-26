import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import asyncio
from TLSscanner import TLSscanner


SUPP_CV_GROUPS = [24, 23, 29] # da aggiungere X25519Kyber768Draft00
SIGN_ALGS = [1027,1283,1539,2055,2053,2054,1025,1281,1537]


class test_TLSscanner():

    def __init__(self, target, dstport):
        self.scanner = TLSscanner(target=target, dstport=dstport, sourceAddress=None, groups=SUPP_CV_GROUPS, sign_algs=SIGN_ALGS )

    def test_protocol_versions(self):
        self.scanner.get_supportedProtocols()

    def test_cipher_suites(self):    
        asyncio.run(self.scanner.get_supportedCipherSuites())
    
    def test_curves(self):
        asyncio.run(self.scanner.get_supportedCurves())
    
    def test_algorithms(self):
        asyncio.run(self.scanner.get_supportedSignalgs())

    def test_get_certificate(self):
        self.scanner.get_certificate()

    def test_get_certificate_chain(self):
        self.scanner.get_certificate_chain()
    
    def test_check_secure_renegotiation(self):
        self.scanner.check_secure_renegotiation()

    def test_analyze_cert_chain(self):
        self.scanner.get_certificate_chain()

    def test_check_heartbleed(self):
        self.scanner.check_heartbleed()
    
    def test_check_ccsinjection(self):
        self.scanner.check_ccsinjection()
    
    def test_check_crime(self):
        self.scanner.check_crime()
 
if __name__ == "__main__":

    scanner = test_TLSscanner(target="juice-shop.herokuapp.com", dstport=443) 
    scanner.test_protocol_versions()
    scanner.test_cipher_suites()
    scanner.test_curves()
    scanner.test_algorithms()
    # scanner.test_get_certificate()
    # scanner.test_get_certificate_chain()
    # scanner.test_check_secure_renegotiation()
    # scanner.test_analyze_cert_chain()
    # scanner.test_check_heartbleed()
    # scanner.test_check_ccsinjection()
    # scanner.test_check_crime()




