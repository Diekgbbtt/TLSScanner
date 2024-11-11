import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import asyncio
from TLSscanner import TLSscanner


class test_TLSscanner():

    def __init__(self, target, dstport):
        self.scanner = TLSscanner(target=target, dstport=dstport)

    def test_protocol_versions(self):
        self.scanner.get_supportedProtocols()
        print(self.scanner.targetIP)

    def test_cipher_suites(self):    
        asyncio.run(self.scanner.get_supportedCipherSuites())
    
    def test_curves(self):
        asyncio.run(self.scanner.get_supportedCurves())
    
    def test_algorithms(self):
        asyncio.run(self.scanner.get_supportedSignalgs())

    def test_get_certificate(self):
        self.scanner.get_certificate()
    
    def test_check_secure_renegotiation(self):
        self.scanner.check_secure_renegotiation()

    def test_analyze_cert_chain(self):
        self.scanner.get_certificate_chain()

    def test_check_heartbleed(self):
        self.scanner.check_heartbleed()
 
if __name__ == "__main__":

    scanner = test_TLSscanner(target="192.168.1.192", dstport=8443)
    # scanner.test_protocol_versions()
    # scanner.test_get_certificate()
    # scanner.test_check_secure_renegotiation()
    # scanner.test_analyze_cert_chain()
    scanner.test_check_heartbleed()




