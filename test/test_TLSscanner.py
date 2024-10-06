import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import asyncio
from TLSscanner import TLSscanner


class test_TLSscanner():

    def __init__(self, target):
        self.scanner = TLSscanner(target=target)

    def test_protocol_versions(self):
        self.scanner.get_supportedProtocols()

    def test_cipher_suites(self):    
        asyncio.run(self.scanner.get_supportedCipherSuites())
 
    
 
if __name__ == "__main__":

    scanner = test_TLSscanner(target="www.youtube.com")
    scanner.test_protocol_versions()
    scanner.test_cipher_suites()



