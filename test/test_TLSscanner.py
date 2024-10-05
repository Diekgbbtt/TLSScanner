import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from TLSscanner import TLSscanner


class test_TLSscanner():
        
    def test_cipher_suites():    
        scanner = TLSscanner(target="www.ikea.com")

        scanner.create_sniffer()
        scanner.supportedProtocols = [771, 772]
        scanner.get_supportedCipherSuites()
        scanner.sock.close()

if __name__ == "__main__":
    test_TLSscanner.test_cipher_suites()



