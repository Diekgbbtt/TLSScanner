#!/usr/bin/env python3.12


import sys, argparse, logging, warnings

from base64 import b64encode
from textwrap import fill
from scapy.layers.tls.crypto.suites import _tls_cipher_suites
from scapy.layers.tls.crypto.groups import _tls_named_curves
from scapy.layers.tls.keyexchange import _tls_hash_sig

import TLSscanner


SUPP_CV_GROUPS = [24, 23, 22, 21, 29] # da aggiungere X25519Kyber768Draft00
SUPP_CV_GROUPS_test  = [24, 23, 29] 
SIGN_ALGS = [1027,1283,1539,2055,2053,2054,1025,1281,1537]


warnings.filterwarnings("ignore", category=SyntaxWarning)


def get_args():
     
    """
    istanziare ArgumentParser

    parsare arguments, che vengono aggiunti al parser

    controllare che gli args minimi siano stato forniti(target) e che tutti siano stati forniti correttamente

    ritornare gli args - args = parser.parse_args()
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, type=str, help="target to scan")
    parser.add_argument("-p", "--port", required=False, type=int, help="port to scan", default=443)
    parser.add_argument("-sa", "--sourceaddress", required=False, type=str, help="source address", default=None)
    parser.add_argument("-m", "--mode", required=False, type=str, help="scan mode", default='full')
    parser.add_argument("-c", "--curves", required=False, type=int, nargs='+', help="elliptic curves to check for and use as supported in EC based encryption", default=SUPP_CV_GROUPS_test)
    parser.add_argument("-s", "--signalgs", required=False, type=int, nargs='+', help="signature algorithms to check for and use to sign messages", default=SIGN_ALGS)
    parser.add_argument("-v", "--verbose", type=int, required=False, help="verbosity of output", default=1)

    args = parser.parse_args()

    if not args.target:
        parser.error("target is required")

    return args
    
    # args sanitization


def tlsScan(args):
     
    scanner = TLSscanner.TLSscanner(target=args.target, dstport=args.port, sourceAddress=args.sourceaddress, groups=args.curves, sign_algs=args.signalgs)
    scanner.scan()

    print(f"""
          
        {args.target} TLS scan completed

        ########################################################################################
        #                                                                                      #
        #                                                                                      #
        #                                                                                      #""")
    # supported versions and relative ciphers
    for sp in scanner.supportedProtocols:

        match sp:
            case 768:
                print(
f"""        #                                                                                      #
        #    SSLV3.0 : SUPPORTED                                                               #
        #    |\                                                                                #      
        #    | \__ CIPHERS :                                                                   #""")

                for index, cipher in enumerate(scanner.ciphers_info[sp]["supportedCiphers"]):
                    print(
f"""        #    |     {index:<2} : {_tls_cipher_suites[cipher]:<40}                               #""")
                print(
f"""        #                                                                                      #
        #####       #####       #####       #####       #####       #####       #####       ####""")
                                                                                  #
        
            case 769:
                print(
f"""        #                                                                                      #
        #    TLS1.0 : SUPPORTED                                                                #
        #    |\                                                                                #      
        #    | \__ CIPHERS :                                                                   #""")
                for index, cipher in enumerate(scanner.ciphers_info[sp]["supportedCiphers"]):
                    print(
f"""        #    |     {index:<2} : {_tls_cipher_suites[cipher]:<40}                               #""")
                print(
f"""        #                                                                                      #
        #####       #####       #####       #####       #####       #####       #####       ####""")
            case 770:
                print(   
f"""        #                                                                                      #
        #                                                                                      #
        #    TLS1.1 SUPPORTED                                                                  #
        #    |\                                                                                #      
        #    | \__ CIPHERS :                                                                   #""")
                for index, cipher in enumerate(scanner.ciphers_info[sp]["supportedCiphers"]):
                    print(
f"""        #    |     {index:<2} : {_tls_cipher_suites[cipher]:<40}                               #""")
                print(
f"""        #                                                                                      #
        #####       #####       #####       #####       #####       #####       #####       ####""")
            case 771:
                print(
f"""        #                                                                                      #
        #    TLS1.2 SUPPORTED                                                                  #
        #    |\                                                                                #      
        #    | \__ CIPHERS :                                                                   #""")
                for index, cipher in enumerate(scanner.ciphers_info[sp]["supportedCiphers"]):
                    print(    
f"""        #    |     {index:<2} : {_tls_cipher_suites[cipher]:<40}                               #""")
                print(
f"""        #                                                                                      #
        #                                                                                      #
        #####       #####       #####       #####       #####       #####       #####       ####""")
            case 772:
                print(  
f"""        #                                                                                      #
        #    TLS1.3 SUPPORTED                                                                  #
        #    |\                                                                                #      
        #    | \__ CIPHERS :                                                                   #""")
                for index, cipher in enumerate(scanner.ciphers_info[sp]["supportedCiphers"]):
                    print(
f"""        #    |     {index:<2} : {_tls_cipher_suites[cipher]:<40}                               #""")
                print(
f"""        #                                                                                      #
        #####       #####       #####       #####       #####       #####       #####       ####""")
            case _:
                print(f"Unsupported protocol {sp}")

# supported curves        
    print(
f"""        #    |\                                                                                #
        #    | \__ CURVES :                                                                    #""")
    for index, curve in enumerate(scanner.supportedCurves):
        print(
f"""        #    |     {index:<2} : {_tls_named_curves[curve]:<10}                                                              #""")
# supported algs
    print(
f"""        #    |\                                                                                #
        #    | \__ SIGN ALGORITHMS :                                                           #""")
    for index, alg in enumerate(scanner.supportedAlgs):
        print(
f"""        #    |     {index:<2} : {_tls_hash_sig[alg]:<10}                                                         #""")
# report ending line
    print(
f"""        #                                                                                      #
        #                                                                                      #
        ########################################################################################""")
    
#server certificate major security information

    print(
fr"""        #                                                                                      #
        #                                                                                      #
        #    CERTIFICATE INFORMATION :                                                         #
        #     \                                                                                #
        #      \__Version : {scanner.srv_certificate.version}                                                               #
        #      |__Subject : {scanner.srv_certificate.subject['commonName']}                                                 #
        #      |  \__Public Key  :                                                             #
        #                   {b64encode(scanner.srv_certificate.pubKey.der)[:120]} #                     
        #      |    \__CorrectUsage : {'Yes' if scanner.srv_certificate.is_keyUsage_correct else 'No'}                                                  #    
        #      |      \_Algorithm : rsaEncryption                                              #
        #      |__Issuer : {scanner.srv_certificate.issuer['commonName']}   
        #         \__selfSigned : {scanner.srv_certificate.isSelfSigned()}                #
        #      |__Validity                                                                     #
        #      |   \__FROM : {scanner.srv_certificate.notBefore_str}                                        #
        #      |    \_TO : {scanner.srv_certificate.notAfter_str}                                           #
        #      |__Signature :                                                                  #
        #               {b64encode(scanner.srv_certificate.signatureValue)[:120]} #
        #      |    \__Signature Algorithm : {scanner.srv_certificate.sigAlg}                           #   
        #      |     \_Signature Validity :  {'Yes' if scanner.srv_certificate.is_signature_valid else 'No'}                                                #                                        
        #      |__Serial Number : {scanner.srv_certificate.serial}                       #
        #      |__Revoked : NO                                                                 #
        #                                                                                      #
        ########################################################################################""")
    
    if hasattr(scanner, 'CA_certificate'):
    # certificate chain major information
        print(
f"""        #                                                                                      #         
        #    CERTIFICATE CHAIN :                                                               #
        #     \                                                                                #
        #      \__CorrectChain : {'Yes' if scanner.valid_cert_chain else 'No'}                                                                 #
        #      |__CA_CorrectUsage :   {'Yes' if scanner.CA_certificate.is_keyUsage_correct else 'No'}                                                      #                
        #                                                                                      #
        #                                                                                      #
        ########################################################################################""")

#  common attacks results
    print(
f"""        #                                                                                      #
        #                                                                                      #
        #  COMMON ATTACKS :                                                                    #
        #  \                                                                                   #
        #   \__HeartBleed : {'Vulnerable' if scanner.heartbleed else 'Safe'}                                                            #
        #   |__CCSInjection : {'Vulnerable' if scanner.ccsinjection else 'Safe'}                                                        #
        #   |__CRIME : {'Vulnerable' if scanner.crime else 'Safe'}                                                                    #
        #   |__POODLE : {'Vulnerable' if 768 in scanner.supportedAlgs else 'Safe'}                                                                  #
        #   |__BEAST : {'Vulnerable' if 769 in scanner.supportedAlgs else 'Safe'}                                                                   #
        #   |__TicketBleed : Safe                                                              #
        #                                                                                      #
        #                                                                                      #
        ########################################################################################""")

    """

    Istanziare TLSScanner - da vedere come un processo separato

    create scanResult object with evaluations of TLSScanner attributes

    ritornare l'oggetto scanResults - che può essere visto come un dizionario
    "targett {
        "supportVersions": {
            "tls1.3" : {
                "supported" : true/false
                "ciphers" : [ciphers]
                "curves" : [curves]
                "sign_algs" : [sign_algs]
            },
            "tls1.2" : {
                "supported" : true/false
                "ciphers" : [ciphers]
                "curves" : [curves]
                "sign_algs" : [sign_algs]
            },

            "tls1.1" : {
                "supported" : true/false
                "ciphers" : [ciphers]
                "curves" : [curves]
                "sign_algs" : [sign_algs]
            },
            
            "tls1.0" : {
                "supported" : true/false
                "ciphers" : [ciphers]
                "curves" : [curves]
                "sign_algs" : [sign_algs]
            } -- da implementare in qualche modo delle considerazioni di sicurezza sui ciphers e curve utilizzate
        }
        "certificate_info_{hostname}" : {
            "version" : version,

            "sign_alg" : sign_alg,
            "signature" : {
                value : [signature]
                "is_valid" : true/false - verificare che sia correttta con la chiave pubblica della CA, presente nell'ext auth key identifier
            
            }, -- che verfiche della firma del certificato si possono fare? , ..
            "issuer" : {
                organization : [organization]
                country : [country]
                common_name : [common_name]
                is_selfSigned : true/false
            }
            subject : {
                common_name : [common_name]
                CA : {
                    is_CA : true/false
                    is_trusted : true/false
                }
                is_requestedSameName : true/false
            }
            validity : {
                notBefore : [notBefore]
                notAfter : [notAfter]
                is_expired : true/false
            }
            public_key : {
                algorithm : [algorithm]
                key : [key]
                is_correct : true/false; -- permette di decifrare la firma della chiave pubblica effimera, effettuata con la relativa chiave privata? https://chatgpt.com/c/c259fcc7-0d1d-4989-892d-453ef9ff4f32
            }
            extensions check...
        }
        vulnerabilities : {
            "attacks" : {
                "attack_1" : true/false
                "attack_2" : true/false
                ....
            }
            "securityImplementation_issues" : {
            
                "SECURE_RENEGOTIATION" : true/false
                "TLS_FALLBACK_SCSV" : true/false
                ....
            }

    }
    
    """

def start_scan():
        
    """"
    parse arguments


    execute tlsScan


    print scan results

    """
    print("""
 _________  ___       ________  ________  ________  ________   ________   _______   ________     
|\___   ___\\  \     |\   ____\|\   ____\|\   __  \|\   ___  \|\   ___  \|\  ___ \ |\   __  \    
\|___ \  \_\ \  \    \ \  \___|\ \  \___|\ \  \|\  \ \  \\ \  \ \  \\ \  \ \   __/|\ \  \|\  \   
     \ \  \ \ \  \    \ \_____  \ \  \    \ \   __  \ \  \\ \  \ \  \\ \  \ \  \_|/_\ \   _  _\  
      \ \  \ \ \  \____\|____|\  \ \  \____\ \  \ \  \ \  \\ \  \ \  \\ \  \ \  \_|\ \ \  \\  \| 
       \ \__\ \ \_______\____\_\  \ \_______\ \__\ \__\ \__\\ \__\ \__\\ \__\ \_______\ \__\\ _\ 
        \|__|  \|_______|\_________\|_______|\|__|\|__|\|__| \|__|\|__| \|__|\|_______|\|__|\|__|
                        \|_________|                                                                                                                                                                                            
        """)
    # parse arguments
    args = get_args()
    tlsScan(args)



if __name__ == "__main__":  
    start_scan()