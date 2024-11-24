#!/usr/bin/env python3.12


import sys, argparse, logging

import TLSscanner


SUPP_CV_GROUPS = [24, 23, 22, 21, 29] # da aggiungere X25519Kyber768Draft00
SUPP_CV_GROUPS_test  = [24, 23, 29] 
SIGN_ALGS = [1027,1283,1539,2055,2053,2054,1025,1281,1537]



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
    parser.add_argument("-s", "--sourceaddress", required=False, type=str, help="source address", default=None)
    parser.add_argument("-m", "--mode", required=False, type=str, help="scan mode", default='full')
    parser.add_argument("-c", "--curves", required=False, type=int, nargs='+', help="elliptic curves to check for and use as supported in EC based encryption", default=SUPP_CV_GROUPS_test)
    parser.add_argument("-s", "--sign_algs", required=False, type=int, nargs='+', help="signature algorithms to check for and use to sign messages", default=SIGN_ALGS)
    parser.add_argument("-v", "--verbose", type=int, required=False, action="store_true", help="verbosity of output", default=1)

    args = parser.parse_args()

    if not args.target:
        parser.error("target is required")

    return args
    
    # args sanitization


def tlsScan(args):
     
    scanner = TLSscanner.TLSscanner(target=args.target, dstport=args.port, sourceAddress=args.sourceaddress, groups=args.curves, sign_algs=args.sign_algs)
    scanner.scan()

    print(f"""
          
        {args.target} TLS scan completed

        ########################################################################################
        #                                                                                      #
        #                                                                                      #
        #                                                                                      #
        """)
    for sp in scanner.supportedProtocols:

        match sp:
            case 768:
                print(
                f"""
                #                                                                                      #
                #    SSLV3.0 : SUPPORTED                                                               #
                #    |\                                                                                #      
                #    | \__ CIPHERS :                                                                   #
                """)

                for index, cipher in enumerate(scanner.ciphers_info[sp]["supportedCiphers"]):
                    print(
                        f"""
                        #    |     {index} : {cipher}                                                          #
                        """)
                print(
                    f"""
                    #    |\                                                                                #
                    #    | \__ CURVES :                                                                    #
                    """)
                    
                for index, curve in enumerate(scanner.supportedCurves):
                    print(
                        f"""
                        #    |     {index} : {curve}                                                          #
                        """)
                print(
                    f"""
                    #    |\                                                                                #
                    #    | \__ SIGN ALGORITHMS :                                                           #
                    """)
                for index, alg in enumerate(scanner.supportedAlgs):
                    print(
                        f"""
                        #    |     {index} : {alg}                                                             #
                        """)
                print(
                    f"""
                    #                                                                                      #
                    #                                                                                      #
                    #####       #####       #####       #####       #####       #####       #####       ####
                    """)
                                                                                  #
        
            case 769:
                print(
                f"""
                #                                                                                      #
                #    TLS1.0 : SUPPORTED                                                               #
                #    |\                                                                                #      
                #    | \__ CIPHERS :                                                                   #
                """)

                for index, cipher in enumerate(scanner.ciphers_info[sp]["supportedCiphers"]):
                    print(
                        f"""
                        #    |     {index} : {cipher}                                                          #
                        """)
                print(
                    f"""
                    #    |\                                                                                #
                    #    | \__ CURVES :                                                                    #
                    """)
                    
                for index, curve in enumerate(scanner.supportedCurves):
                    print(
                        f"""
                        #    |     {index} : {curve}                                                          #
                        """)
                print(
                    f"""
                    #    |\                                                                                #
                    #    | \__ SIGN ALGORITHMS :                                                           #
                    """)
                for index, alg in enumerate(scanner.supportedAlgs):
                    print(
                        f"""
                        #    |     {index} : {alg}                                                             #
                        """)
                print(
                    f"""
                    #                                                                                      #
                    #                                                                                      #
                    #####       #####       #####       #####       #####       #####       #####       ####
                    """)
            case 770:
                print(
                f"""
                #                                                                                      #
                #    TLS1.1 SUPPORTED                                                               #
                #    |\                                                                                #      
                #    | \__ CIPHERS :                                                                   #
                """)

                for index, cipher in enumerate(scanner.ciphers_info[sp]["supportedCiphers"]):
                    print(
                        f"""
                        #    |     {index} : {cipher}                                                          #
                        """)
                print(
                    f"""
                    #    |\                                                                                #
                    #    | \__ CURVES :                                                                    #
                    """)
                    
                for index, curve in enumerate(scanner.supportedCurves):
                    print(
                        f"""
                        #    |     {index} : {curve}                                                          #
                        """)
                print(
                    f"""
                    #    |\                                                                                #
                    #    | \__ SIGN ALGORITHMS :                                                           #
                    """)
                for index, alg in enumerate(scanner.supportedAlgs):
                    print(
                        f"""
                        #    |     {index} : {alg}                                                             #
                        """)
                print(
                    f"""
                    #                                                                                      #
                    #                                                                                      #
                    #####       #####       #####       #####       #####       #####       #####       ####
                    """)
            case 771:
                print(
                f"""
                #                                                                                      #
                #    TLS1.2 SUPPORTED                                                               #
                #    |\                                                                                #      
                #    | \__ CIPHERS :                                                                   #
                """)

                for index, cipher in enumerate(scanner.ciphers_info[sp]["supportedCiphers"]):
                    print(
                        f"""
                        #    |     {index} : {cipher}                                                          #
                        """)
                print(
                    f"""
                    #    |\                                                                                #
                    #    | \__ CURVES :                                                                    #
                    """)
                    
                for index, curve in enumerate(scanner.supportedCurves):
                    print(
                        f"""
                        #    |     {index} : {curve}                                                          #
                        """)
                print(
                    f"""
                    #    |\                                                                                #
                    #    | \__ SIGN ALGORITHMS :                                                           #
                    """)
                for index, alg in enumerate(scanner.supportedAlgs):
                    print(
                        f"""
                        #    |     {index} : {alg}                                                             #
                        """)
                print(
                f"""
                #                                                                                      #
                #                                                                                      #
                #####       #####       #####       #####       #####       #####       #####       ####
                """)
            case 772:
                print(
                f"""
                #                                                                                      #
                #    TLS1.3 SUPPORTED                                                                  #
                #    |\                                                                                #      
                #    | \__ CIPHERS :                                                                   #
                """)

                for index, cipher in enumerate(scanner.ciphers_info[sp]["supportedCiphers"]):
                    print(
                        f"""
                        #    |     {index} : {cipher}                                                          #
                        """)
                print(
                f"""
                #    |\                                                                                #
                #    | \__ CURVES :                                                                    #
                """)
                    
                for index, curve in enumerate(scanner.supportedCurves):
                    print(
                        f"""
                        #    |     {index} : {curve}                                                          #
                        """)
                print(
                f"""
                #    |\                                                                                #
                #    | \__ SIGN ALGORITHMS :                                                           #
                """)
                for index, alg in enumerate(scanner.supportedAlgs):
                    print(
                        f"""
                        #    |     {index} : {alg}                                                             #
                        """)
                print(
                f"""
                #                                                                                      #
                #                                                                                      #
                ########################################################################################
                """)
            case _:
                print(f"Unsupported protocol {sp}")


    
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
                "is_valid" : true/false - verificare che sia correttta con la chiave pubblica della CA, presente nnell'ext auth key identifier
            
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