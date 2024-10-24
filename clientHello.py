#!/usr/bin/env python3.12

""" SSL Fuzzer """

__version__ = "0.0.1"
__author__ = "Diego Gobbetti"


"""
status :  handled tls1.3 and tls1.2
"""
""""
todo : 
    - handler of responses different than serverHello: changecipherspec, ... 
        - I can get chagnecipherspce for several reasons :
            - if the server decide to use exchange method with psk ecdh, it expects a keyshare and I can't create a proper clienthello packet --> fixed
            - server reveal that there is a previous session so it provieds a sessione id or ticket in the reply and skip verification.
            - PSK-based handshake(TLS1.3), a changecipherspec is used and included in the server hello, to diguise the session as tls1.2 
            for middleboxes compatibility(sw/hw in the middle of a connection that filter/modify packets)
        the bottom line is in tls1.3 everythin that follows serverhello is encrypted with teh session key and authneticated, so are the certificates and certifcate verify messages. That appear as
        application data in the following tls messsages --> watch test in scapy repo with tlssession mirror to decrypt
        So I should decrypted the followign message to retrive certificate in tls1.3. Otherwise in tls1.2(wordreference.com) the certificate is sent in 
        the serverhello message, which is not encypted.
        So first of all I need to undestand the tls version sued by the server and accordingly proceed on the analysis. Anyway if I send a client hello with version tls1.2
        (supported_ch_versions = [771]) I can get a certificate in the serverhello message, which is not encrypted.

    - prn or lower method should return a tls package crafted with the responses    
"""



import socket, sys, os,argparse, ssl
import logging

from ecdsa import NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, SECP256k1
from ecdsa.keys import SigningKey


from scapy.all import AsyncSniffer, SuperSocket
from scapy.layers.tls.all import *
from scapy.layers.tls.crypto import groups as curves
from scapy.layers.inet import * # IP, TCP
from scapy.layers.tls.crypto.suites import _tls_cipher_suites


from cryptography.hazmat.primitives.asymmetric import *


CIPHERS = [4866,4867,4865,49196,49200,159,52393,52392,52394,49195,49199,158,49188,49192,107,49187,49191,103,49162,49172,57,49161,49171,51,157,156,61,60,53,47,255]
TLS12_CIPHERS = [4866,4867,4865,49196,49200,159,52393,52392,52394,49195,49199,158,49188,49192,107,49187,49191,103,49162,49172,57,49161,49171,51,157,156,61,60,53,47,255]
TLS13_CIPHERS = [4869, 4868, 4867, 4866, 4865]
SUPP_CV = [24, 23, 22, 21, 29]
SUPP_CV_test = [29]
SIGN_ALGS = [1027,1283,1539,2055,2056,2057,2058,2059,2052,2053,2054,1025,1281,1537]

sock = SuperSocket(family=socket.AF_INET,type=socket.SOCK_STREAM) 
srv_rs = []


def parse_args():
     
     """
     istanziare ArgumentParser

     parsare arguments, che vengono aggiunti al parser

     controllare che gli args minimi siano stato forniti(target) e che tutti siano stati forniti correttamente

     ritornare gli args - args = parser.parse_args()
     """


def tlsScan(args):
     
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

def main():
        
        """"
        parse arguments


        execute tlsScan


        print scan results

        """
        
        
        parser = argparse.ArgumentParser()
        
        ch_pk = clientHello(hostname="www.acmilan.com")

        sock.ins.bind(("192.168.1.46", 5899))
        dstip=socket.gethostbyname("www.acmilan.com")
        sock.ins.connect((dstip, 443))      
        print(dstip)
        # sock = socket.create_connection((dstip, 443))

        srv_name = sock.ins.getpeername()
        print(srv_name)


        sniffer = AsyncSniffer(prn=handleServerHello, session=TLSSession, iface="en0", store=False, filter=f"src host {dstip}") # stopfilter=lambda

        sock.send(bytes(ch_pk))
        # srv_rs = sock.recv(4096)
 
        # srv_rs = sr1(ch_pk) # filter=f"host {dstip}"
        # print(srv_rs)
    

        sniffer.start()
        time.sleep(5)
        sniffer.stop()
        print("out of sleep")
        print(sniffer.results)
        sock.close()

        for rs in srv_rs:
            rs.show()

        # sendrecv.tshark(iface="en0", session=TLSSession, filter=f"src host {dstip}") # prn=handleServerHello
        # sniff(prn=handleServerHello(), session=TLSSession, iface="en0", store=False, filter=f"src host {dstip}") #" opened_socket=sock, 
       #  rsp_dump_hex = (hexdump(srv_rs))
        # srv_hello_eth = Ether(import_hexcap(rsp_dump_hex))
        # print(srv_hello_eth.show())
        # srv_hello_ip = IP(raw(srv_hello_eth[Raw].load))
        # print(srv_hello_ip.show())

        return None



def handleServerHello(srv_hello):

        try:
            # print(f"received , msg: \n {srv_hello['TLS'].show()}")
            # print(f"server hello received , msg: \n {srv_hello['TLS'].msg[1]}")
            if srv_hello.haslayer('TLS'):
                if srv_hello['TLS'].type == 22:
                        if srv_hello['TLS'].msg[0].msgtype in [2,11,12,13,14]:
                            srv_rs.append(TLS(raw(srv_hello['TLS'])))
                            # print(f"ServerHello received correclty : \n {srv_hello.show(dump=True)}")
                            """
                            for e in srv_hello['TLS'].msg[0].ext:
                                if(isinstance(e, TLS_Ext_RenegotiationInfo)):
                                    print("renegotiation fetched succesfully")
                                    srvhelloAck = TCP(dport=443, seq=srv_hello['TCP'].ack)
                                    srvhelloAck.show()
                                    # sock.send(bytes(srvhelloAck))
                            """
                        elif srv_hello['TLS'].msg[0].msgtype == 20:
                            print(f"Cipher spec request received \n")
            else:
                print("not expected pkg received")
        
        except:
            pass
    


def get_curve(curve_name):
    curve_map = {
        "secp192r1": NIST192p,
        "secp224r1": NIST224p,
        "secp256r1": NIST256p,
        "secp384r1": NIST384p,
        "secp521r1": NIST521p,
        "secp256k1": SECP256k1,
    }
    return curve_map.get(curve_name)

def generateKeys(groups):
        pubks_list =[]
        for curve in groups:
        #    private_key = x25519.X25519PrivateKey.generate()# per ora  non salviamo chiave priv
            try:
                if(curves._tls_named_curves[curve] == "x25519"):
                    pv_key = x25519.X25519PrivateKey.generate()
                    pu_key = pv_key.public_key()
                    pu_key_raw = pu_key.public_bytes(encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw)
                else:
                    curve_obj = get_curve(curves._tls_named_curves[curve])
                    if curve_obj:
                        sk = SigningKey.generate(curve=curve_obj)
                        pu_key = sk.get_verifying_key()
                        pu_key_raw = pu_key.to_string("raw")
            except:
                print("not supported curve type")
                sys.exit(1)
            

            pubks_list.append(pu_key_raw)

        return pubks_list

            
            

def clientHello(version=771, ciphers=TLS12_CIPHERS, groups=SUPP_CV, sign_algs=SIGN_ALGS, pubkeys=None, pskkxmodes=1, hostname=None):
        try:
            ch_pk = TLS(version=769, type=22, msg=[TLSClientHello(version=771, ciphers=ciphers, random_bytes=os.urandom(32) , ext=[ \
                                    TLS_Ext_ServerName(servernames=[ServerName(nametype=0, servername=hostname.encode('utf-8'))]), TLS_Ext_SupportedGroups(groups=groups), \
                                    TLS_Ext_SignatureAlgorithms(sig_algs=sign_algs), TLS_Ext_SupportedVersion_CH(versions=[version]), \
                                    TLS_Ext_PSKKeyExchangeModes(kxmodes=[pskkxmodes]), TLS_Ext_SupportedPointFormat(ecpl=[0], type=11, len=2, ecpllen=1), 
                                    TLS_Ext_KeyShare_CH(client_shares=[])])]) #TLS_Ext_ServerName(servernames=hostname),
            """
            version 1.2
            """
            ch_pk12 = TLS(version=769, type=22, msg=[TLSClientHello(version=771, msgtype=1,  ciphers=ciphers, random_bytes=os.urandom(32), comp=[0], ext=[ \
                                    TLS_Ext_ServerName(servernames=[ServerName(nametype=0, servername=hostname.encode('utf-8'))], type=0), \
                                    TLS_Ext_RenegotiationInfo(type=65281, len=1, reneg_conn_len=0, renegotiated_connection=b''), \
                                    TLS_Ext_SupportedGroups(groups=groups), TLS_Ext_SignatureAlgorithms(sig_algs=sign_algs) \
                                    # TLS_Ext_SupportedVersion_CH(versions=[version, 771]), TLS_Ext_PSKKeyExchangeModes(kxmodes=[pskkxmodes]), \
                                    # TLS_Ext_KeyShare_CH(client_shares=[])
                                    ])]) #
            # MISSING from scapy repo example tls12 : gmt_unix_time, alcuni len parameters : namelen , servernameslen ....  , TLS_Ext_SessionTicket, TLS_Ext_NPN, TLS_Ext_ALPN, TLS_Ext_CSR


        except Exception as e:
            logging.log(40, "Error during client hello packet creation \n") 
            print(e)
            sys.exit(1)


        if not pubkeys:
            pubkeys = generateKeys(groups)
        
        for curve, pu_key in zip(list(groups), pubkeys):
            print(pu_key)
            ch_pk[TLSClientHello].ext[6].client_shares.append(KeyShareEntry(group=curve, key_exchange=pu_key, kxlen=len((pu_key))))


        # print(ch_pk['TLS'].show())

        ch_pk[TLS].len = len(raw(ch_pk[TLSClientHello]))
        ch_pk12[TLS].len = len(raw(ch_pk12[TLS]))
        # ch_pk12[TLS].msg[0].msglen = len(raw([ch_pk12[TLS].msg[0]]))
        ext_len = 0
        for e in ch_pk12[TLSClientHello].ext:
            ext_len += len(raw(e))
        ch_pk12[TLS].msg[0].extlen = ext_len

        ch_pk.show()

        return ch_pk




if __name__ == "__main__":  
     main()