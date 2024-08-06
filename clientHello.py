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
    - prn or lower method should return a tls package crafted with the responses    
"""



import socket, sys
import logging

from scapy import sendrecv
from scapy.all import sniff, hexdump, import_hexcap, AsyncSniffer, SuperSocket
from scapy.layers.tls.all import *
from scapy.layers.tls.crypto import groups as curves
from scapy.layers.inet import * # IP, TCP

from cryptography.hazmat.primitives.asymmetric import *
import scapy.supersocket


    
CIPHERS = [4866,4867,4865,49196,49200,159,52393,52392,52394,49195,49199,158,49188,49192,107,49187,49191,103,49162,49172,57,49161,49171,51,157,156,61,60,53,47,255]
SUPP_CV = [24, 23, 22, 21, 29]
SIGN_ALGS = [1027,1283,1539,2055,2056,2057,2058,2059,2052,2053,2054,1025,1281,1537]

sock = SuperSocket(family=socket.AF_INET,type=socket.SOCK_STREAM) 
srv_rs = []

def main():
     
        sock.ins.bind(("192.168.1.46", 5898))
        dstip=socket.gethostbyname("www.w3schools.com")
        sock.ins.connect((dstip, 443))      
        print(dstip)
        # sock = socket.create_connection((dstip, 443))

        ch_pk = clientHello()

        srv_name = sock.ins.getpeername()
        print(srv_name)

        sniffer = AsyncSniffer(prn=handleServerHello, session=TLSSession, iface="en0", store=False, filter=f"src host {dstip}") # 

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
                            print(f"Cipher spec request received \n. Cipher requested : {srv_hello['TLS'].msg[0].ciphers[0]} ")
            else:
                print("not expected pkg received")

                
        except:
            pass
    




def generateKeys(groups):
        pubks_list =[]
        for curve in groups:
           # if(curve=="0xaaaa"):
            #    private_key = x25519.X25519PrivateKey.generate()# per ora  non salviamo chiave priv
            try:
                pv_key = ec.generate_private_key(ec._CURVE_TYPES[curves._tls_named_curves.items()[curve]])
                pu_key = pv_key.public_key()
            except:
                pv_key = x25519.X25519PrivateKey.generate()
                pu_key = pv_key.public_key()

            print(pu_key)
            pu_key_pem = pu_key.public_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
            print(pu_key_pem.decode())
            print(pu_key_pem)
            print(len(pu_key_pem))
            
            pubks_list.append(pu_key_pem)
        
        return pubks_list

            
            

def clientHello(version=772, ciphers=CIPHERS, groups=SUPP_CV, sign_algs=SIGN_ALGS, pubkeys=None, servername=None, pskkxmodes=1):
        try:
            ch_pk = TLS(version=771, type=22)/\
                    TLSClientHello(version=771, ciphers=ciphers, ext=[ \
                                    TLS_Ext_SupportedGroups(groups=groups), TLS_Ext_SignatureAlgorithms(sig_algs=sign_algs), \
                                    TLS_Ext_SupportedVersion_CH(versions=[version]), TLS_Ext_PSKKeyExchangeModes(kxmodes=[pskkxmodes]), \
                                        TLS_Ext_KeyShare_CH(client_shares=[])
                                    ])
        except Exception as e:
            logging.log(40, "Error during client hello packet creation \n") 
            print(e)
            sys.exit(1) 

        ch_pk[TLS].len = len(raw(ch_pk[TLSClientHello]))
            
        """
        if not pubkeys:
            pubkeys = generateKeys(groups)
        
        for curve, pu_key in zip(list(groups), pubkeys):
            ch_pk[TLSClientHello].ext[4].client_shares.append(KeyShareEntry(group=curve, key_exchange=pu_key, len=len(pu_key)))
        """
        return ch_pk


if __name__ == "__main__":  
     main()