
""" SSL Fuzzer """

__version__ = "0.0.1"
__author__ = "Diego Gobbetti"

"""
Ideally this is the main class, parses args form stdin, manipulates value,
creates connection and client hello message accordingly --> default to tls13, 
with the records in the serverHello reply from the server. pritn scan results 
fetching attributes of TLSScanner
"""


import logging
import TLSscanner, scan

LOGLEVELS = {"DEBUG" : 10, "INFO" : 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}



def log(message, level="INFO"):
    logging.log(LOGLEVELS[level], message)



