#!/usr/bin/env python
#
# Exampe echo client, to show extended code generation in ZSI
#
# Import the client proxy object
from EchoServer_client import EchoServerSOAP
import sys

import wsSecurity

# Lambda used by WS-Security handler to check which operation has been
# invoked
isEchoRequest = lambda sw: sw.body.node.childNodes[0].localName=='Echo'
isEchoEncrRequest = lambda sw: sw.body.node.childNodes[0].localName=='EchoEncr'

isEchoResponse = lambda ps: \
ps.dom.childNodes[1].childNodes[1].childNodes[0].localName == 'EchoResponse'
isEchoEncrResponse = lambda ps: \
ps.dom.childNodes[1].childNodes[1].childNodes[0].localName=='EchoEncrResponse'

class WSSEhandler:
    def __init__(self, sigHandler=None, encrHandler=None):
        self.sigHandler = sigHandler
        self.encrHandler = encrHandler
        
    def sign(self, sw):
        if self.sigHandler:
            self.sigHandler.sign(sw)
            
    def verify(self, ps):
        if self.sigHandler:
            self.sigHandler.verify(ps)
        
    def encrypt(self, sw):
        if self.encrHandler:
            self.encrHandler.encrypt(sw)
           
    def decrypt(self, ps):
        if self.encrHandler:
            self.encrHandler.decrypt(ps)


#priKeyPwd = open('../tmp2').read().strip()
#certFilePath = '../Junk-cert.pem'
#priKeyFilePath = '../Junk-key.pem'
priKeyPwd = None
certFilePath = '../webSphereTestcert.pem'
priKeyFilePath = '../webSphereTestkey.pem'

# Signature handler object is passed to binding
sigHandler = wsSecurity.SignatureHandler(certFilePath=certFilePath,
                                         priKeyFilePath=priKeyFilePath,
                                         priKeyPwd=priKeyPwd)

encrHandler = wsSecurity.EncryptionHandler(certFilePath=certFilePath,
                                           priKeyFilePath=priKeyFilePath,
                                           priKeyPwd=priKeyPwd)

# Test encryption only
#wsseHandler = WSSEhandler(sigHandler, encrHandler)
wsseHandler = WSSEhandler(encrHandler=encrHandler)
    
        
# Instantiate a client proxy object, then call it
#wsURL = "http://192.100.78.234:9081/EchoServiceWeb/services/EchoServer"
wsURL = "http://localhost:7000"
echoSrv = EchoServerSOAP(wsURL,
                         sig_handler=sigHandler,
                         encr_handler=encrHandler,
                         tracefile=sys.stdout)
try:
    #import pdb;pdb.set_trace()
    print echoSrv.Echo("Test String")
    #print echoSrv.EchoEncr("Test Secret")
except Exception, e:
    print "Failed to echo: ", e

