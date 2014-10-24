#!/usr/bin/env python
#
# How to build an echo server using the extended code generation
#
import sys

# Import the ZSI stuff you'd need no matter what
from ZSI.ServiceContainer import ServiceContainer, SOAPRequestHandler

# This is a new method imported to show it's value
from ZSI.ServiceContainer import GetSOAPContext

# Import the generated Server Object
import EchoServer_interface

# Set security operation by request type
from EchoServer_messages import *

import wsSecurity

psBodyChildName = lambda ps: \
    ps.dom.childNodes[1].childNodes[1].childNodes[0].localName

priKeyPwd = None
certFilePath = '../webSphereTestcert.pem'
priKeyFilePath = '../webSphereTestkey.pem'

    
# Create a Server implementation

#_____________________________________________________________________________
class EchoSOAPRequestHandler(SOAPRequestHandler):
     """Add a do_GET method to return the WSDL on HTTP GET requests.
     Please note that the path to the wsdl file is derived from what
     the HTTP invocation delivers (which is put into the self.path
     attribute), so you might want to change this addressing scheme.
     """
     def do_GET(self):
         """Return the WSDL file."""         
         self.send_xml(EchoServer_interface.EchoServer._wsdl)
         
     def do_POST(self):
          """Fudge to get _Dispatch to pick up the correct address
          - seems to be necessary when putting proxy redirect for port in
          the wsdl e.g. http://glue.badc.rl.ac.uk/sessionMgr points to the
          default port for the Session Manager."""
          self.path = "/EchoServIn"
          SOAPRequestHandler.do_POST(self)
   
# This using a derived server instead
class EchoServIn(EchoServer_interface.EchoServer):
    def __init__(self, post='', **kw):
        EchoServer_interface.EchoServer.__init__(self, post, **kw)

        # Fudge to copy methods of this class so that equivalent 
        # SimpleCAService class WS stub picks it up
        self.impl = self
        
        self.signatureHandler = wsSecurity.SignatureHandler(\
                                    certFilePath=certFilePath,
                                    priKeyFilePath=priKeyFilePath,
                                    priKeyPwd=priKeyPwd)

        self.encryptionHandler = wsSecurity.EncryptionHandler(\
                                    certFilePath=certFilePath,
                                    priKeyFilePath=priKeyFilePath,
                                    priKeyPwd=priKeyPwd)
        
        
#    def sign(self, sw):
#        '''\
#        Overrides ServiceInterface class method to allow digital signature'''
#        if isinstance(self.request, EchoRequest):
#            # Echo response applies digital signature
#            self.signatureHandler.sign(sw)
#        
#    def verify(self, ps):
#        '''\
#        Overrides ServiceInterface class method to allow signature 
#        verification'''      
#        if isinstance(self.request, EchoRequest):
#            # Echo request checks digital signature
#            self.signatureHandler.verify(ps)

    def encrypt(self, sw):
        #if isinstance(self.request, EchoEncrRequest):
        # Assume EchoEncr response - apply encryption
        self.encryptionHandler.encrypt(sw)

            
    def decrypt(self, ps):
        if psBodyChildName(ps) == 'EncryptedData':
            # Assume EchoEncr request
            self.encryptionHandler.decrypt(ps)
        
#
#        
#    def authorize(self, auth_info, post, action):
#        print "Authorizing INHERIT Echo"
#        ctx = GetSOAPContext()
#        print dir(ctx)
#        print "Container: ", ctx.connection
#        print "Parsed SOAP: ", ctx.parsedsoap
#        print "Container: ", ctx.container
#        print "HTTP Headers:\n", ctx.httpheaders
#        print "----"
#        print "XML Data:\n", ctx.xmldata
#        return 1

    def Echo(self, input):
        return "Input message was: %s" % input

    def EchoEncr(self, input):
        return "Input secret was: %s" % input

# Here we set up the server
serviceContainer = ServiceContainer(('localhost', 7000),#7100),
                                    RequestHandlerClass=EchoSOAPRequestHandler)

# Create the TIE version of the server
#hws = EchoServer()
#hwsi = EchoServer_interface.EchoServer(impl=hws,
#                                       auth_method_name="authorize")
#serviceContainer.setNode(hwsi, url="/EchoServer")

# Create the Inherited version of the server
import sys
hws2 = EchoServIn(tracefile=sys.stdout)
serviceContainer.setNode(hws2, url="/EchoServIn")

try:
    # Run the service container
    serviceContainer.serve_forever()
except KeyboardInterrupt:
    sys.exit(0)
