#!/bin/env python
#
# How to build an echo server using the extended code generation
#

import sys

# Import the ZSI stuff you'd need no matter what
from ZSI.ServiceContainer import ServiceContainer

# This is a new method imported to show it's value
from ZSI.ServiceContainer import GetSOAPContext

# Import the generated Server Object
import SimpleCA_interface

# Create a Server implementation

# This using a derived server instead
class SimpleCAServIn(SimpleCA_interface.SimpleCAService):
    def __init__(self, post='', **kw):
        
        SimpleCA_interface.SimpleCAService.__init__(self, post, **kw)
        
        # Fudge to copy methods of this class so that equivalent 
        # SimpleCAService class WS stub picks it up
        self.impl = self
#        
#        
#    def sign(self, sw):
#        '''\
#        Overrides ServiceInterface class method to allow digital signature'''
#        self.signatureHandler.sign(sw)
#
#        
#    def verify(self, ps):
#        '''\
#        Overrides ServiceInterface class method to allow signature 
#        verification'''
#        self.signatureHandler.verify(ps)
        
    def encrypt(self, sw):
        pass
    
    def decrypt(self, ps):
        pass
        
    def authorize(self, auth_info, post, action):
        print "Authorizing INHERIT SimpleCA"
        ctx = GetSOAPContext()
        print dir(ctx)
        print "Container: ", ctx.connection
        print "Parsed SOAP: ", ctx.parsedsoap
        print "Container: ", ctx.container
        print "HTTP Headers:\n", ctx.httpheaders
        print "----"
        print "XML Data:\n", ctx.xmldata
        return 1

    def reqCert(self, input):
        #import pdb;pdb.set_trace()
        return 'SIGNED CERTIFICATE', 'OK'


# Here we set up the server
serviceContainer = ServiceContainer(('localhost', 5001))

# Create the Inherited version of the server
simpleCAsrv = SimpleCAServIn()
serviceContainer.setNode(simpleCAsrv, url="/SimpleCAServIn")

# Run the service container
try:
    serviceContainer.serve_forever()
except KeyboardInterrupt:
    sys.exit(0)
