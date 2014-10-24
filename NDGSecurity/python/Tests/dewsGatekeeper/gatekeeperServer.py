#!/usr/bin/env python
#
# How to build an echo server using the extended code generation
#

import sys

# Import the ZSI stuff you'd need no matter what
from ZSI.ServiceContainer import ServiceContainer

# This is a new method imported to show it's value
from ZSI.ServiceContainer import GetSOAPContext

# Import the generated Server Object
from Gatekeeper_services_server import GatekeeperService

# Create a Server implementation

# This using a derived server instead
class GatekeeperServIn(GatekeeperService):
    def __init__(self, post='', **kw):
        
        GatekeeperService.__init__(self, post, **kw)
        
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
        
    def authorize(self, auth_info, post, action):
        print "Authorizing INHERIT Gatekeeper"
        ctx = GetSOAPContext()
        print dir(ctx)
        print "Container: ", ctx.connection
        print "Parsed SOAP: ", ctx.parsedsoap
        print "Container: ", ctx.container
        print "HTTP Headers:\n", ctx.httpheaders
        print "----"
        print "XML Data:\n", ctx.xmldata
        return 1

    def soap_get(self, ps, **kw):
        #import pdb;pdb.set_trace()
        response = GatekeeperService.soap_get(self, ps)
        response._geoServerResponse = 'Geoserver Response'
        return response 


# Here we set up the server
serviceContainer = ServiceContainer(('localhost', 5000))

# Create the Inherited version of the server
Gatekeepersrv = GatekeeperServIn()
serviceContainer.setNode(Gatekeepersrv, url="/GatekeeperServIn")

# Run the service container
try:
    serviceContainer.serve_forever()
except KeyboardInterrupt:
    sys.exit(0)
