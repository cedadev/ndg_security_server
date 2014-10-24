#!/usr/bin/env python

"""WS-Security test server

NERC Data Grid Project

P J Kershaw 01/09/06

Copyright (C) 2009 Science and Technology Facilities Council

"""

__revision__ = '$Id$'

import sys
import socket

# Web service interface
from ZSI import *
from ZSI.dispatch import SOAPRequestHandler, _client_binding
from ZSI.auth import _auth_tc, AUTH, ClientBinding

from BaseHTTPServer import HTTPServer

from wsSecurity import *
from wsInterface import *


#_________________________________________________________________________
def echo(ps):
    """example service simply returns message sent to it"""
   
    request = ps.Parse(echoRequestWrapper)
    response = echoResponseWrapper()    
    response._message = request._message
    
    return response

def _Dispatch(ps, modules, SendResponse, SendFault, docstyle=0,
              nsdict={}, typesmodule=None, rpc=None, **kw):
    '''Find a handler for the SOAP request in ps; search modules.
    Call SendResponse or SendFault to send the reply back, appropriately.

    Default Behavior -- Use "handler" method to parse request, and return
       a self-describing request (w/typecode).

    Other Behaviors:
        docstyle -- Parse result into an XML typecode (DOM). Behavior, wrap result 
          in a body_root "Response" appended message.

        rpc -- Specify RPC wrapper of result. Behavior, ignore body root (RPC Wrapper)
           of request, parse all "parts" of message via individual typecodes.  Expect
           response pyobj w/typecode to represent the entire message (w/RPC Wrapper),
           else pyobj w/o typecode only represents "parts" of message.

    '''
    
    # WS-Security handler called here
#    signatureHandler = SignatureHandler(\
#                            certFilePath='../../Junk-cert.pem',
#                            priKeyFilePath='../../Junk-key.pem',
#                            priKeyPwd=open('../../tmp2').read().strip())
#    signatureHandler.verify(ps)
    # Test decryption
    encryptionHandler = EncryptionHandler(\
                            certFilePath='../../Junk-cert.pem',
                            priKeyFilePath='../../Junk-key.pem',
                            priKeyPwd=open('../../tmp2').read().strip())
    encryptionHandler.decrypt(ps)

    
    global _client_binding
    try:
        what = ps.body_root.localName

        # See what modules have the element name.
        if modules is None:
            modules = ( sys.modules['__main__'], )

        handlers = [ getattr(m, what) for m in modules if hasattr(m, what) ]
        if len(handlers) == 0:
            raise TypeError("Unknown method " + what)

        # Of those modules, see who's callable.
        handlers = [ h for h in handlers if callable(h) ]
        if len(handlers) == 0:
            raise TypeError("Unimplemented method " + what)
        if len(handlers) > 1:
            raise TypeError("Multiple implementations found: " + `handlers`)
        handler = handlers[0]

        _client_binding = ClientBinding(ps)
        if docstyle:
            result = handler(ps.body_root)
            tc = TC.XML(aslist=1, pname=what + 'Response')
        elif rpc is None:
            # Not using typesmodule, expect 
            # result to carry typecode
            result = handler(ps)
            if hasattr(result, 'typecode') is False:
                raise TypeError("Expecting typecode in result")
            tc = result.typecode
        else:
            data = _child_elements(ps.body_root)
            if len(data) == 0:
                arg = []
            else:
                try:
                    try:
                        type = data[0].localName
                        tc = getattr(typesmodule, type).typecode
                    except Exception, e:
                        tc = TC.Any()
                    arg = [ tc.parse(e, ps) for e in data ]
                except EvaluateException, e:
                    SendFault(FaultFromZSIException(e), **kw)
                    return
            result = handler(*arg)
            if hasattr(result, 'typecode'):
                tc = result.typecode
            else:
                tc = TC.Any(aslist=1, pname=what + 'Response')
                result = [ result ]

                
        sw = SoapWriter(nsdict=nsdict)
        
        sw.serialize(result, tc, rpc=rpc)
         
        # Test encryption handler independently of signature       
#        signatureHandler = SignatureHandler(\
#                                certFilePath='../../Junk-cert.pem',
#                                priKeyFilePath='../../Junk-key.pem',
#                                priKeyPwd=open('../../tmp2').read().strip())
#        signatureHandler.sign(sw)
        encryptionHandler = EncryptionHandler(\
                                certFilePath='../../Junk-cert.pem',
                                priKeyFilePath='../../Junk-key.pem',
                                priKeyPwd=open('../../tmp2').read().strip())
        encryptionHandler.encrypt(sw)
        
        return SendResponse(str(sw), **kw)
    
    except Exception, e:
        # Something went wrong, send a fault.
        return SendFault(FaultFromException(e, 0, sys.exc_info()[2]), **kw)

#_____________________________________________________________________________
class EchoSOAPRequestHandler(SOAPRequestHandler):
    """Implement to allow overloaded do_POST in order to handle WS-Security
    for outbound messages"""
 
    def do_POST(self):
        """Override default to allow custom dispatch call"""
        try:
            ct = self.headers['content-type']
            if ct.startswith('multipart/'):
                cid = resolvers.MIMEResolver(ct, self.rfile)
                xml = cid.GetSOAPPart()
                ps = ParsedSoap(xml, resolver=cid.Resolve)
            else:
                length = int(self.headers['content-length'])
                ps = ParsedSoap(self.rfile.read(length))
        except ParseException, e:
            self.send_fault(FaultFromZSIException(e))
            return
        except Exception, e:
            # Faulted while processing; assume it's in the header.
            self.send_fault(FaultFromException(e, 1, sys.exc_info()[2]))
            return
        
        _Dispatch(ps, self.server.modules, self.send_xml, self.send_fault,
                  docstyle=self.server.docstyle, nsdict=self.server.nsdict,
                  typesmodule=self.server.typesmodule, rpc=self.server.rpc)


#_____________________________________________________________________________
def AsServer(port=80, 
             modules=None, 
             docstyle=0, 
             nsdict={}, 
             typesmodule=None,
             rpc=None,
             **kw):
    
    address = ('', port)
    httpd = HTTPServer(address, EchoSOAPRequestHandler)
    httpd.modules = modules
    httpd.docstyle = docstyle
    httpd.nsdict = nsdict
    httpd.typesmodule = typesmodule
    httpd.rpc = rpc
    httpd.serve_forever()


if __name__ == '__main__':
    print "Server listening ..."

    try:
        AsServer(port=8080)

    except KeyboardInterrupt:
        sys.exit(0)

    except socket.error, e:
        print >>sys.stderr, "Server socket error: %s" % e[1]
        sys.exit(1)

#    except Exception, e:
#        print >>sys.stderr, "Server: %s" % e
#        sys.exit(1)
