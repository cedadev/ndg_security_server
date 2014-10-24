#!/usr/bin/env python

"""WS-Security test client

NERC Data Grid Project

P J Kershaw 01/09/06

Copyright (C) 2009 Science and Technology Facilities Council

"""

__revision__ = '$Id$'

import sys, socket
from ZSI import Binding, TCcompound, TC
from wsInterface import *
import wsSecurity

MESSAGE = "Hello from Python!"

def main():
    
    priKeyPwd = open('../../tmp2').read().strip()
    certFilePath = '../../Junk-cert.pem'
    priKeyFilePath = '../../Junk-key.pem'
    
    # Signature handler object is passed to binding
    signatureHandler = wsSecurity.SignatureHandler(certFilePath=certFilePath,
                                                priKeyFilePath=priKeyFilePath,
                                                priKeyPwd=priKeyPwd)
    
    encryptionHandler = wsSecurity.EncryptionHandler(
                                                certFilePath=certFilePath,
                                                priKeyFilePath=priKeyFilePath,
                                                priKeyPwd=priKeyPwd)

    # Added in encr_handler keyword as a quick fudge - encr_handler.encrypt
    # gets called after sig_handler.sign and encr_handler.decrypt gets called
    # before sig_handler.verify
    #
    # Maybe there should be a generic handler keyword for signature and
    # encryption so that it can customised - sign then encrypt or encrypt
    # then sign or any other combination...
    binding = Binding(url='http://localhost:8080/wsServer.py',
                      #sig_handler=signatureHandler, [leave out whilst testing
                      # encryption]
                      encr_handler=encryptionHandler)
                 
    echoRequest = echoRequestWrapper()
    echoRequest._message = MESSAGE
    
    import pdb;pdb.set_trace()
    print ' Sending: %s' % MESSAGE
    
    try:
        binding.Send(None, 
                 'echo', 
                 echoRequest,
                 encodingStyle="http://schemas.xmlsoap.org/soap/encoding/")
    
        response = binding.Receive(echoResponseWrapper(), 
                 encodingStyle="http://schemas.xmlsoap.org/soap/encoding/")

    except socket.error, (errNum, errMsg):
        print >>sys.stderr, "Socket error: %s" % errMsg
        sys.exit(1)
        
    if not isinstance(response, echoResponse) and \
       not issubclass(echoResponse, response.__class__):
        print >>sys.stderr, "%s incorrect response type" % response.__class__
        sys.exit(1)

    print 'Response: %s' % response._message


if __name__ == '__main__':
    main()
