#!/bin/env python
#
# Exampe echo client, to show extended code generation in ZSI
#
# Import the client proxy object
from SimpleCA_client import SimpleCABindingSOAP
import wsSecurity
#import pdb;pdb.set_trace()


priKeyPwd = open('../tmp2').read().strip()
certFilePath = '../Junk-cert.pem'
priKeyFilePath = '../Junk-key.pem'

# Signature handler object is passed to binding
signatureHandler = wsSecurity.SignatureHandler(certFilePath=certFilePath,
                                               priKeyFilePath=priKeyFilePath,
                                               priKeyPwd=priKeyPwd)

# Instantiate a client proxy object, then call it
simpleCAPx = SimpleCABindingSOAP("http://localhost:5001/SimpleCAServIn")#,
                                 #sig_handler=signatureHandler)

try:
    print simpleCAPx.reqCert("Test INHERIT String")
except Exception, e:
    print "Error calling certificate request: ", e

