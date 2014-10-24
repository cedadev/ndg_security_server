#!/usr/bin/env python
#
# Exampe echo client, to show extended code generation in ZSI
#
# Import the client proxy object
from Gatekeeper_services import GatekeeperBindingSOAP
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
GatekeeperPx = GatekeeperBindingSOAP("http://localhost:5000/GatekeeperServIn")#,
                                 #sig_handler=signatureHandler)

print GatekeeperPx.get("User X.509 Cert", 
                       "User Attribute Certificate", 
                       "Geoserver Request")

