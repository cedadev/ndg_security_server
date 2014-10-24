#!/bin/env python
import os, sys, base64
import urllib
from M2Crypto import X509, BIO, RSA
from sha import sha

class Client:
    def __init__(self, x509CertFilePath, priKeyFilePath, priKeyPwd):
        self.x509CertFilePath = x509CertFilePath
        
        self.priKeyFilePath = priKeyFilePath
        self.priKeyPwd = priKeyPwd
        
    def makeRequestURI(self, uri, securityToken):
        
        pwdCallback = lambda *ar, **kw: self.priKeyPwd
        priKey = RSA.load_key(self.priKeyFilePath, callback=pwdCallback)
        
        b64encSecurityToken = base64.urlsafe_b64encode(securityToken).strip()
                    
        tokenSignature = priKey.sign(securityToken)
        b64EncTokenSignature=base64.urlsafe_b64encode(tokenSignature).strip()
               
        # Make Cert DN
        x509Cert = X509.load_cert(self.x509CertFilePath)
        dn = x509Cert.get_subject().as_text()
        b64EncDN = base64.urlsafe_b64encode(dn).strip()
        
        # Combine together into URI
        return "%s?sessid=%s&tokSig=%s&dn=%s" % (uri,
                                                 b64encSecurityToken, 
                                                 b64EncTokenSignature,
                                                 b64EncDN)

    def request_GET(self, *args):
        uri = self.makeRequestURI(*args)
        print "Request is: %s" % uri
        print "Request length = %d" % len(uri)
        
        resrc = urllib.urlopen(uri)
        dat = resrc.read()
        return dat

        
         
if __name__ == "__main__":
    import getpass
    priKeyPwd = getpass.getpass(prompt="password for private key: ")
    
    import pdb;pdb.set_trace()
    if len(sys.argv) < 3:
	uri = "http://gabriel.bnsc.rl.ac.uk/cgi-bin/binDataServe.py"
    else:
	uri = sys.argv[3]

    securityToken = 'A Security Token' #os.urandom(8)
    
    clnt = Client(sys.argv[1], sys.argv[2], priKeyPwd)
    dat = clnt.request_GET(uri, securityToken)

    print dat
