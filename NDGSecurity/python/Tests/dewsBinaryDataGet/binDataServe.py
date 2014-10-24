#!/usr/local/NDG/bin/python

import cgi
import os, sys, base64
import urllib
from M2Crypto import X509, RSA
from sha import sha


class URISignatureHandler:
    def __init__(self, x509CertFilePath):
        self.x509CertFilePath = x509CertFilePath

    def verifyRequest(self):

        # Get cert
        x509Cert = X509.load_cert(self.x509CertFilePath)

        # Check DN
        dn = base64.urlsafe_b64decode(self['dn'].value)
        if dn != x509Cert.get_subject().as_text():
            raise "No matching cert DN for: " + dn

        # Check signature
        securityToken = base64.urlsafe_b64decode(self['sessid'].value)
        tokenSignature = base64.urlsafe_b64decode(self['tokSig'].value)
        pubKey = x509Cert.get_pubkey().get_rsa()
        try:
            verify = pubKey.verify(securityToken, tokenSignature)
        except RSA.RSAError, e:
            raise VerifyError, "Error in Signature: " + str(e)

        if not verify:
            raise "Signature is invalid"


class ServeDat(URISignatureHandler, cgi.FieldStorage):

    def __init__(self, *uriSignatureHandlerKw, **cgiKw):

        URISignatureHandler.__init__(self, *uriSignatureHandlerKw)

        # Read fields so that self becomes a dictionary of the fields
        cgi.FieldStorage.__init__(self, **cgiKw)

    def __call__(self):
        self.verifyRequest()

        print "Content-type: text/html\n"
        print """<html>
<head>
<title>Serve Data</title>
</script>
</head>
<body>
    <h1>Signature OK - Serving data</h1>
</body>
</html>"""


if __name__ == "__main__":
    cgi = ServeDat("/home/pjkersha/Development/security/python/Tests/webSphereTestcert.pem")
    cgi()
