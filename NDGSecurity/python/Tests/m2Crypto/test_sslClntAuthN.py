#!/usr/bin/env python

#import socket, M2Crypto
#from M2Crypto import SSL
#from M2Crypto.httpslib import HTTPSConnection as _HTTPSConnection
#
#class VerifyCB(object):
#    def __init__(self, ca):
#        self.ca =ca
#        
#    def __call__(ok, store):
#        cert = store.get_current_cert()
#        mecert = M2Crypto.X509.load_cert(self.ca)
#        if mecert.get_fingerprint(md="sha1") == \
#            cert.get_fingerprint(md="sha1"):
#            return True
#        else:
#            return ok
#
#class HTTPSConnection(_HTTPSConnection):
#    # setting socket types
#    address_family = socket.AF_INET
#    socket_type = socket.SOCK_STREAM
# 
#    def __init__(self, *args, **kw):
#        _HTTPSConnection.__init__(self, *args, **kw)
#        self.server_address = server_address
#        self.connected = False
#        self.cert = kw.pop('certFilePath')
#        self.keyFilePath
#        self.ca = ca
# 
#    def connect(self):
#        cert = self.cert
#        certkey = self.certkey
#
#        # setup an SSL context.
#        context = SSL.Context("sslv23")
#        context.load_verify_locations(self.ca, "./")
#        
#        # setting verifying level
#        context.set_verify(SSL.verify_peer | SSL.verify_fail_if_no_peer_cert, 
#                           1,
#                           VerifyCB(self.ca))
#        
#        # load up certificate stuff.
#        context.load_cert(cert, certkey)
#        
#        # setting callback so we can monitor our SSL
#        context.set_info_callback()
#        
#        # create real socket
#        real_sock = socket.socket(self.address_family, self.socket_type)
#        connection = SSL.Connection(context, real_sock)
#        self.socket = connection
#        self.socket.connect(self.server_address)
#        self.connected = True
from ndg.security.common.utils.m2crypto import HTTPSConnection

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        from urlparse import urlparse
        url = urlparse(sys.argv[1])
        hostname = url.netloc
        path = url.path
    else:    
        hostname = 'gabriel.badc.rl.ac.uk'
        path = '/openid'
        
    con = HTTPSConnection(hostname, clntCertFilePath='./test.crt',
                          clntPriKeyFilePath='./test.key')
    con.putrequest('GET', path)
    con.endheaders()
    resp = con.getresponse()
    print resp.read()
