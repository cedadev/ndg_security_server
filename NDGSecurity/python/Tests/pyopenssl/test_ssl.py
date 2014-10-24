import unittest
import socket
from OpenSSL import SSL


class SSLTestCase(unittest.TestCase):
    def test01(self):
        addr = ('localhost', 7443)
        caDir = '/home/pjkersha/workspace/ndg_security_python/ndg_security_test/ndg/security/test/config/ca'
        
        ctx = SSL.Context(SSL.SSLv3_METHOD)
        ctx.load_verify_locations(None, caDir)
        ctx.set_verify_depth(9)
        def _callback(conn, x509, errnum, errdepth, ok):
            return ok
        
        ctx.set_verify(SSL.VERIFY_PEER, _callback)
#        ctx.set_verify(SSL.VERIFY_NONE, _callback)
        print "Verify mode = %d" % ctx.get_verify_mode()
        conn = SSL.Connection(ctx, socket.socket())
        conn.connect(addr)
        conn.do_handshake()
        
        
if __name__ == "__main__":
    unittest.main()