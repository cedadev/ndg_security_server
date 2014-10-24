"""ESG Security SSL system tests

"""
__author__ = "P J Kershaw"
__date__ = "20/09/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S')
log = logging.getLogger(__name__)

import unittest
import traceback
import socket
from os import path
from ConfigParser import SafeConfigParser, NoOptionError

from OpenSSL import SSL


class SSLTestCaseConfigException(Exception):
    """Invalid Config file settings"""
    
    
class SSLTestCase(unittest.TestCase):
    """Test SSL endpoints in ESG federation"""
    THIS_DIR = path.dirname(path.abspath(__file__))
    INI_FILENAME = 'test_ssl.cfg'
    INI_FILEPATH = path.join(THIS_DIR, INI_FILENAME)
    
    def __init__(self, *arg, **kw):
        cfg = SafeConfigParser(defaults=dict(here=self.__class__.THIS_DIR))
        cfg.optionxform = str
        cfg.read(self.__class__.INI_FILEPATH)
        
        self.caCertDir = cfg.get('DEFAULT', 'caCertDir')
        self.endpoints = []
        for i in cfg.get('DEFAULT', 'endpoints').split():
            try:
                fqdn, port = i.split(':') 
            except ValueError:
                raise SSLTestCaseConfigException("Reading configuration file "
                                                 "%r - endpoints format is "
                                                 "<fqdn>:<portnum>", 
                                                 self.__class__.INI_FILEPATH)
            self.endpoints.append((fqdn, int(port)))
        
        try:
            self.ignoreCertExpiryErrors = cfg.getboolean('DEFAULT', 
                                                     'ignoreCertExpiryErrors')
        except NoOptionError:
            self.ignoreCertExpiryErrors = False
            
        self.ctx = SSL.Context(SSL.SSLv3_METHOD)
        self.ctx.load_verify_locations(None, self.caCertDir)
        self.ctx.set_verify_depth(9)
        
        def _callback(conn, x509, errorNum, errorDepth, preverifyOK):
            """OpenSSL Verification callback"""
            if errorNum == 10 and self.ignoreCertExpiryErrors:
                dn = x509.get_subject()
                log.warning("\"ignoreCertExpiryErrors\" flag set: ignoring "
                            "certificate expiry error number %d for "
                            "certificate %s", errorNum, dn)
                return True
                
            elif errorNum != 0:
                dn = x509.get_subject()
                log.error("Error number for certificate %s is %d", dn, errorNum)
                
            return preverifyOK
        
        self.ctx.set_verify(SSL.VERIFY_PEER, _callback)
        
        super(SSLTestCase, self).__init__(*arg, **kw)
    
    def _test_connection(self, endpoint):
        log.info('Probing %s:%d ...' % endpoint)

        conn = SSL.Connection(self.ctx, socket.socket())
        conn.connect(endpoint)
        try:
            conn.do_handshake()
        except SSL.Error:
            log.error("Handshake error for %r: %s" %
                      (endpoint, traceback.format_exc()))
            return False
            
        except socket.error:
            log.error("Socket error for %r: %s" %
                      (endpoint, traceback.format_exc()))
            return False
        
        return True
       
    def test01ValidPeerCerts(self):
        # Verify all peers have EECs issued by valid ESG CAs
        nFails = 0
        for i in self.endpoints:
            if not self._test_connection(i):
                nFails += 1

        self.failIf(nFails > 0, "%d connection failure(s)" % nFails)

    def test02HttpsEnforcedWhitelisting(self):
        # Check HTTPS endpoints have correct whitelisting enforced - expect
        # negative result as this client holds an invalid certificate
        pass
        
if __name__ == "__main__":
    unittest.main()
