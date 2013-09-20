#!/usr/bin/env python
"""PyOpenSSL HTTPSConnection wrapper unit test package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "17/03/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import unittest
import logging
logging.basicConfig(level=logging.DEBUG)
from OpenSSL import SSL
from webob import Response, dec
from ndg.security.test.unit import BaseTestCase
from ndg.security.common.utils.pyopenssl import (HTTPSConnection, 
                                                 urllib2_build_opener)


class TestHTTPSConnection(BaseTestCase):
    """Test PyOpenSSL based HTTPSConnection class and associated custom urllib2
    builder opener
    """
    HOSTNAME = 'localhost'
    PORTNUM = 8443
    PATH = '/'
    URI = 'https://%s:%s%s' % (HOSTNAME, PORTNUM, PATH)
    
    def __init__(self, *arg, **kw):
        super(TestHTTPSConnection, self).__init__(*arg, **kw)
        
        # Add a noddy HTTPS app to test against
        @dec.wsgify
        def XtestApp(request):
            return Response('TestHTTPSConnection Unit Test: Test App')
        
        def testApp(environ, start_response):
            status = response = '200 OK'
            start_response(status,
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
            return [response]
        
        self.addService(app=testApp, withSSL=True, port=self.__class__.PORTNUM)

    def test00M2Crypto(self):
        # Comparison test with M2Crypto
        try:
            from M2Crypto.m2urllib2 import build_opener
        except ImportError, e:
            print('M2Crypto not available, skipping test: %s' % e)
            
        opener = build_opener()
        res = opener.open(self.__class__.URI)
        print("_"*80)
        print(res.read())
              
    def test01HTTPSConnection(self):
        httpsConn = HTTPSConnection(self.__class__.HOSTNAME, 
                                    port=self.__class__.PORTNUM)
        httpsConn.connect()
        httpsConn.putrequest('GET', self.__class__.PATH)
        httpsConn.endheaders()
        resp = httpsConn.getresponse()
        httpsConn.close()
        print resp.read()
        
    def test02Urllib2CustomBuilderOpener(self):
        cert = None
        ctx = SSL.Context(SSL.SSLv3_METHOD)
#        ctx.add_extra_chain_cert(cert)
        opener = urllib2_build_opener()
        resp2 = opener.open(self.__class__.URI)
        print("_"*80)
        print(resp2.read())


if __name__ == "__main__":
    unittest.main()