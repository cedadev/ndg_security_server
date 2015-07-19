#!/usr/bin/env python
"""Unit tests for WSGI SSL Client Authentication Middleware

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "22/05/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import unittest
import os

import paste.fixture
from paste.deploy import loadapp
from OpenSSL import crypto

from ndg.security.server.test.base import CONFIG_DIR_ENVVARNAME


class TestSSLClientAuthnApp(BaseTestCase):
    '''Test Application for the Authentication handler to protect'''
    response = "Test Authentication redirect application"
       
    def __init__(self, app_conf, **local_conf):
        pass
    
    def __call__(self, environ, start_response):
        
        if environ['PATH_INFO'] == '/secured/uri':
            status = "200 OK"
            
        elif environ['PATH_INFO'] == '/unsecured':
            status = "200 OK"
            
        elif environ['PATH_INFO'] == '/test_200WithNotLoggedIn':
            status = "200 OK"
            
        elif environ['PATH_INFO'] == '/test_200WithLoggedIn':
            environ['REMOTE_USER'] = 'testuser'
            status = "200 OK"
        else:
            status = "404 Not found"
                
        start_response(status,
                       [('Content-length', 
                         str(len(TestSSLClientAuthnApp.response))),
                        ('Content-type', 'text/plain')])
        return [TestSSLClientAuthnApp.response]


class SSLClientAuthNTestCase(BaseTestCase):

    def __init__(self, *args, **kwargs):
        here_dir = os.path.dirname(os.path.abspath(__file__))
        wsgiapp = loadapp('config:test.ini', relative_to=here_dir)
        self.app = paste.fixture.TestApp(wsgiapp)
         
        BaseTestCase.__init__(self, *args, **kwargs)
        

    def test01NotAnSSLRequest(self):
        # This request should be ignored because the SSL environment settings
        # are not present
        response = self.app.get('/unsecured')
    
    def test02NoClientCertSet(self):
        extra_environ = {'HTTPS':'1'}
        response = self.app.get('/secured/uri',
                                extra_environ=extra_environ,
                                status=401)
    
    def test03ClientCertSet(self):
        sslClientCertFilePath = os.path.join(
                                os.environ[CONFIG_DIR_ENVVARNAME],
                                'pki',
                                'local.crt')
        
        with open(sslClientCertFilePath) as ssl_cert_file:
            ssl_client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                                      ssl_cert_file.read())
            
        extra_environ = {'HTTPS':'1', 'SSL_CLIENT_CERT': ssl_client_cert}
        response = self.app.get('/secured/uri',
                                extra_environ=extra_environ,
                                status=200)


if __name__ == "__main__":
    unittest.main()        
