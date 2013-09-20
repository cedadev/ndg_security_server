#!/usr/bin/env python
"""Unit tests for WSGI Authentication redirect handler

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "23/02/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging


import unittest
import os
import sys
import getpass
import re
import base64
import urllib2

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_COMBINED_SRVS_UNITTEST_DIR'], 
                             file)

import paste.fixture
from paste.deploy import loadapp
from ndg.security.test.unit import BaseTestCase
from ndg.security.common.X509 import X509Cert
from ndg.security.server.wsgi.ssl import AuthKitSSLAuthnMiddleware


class TestAuthnApp(object):
    '''Test Application for the Authentication handler to protect'''
    response = "Test Authentication redirect application"
    
    loggedIn = lambda self, environ: 'username' in environ.get(
                                                self.beakerSessionKeyName, {})
    
    def __init__(self, app_conf, **local_conf):
        self.beakerSessionKeyName = app_conf.get('beakerSessionKeyName')
    
    def __call__(self, environ, start_response):
        
        if environ['PATH_INFO'] == '/test_401WithNotLoggedIn':
            status = "401 Unauthorized"
            
        elif environ['PATH_INFO'] == '/test_401WithLoggedIn':
            status = "401 Unauthorized"
            
        elif environ['PATH_INFO'] == '/test_200WithNotLoggedIn':
            status = "200 OK"
            
        elif environ['PATH_INFO'] == '/test_200WithLoggedIn':
            environ['REMOTE_USER'] = 'testuser'
            status = "200 OK"
        
        elif environ['PATH_INFO'] == '/test_sslClientAuthn':
            if self.loggedIn(environ):
                status = "200 OK"
            else:
                status = "401 Unauthorized"
        else:
            status = "404 Not found"
                
        start_response(status,
                       [('Content-length', 
                         str(len(TestAuthnApp.response))),
                        ('Content-type', 'text/plain')])
        return [TestAuthnApp.response]


class WSGIAuthNTestController(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        here_dir = os.path.dirname(os.path.abspath(__file__))
        wsgiapp = loadapp('config:test.ini', relative_to=here_dir)
        self.app = paste.fixture.TestApp(wsgiapp)
         
        unittest.TestCase.__init__(self, *args, **kwargs)
        
    def test01Catch401WithNotLoggedIn(self):
        response = self.app.get('/test_401WithNotLoggedIn', status=302)
        redirectResponse = response.follow(status=404)
        
    def test02Skip200WithLoggedIn(self):
        response = self.app.get('/test_200WithLoggedIn',
                                extra_environ={'REMOTE_USER': 'testuser'},
                                status=200)
        print(response.body)

    def test03Catch401WithLoggedIn(self):
        response = self.app.get('/test_401WithLoggedIn', 
                                extra_environ={'REMOTE_USER': 'testuser'},
                                status=401)
        print(response.body)
        
    def test04Catch200WithNotLoggedIn(self):
        response = self.app.get('/test_200WithNotLoggedIn', status=200)


class WsgiSSLClientAuthnTestController(BaseTestCase):
    """Extend Authentication middleware test to use SSL Client Authentication
    middleware"""
    
    def __init__(self, *arg, **kw):
        here_dir = os.path.dirname(os.path.abspath(__file__))
        wsgiapp = loadapp('config:ssl-test.ini', relative_to=here_dir)
        self.app = paste.fixture.TestApp(wsgiapp)
         
        BaseTestCase.__init__(self, *arg, **kw)
        
    def test01(self):
        thisDir = os.path.dirname(__file__)
        sslClientCertFilePath = os.path.join(
                                os.environ[BaseTestCase.configDirEnvVarName],
                                'pki',
                                'test.crt')
        sslClientCert = X509Cert.Read(sslClientCertFilePath).toString()
        
        # Add APache SSL environment variables and sdummy AuthKit set user
        # session cookie method
        extra_environ = {
            'HTTPS':'1', 
            'SSL_CLIENT_CERT': sslClientCert,
            AuthKitSSLAuthnMiddleware.SET_USER_ENVIRON_KEYNAME: lambda id: None
            }

        print("request secured URI '/test_sslClientAuthn' ...")
        response = self.app.get('/test_sslClientAuthn',
                                extra_environ=extra_environ,
                                status=302)
        
        print("Redirect to SSL Client Authentication endpoint %r ..." %
              response.header_dict['location'])
        
        # Redirect to SSL Client Authentication endpoint
        redirectResponse = response.follow(extra_environ=extra_environ,
                                           status=302)

        print("Redirect back to secured URI with authenticated session %r ..."%
              redirectResponse.header_dict['location'])
        
        finalResponse = redirectResponse.follow(extra_environ=extra_environ,
                                                status=200)
        print finalResponse
        
    
if __name__ == "__main__":
    unittest.main()        
