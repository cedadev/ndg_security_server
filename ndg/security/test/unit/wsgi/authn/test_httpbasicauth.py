#!/usr/bin/env python
"""Unit tests for WSGI HTTP Basic Auth handler

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "13/10/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)

import urllib2
import base64
import paste.fixture
from ndg.security.test.unit import BaseTestCase
from ndg.security.server.wsgi.authn import HTTPBasicAuthMiddleware, \
    HTTPBasicAuthUnauthorized


class TestAuthnApp(object):
    '''Test Application for the Authentication handler to protect'''
    response = "Test HTTP Basic Authentication application"
    
    def __init__(self, app_conf, **local_conf):
        pass
        
    def __call__(self, environ, start_response):
        
        if environ['PATH_INFO'] == '/test_200':
            status = "200 OK"
        else:
            status = "404 Not found"
                
        start_response(status,
                       [('Content-length', 
                         str(len(TestAuthnApp.response))),
                        ('Content-type', 'text/plain')])
        return [TestAuthnApp.response]


class HTTPBasicAuthPluginMiddleware(object):
    USERNAME = 'testuser'
    PASSWORD = 'password'
    
    def __init__(self, app):
        self._app = app
        
    def __call__(self, environ, start_response):
        def authenticate(environ, username, password):
            if username == HTTPBasicAuthPluginMiddleware.USERNAME and \
               password == HTTPBasicAuthPluginMiddleware.PASSWORD:
                return
            else:
                raise HTTPBasicAuthUnauthorized("Invalid credentials")
            
        environ['authenticate'] = authenticate
        return self._app(environ, start_response)
    
    
class HTTPBasicAuthMiddlewareTestCase(BaseTestCase):
    SERVICE_PORTNUM = 10443
    WGET_CMD = 'wget'
    WGET_USER_OPTNAME = '--http-user'
    WGET_PASSWD_OPTNAME = '--http-password'
    WGET_OUTPUT_OPTNAME = '--output-document'
    WGET_STDOUT = '-'
    
    def __init__(self, *args, **kwargs):
        app = TestAuthnApp({})
        app = HTTPBasicAuthMiddleware(app, {}, prefix='',
                                               authnFunc='authenticate')
        self.wsgiapp = HTTPBasicAuthPluginMiddleware(app)
        
        self.app = paste.fixture.TestApp(self.wsgiapp)
         
        BaseTestCase.__init__(self, *args, **kwargs)

    def test01PasteFixture(self):
        username = HTTPBasicAuthPluginMiddleware.USERNAME
        password = HTTPBasicAuthPluginMiddleware.PASSWORD
        
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        headers = {'Authorization': authHeader}

        url = '/test_200'
        
        response = self.app.get(url, headers=headers, status=200)
        print response
        
    def test02Urllib2Client(self):
        # Thread separate Paster based service 
        self.addService(app=self.wsgiapp, 
                        port=HTTPBasicAuthMiddlewareTestCase.SERVICE_PORTNUM)
        
        username = HTTPBasicAuthPluginMiddleware.USERNAME
        password = HTTPBasicAuthPluginMiddleware.PASSWORD
        url = 'http://localhost:%d/test_200' % \
            HTTPBasicAuthMiddlewareTestCase.SERVICE_PORTNUM
            
        req = urllib2.Request(url)
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        req.add_header("Authorization", authHeader)
        
        handle = urllib2.urlopen(req)
        
        response = handle.read()
        print (response)
        
    def test03WGetClient(self):
        uri = ('http://localhost:%d/test_200' % 
                  HTTPBasicAuthMiddlewareTestCase.SERVICE_PORTNUM)
                  
        username = HTTPBasicAuthPluginMiddleware.USERNAME
        password = HTTPBasicAuthPluginMiddleware.PASSWORD
        
        import os
        import subprocess
        cmd = "%s %s %s=%s %s=%s %s=%s" % (
            HTTPBasicAuthMiddlewareTestCase.WGET_CMD, 
            uri,
            HTTPBasicAuthMiddlewareTestCase.WGET_USER_OPTNAME,
            username,
            HTTPBasicAuthMiddlewareTestCase.WGET_PASSWD_OPTNAME,
            password,
            HTTPBasicAuthMiddlewareTestCase.WGET_OUTPUT_OPTNAME,
            HTTPBasicAuthMiddlewareTestCase.WGET_STDOUT)
        
        p = subprocess.Popen(cmd, shell=True)
        status = os.waitpid(p.pid, 0)
        self.failIf(status[-1] != 0, "Expecting 0 exit status for %r" % cmd)


if __name__ == "__main__":
    unittest.main()