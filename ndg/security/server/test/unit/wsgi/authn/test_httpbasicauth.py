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

import unittest
import urllib.request, urllib.error, urllib.parse
import base64
import paste.fixture
from paste.httpexceptions import HTTPUnauthorized

from ndg.security.server.test.base import BaseTestCase
from ndg.security.server.wsgi.httpbasicauth import HttpBasicAuthMiddleware
    

class TestAuthnApp(object):
    '''Test Application for the Authentication handler to protect'''
    response = b"Test HTTP Basic Authentication application"
    
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


class HttpBasicAuthPluginMiddleware(object):
    USERNAME = b'testuser'
    PASSWORD = b'password'
    
    def __init__(self, app):
        self._app = app
        
    def __call__(self, environ, start_response):
        def authenticate(environ, username, password):
            if username == HttpBasicAuthPluginMiddleware.USERNAME and \
               password == HttpBasicAuthPluginMiddleware.PASSWORD:
                return
            else:
                raise HTTPUnauthorized("Invalid credentials")
            
        environ['authenticate'] = authenticate
        return self._app(environ, start_response)
    
    
class HttpBasicAuthMiddlewareTestCase(BaseTestCase):
    SERVICE_PORTNUM = 10443
    
    def __init__(self, *args, **kwargs):
        app = TestAuthnApp({})
        app = HttpBasicAuthMiddleware.filter_app_factory(app, {}, prefix='',
                                      authnFunc='authenticate')
        self.wsgiapp = HttpBasicAuthPluginMiddleware(app)
        
        self.app = paste.fixture.TestApp(self.wsgiapp)
         
        BaseTestCase.__init__(self, *args, **kwargs)

    def test01PasteFixture(self):
        username = HttpBasicAuthPluginMiddleware.USERNAME
        password = HttpBasicAuthPluginMiddleware.PASSWORD
        
        base64String = base64.encodestring(b'%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        headers = {'Authorization': authHeader}

        url = '/test_200'
        
        response = self.app.get(url, headers=headers, status=200)
        print(response)
            

if __name__ == "__main__":
    unittest.main()