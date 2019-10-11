#!/usr/bin/env python
"""Unit tests for WSGI Authorization handler

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/05/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
import os
from urllib.parse import urlunsplit

from os import path
from configparser import SafeConfigParser

from uuid import uuid4
from datetime import datetime, timedelta

import paste.fixture
from paste.deploy import loadapp

from ndg.saml.saml2.core import (SAMLVersion, Subject, NameID, Issuer, 
                                 AuthzDecisionStatement, Status, StatusCode, 
                                 StatusMessage, DecisionType, Action, 
                                 Conditions, Assertion)

from ndg.security.server.test.base import BaseTestCase
from ndg.security.server.test.test_util import TestUserDatabase
from ndg.security.server.wsgi import NDGSecurityMiddlewareBase
from ndg.security.server.wsgi.authz.result_handler.basic import \
    PEPResultHandlerMiddleware


class TestAuthorisationServiceMiddleware(object):
    """Test Authorisation Service interface stub"""
    QUERY_INTERFACE_KEYNAME_OPTNAME = 'queryInterfaceKeyName'
    RESOURCE_URI = 'http://localhost/dap/data/'
    ISSUER_DN = '/O=Test/OU=Authorisation/CN=Service Stub'
    
    def __init__(self, app, global_conf, **app_conf):
        self.queryInterfaceKeyName = app_conf[
            self.__class__.QUERY_INTERFACE_KEYNAME_OPTNAME]
        self._app = app
    
    def __call__(self, environ, start_response):
        environ[self.queryInterfaceKeyName] = self.authzDecisionQueryFactory()
        return self._app(environ, start_response)
    
    def authzDecisionQueryFactory(self):
        """Makes the authorisation decision"""
        
        def authzDecisionQuery(query, response):
            """Authorisation Decision Query interface called by the next 
            middleware in the stack the SAML SOAP Query interface middleware 
            instance
            (ndg.saml.saml2.binding.soap.server.wsgi.queryinterface.SOAPQueryInterfaceMiddleware)
            """
            now = datetime.utcnow()
            response.issueInstant = now
            
            # Make up a request ID that this response is responding to
            response.inResponseTo = query.id
            response.id = str(uuid4())
            response.version = SAMLVersion(SAMLVersion.VERSION_20)
            
            response.status = Status()
            response.status.statusCode = StatusCode()
            response.status.statusCode.value = StatusCode.SUCCESS_URI
            response.status.statusMessage = StatusMessage()        
            response.status.statusMessage.value = \
                                                "Response created successfully"
               
            assertion = Assertion()
            assertion.version = SAMLVersion(SAMLVersion.VERSION_20)
            assertion.id = str(uuid4())
            assertion.issueInstant = now
            
            authzDecisionStatement = AuthzDecisionStatement()
            
            # Make some simple logic to simulate a full access policy
            if query.resource == self.__class__.RESOURCE_URI:
                if query.actions[0].value == Action.HTTP_GET_ACTION:
                    authzDecisionStatement.decision = DecisionType.PERMIT
                else:
                    authzDecisionStatement.decision = DecisionType.DENY
            else:
                authzDecisionStatement.decision = DecisionType.INDETERMINATE
                
            authzDecisionStatement.resource = query.resource
                
            authzDecisionStatement.actions.append(Action())
            authzDecisionStatement.actions[-1].namespace = Action.GHPP_NS_URI
            authzDecisionStatement.actions[-1].value = Action.HTTP_GET_ACTION
            assertion.authzDecisionStatements.append(authzDecisionStatement)
            
            # Add a conditions statement for a validity of 8 hours
            assertion.conditions = Conditions()
            assertion.conditions.notBefore = now
            assertion.conditions.notOnOrAfter = now + timedelta(seconds=60*60*8)
                   
            assertion.subject = Subject()  
            assertion.subject.nameID = NameID()
            assertion.subject.nameID.format = query.subject.nameID.format
            assertion.subject.nameID.value = query.subject.nameID.value
                
            assertion.issuer = Issuer()
            assertion.issuer.format = Issuer.X509_SUBJECT
            assertion.issuer.value = \
                                    TestAuthorisationServiceMiddleware.ISSUER_DN
    
            response.assertions.append(assertion)
            return response
        
        return authzDecisionQuery


class RedirectFollowingAccessDenied(PEPResultHandlerMiddleware):
    """Test implementation demonstrates how handler middleware can be extended
    to set a redirect response following an access denied decision"""
    
    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):

        queryString = environ.get('QUERY_STRING', '')
        if 'admin=1' in queryString:
            # User has been rejected access to a URI requiring admin rights,
            # try redirect to the same URI minus the admin query arg, this
            # request will pass because admin rights aren't needed
            queryArgs = queryString.split('&')
            queryList = [arg for arg in queryArgs if arg != 'admin=1']
            editedQuery = '&'.join(queryList)
            redirectURI = urlunsplit(('', '', self.pathInfo, editedQuery, ''))
            return self.redirect(redirectURI)
        else:
            return super(RedirectFollowingAccessDenied, self).__call__(
                                                                environ,
                                                                start_response)


class TestAuthZMiddleware(object):
    '''Test Application for the Authentication handler to protect'''
    RESPONSE = b"Test Authorization application"
       
    def __init__(self, app_conf, **local_conf):
        pass
    
    def __call__(self, environ, start_response):
        response = self.__class__.RESPONSE
        if environ['PATH_INFO'] == '/test_401':
            status = "401 Unauthorized"
            
        elif environ['PATH_INFO'] == '/test_403':
            status = "403 Forbidden"
            
        elif environ['PATH_INFO'] == '/test_200':
            status = "200 OK"
            
        elif environ['PATH_INFO'] == '/test_accessDeniedToSecuredURI':
            # Nb. AuthZ middleware should intercept the request and bypass this
            # response
            status = "200 OK"
            
        elif environ['PATH_INFO'] == '/test_accessGrantedToSecuredURI':
            status = "200 OK"
            
        elif environ['PATH_INFO'] == '/esgf-attribute-value-restricted':
            status = "200 OK"
            
        elif environ['PATH_INFO'].startswith('/layout'):
            status = "200 OK"
            response += (b"\n\nAny calls to this path or sub-path should be "
                         b"publicly accessible")
        else:
            status = "404 Not found"
                
        start_response(status,
                       [('Content-length', 
                         str(len(response))),
                        ('Content-type', 'text/plain')])
        
        return [
            TestAuthZMiddleware.RESPONSE + b' returned: ' + \
            status.encode('utf-8')]


class BeakerSessionStub(dict):
    """Emulate beaker.session session object for purposes of the unit tests
    """
    def save(self):
        pass


class BaseAuthzFilterTestCase(BaseTestCase):
    """Base class for NDG Security WSGI authorisation filters
    """
    INI_FILE = 'saml-test.ini'
    THIS_DIR = path.dirname(path.abspath(__file__))
    INI_FILEPATH = None # Set in __init__ to enable derived classes to alter
    SESSION_KEYNAME = 'beaker.session.ndg.security'
    OPENID_URI = TestUserDatabase.OPENID_URI
    
    def __init__(self, *args, **kwargs):   
        """Test the authorisation filter using Paste fixture and set up 
        Authorisation and Attribute Services needed for making authorisation 
        decisions
        """   
        BaseTestCase.__init__(self, *args, **kwargs)
        
        self.__class__.INI_FILEPATH = os.path.join(self.__class__.THIS_DIR, 
                                                   self.__class__.INI_FILE)
 
        wsgiapp = loadapp('config:'+self.__class__.INI_FILEPATH)
        
        self.app = paste.fixture.TestApp(wsgiapp)

        
        
if __name__ == "__main__":
    unittest.main()        
