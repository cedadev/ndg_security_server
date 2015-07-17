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
from urlparse import urlunsplit

from os import path
from ConfigParser import SafeConfigParser

from uuid import uuid4
from datetime import datetime, timedelta

import paste.fixture
from paste.deploy import loadapp

from ndg.saml.saml2.core import (SAMLVersion, Subject, NameID, Issuer, 
                                 AuthzDecisionQuery, AuthzDecisionStatement, 
                                 Status, StatusCode, StatusMessage, 
                                 DecisionType, Action, Conditions, Assertion)
from ndg.saml.xml.etree import (AuthzDecisionQueryElementTree, 
                                ResponseElementTree)

from ndg.security.server.test.base import BaseTestCase
from ndg.security.server.wsgi import NDGSecurityMiddlewareBase
from ndg.security.server.wsgi.authz.result_handler.basic import \
    PEPResultHandlerMiddleware
from ndg.security.server.wsgi.authz.pep import SamlPepFilterConfigError


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
    RESPONSE = "Test Authorization application"
       
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
            response += ("\n\nAny calls to this path or sub-path should be "
                         "publicly accessible")
        else:
            status = "404 Not found"
                
        start_response(status,
                       [('Content-length', 
                         str(len(response))),
                        ('Content-type', 'text/plain')])
        
        return [TestAuthZMiddleware.RESPONSE + ' returned: ' + status]


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
    
    def __init__(self, *args, **kwargs):   
        """Test the authorisation filter using Paste fixture and set up 
        Authorisation and Attribute Services needed for making authorisation 
        decisions
        """   
        BaseTestCase.__init__(self, *args, **kwargs)
        
        self.__class__.INI_FILEPATH = os.path.join(self.__class__.THIS_DIR, 
                                                   self.__class__.INI_FILE)
# 
#        wsgiapp = loadapp('config:'+self.__class__.INI_FILE, 
#                          relative_to=self.__class__.THIS_DIR)
 
        wsgiapp = loadapp('config:'+self.__class__.INI_FILEPATH)
        
        self.app = paste.fixture.TestApp(wsgiapp)
       
        self.startSiteAAttributeAuthority(withSSL=True,
            port=self.__class__.SITEA_SSL_ATTRIBUTEAUTHORITY_PORTNUM)
        
        self.startAuthorisationService()  
    
          
class SamlPepFilterTestCase(BaseAuthzFilterTestCase):
    """Test SAML based Policy Enforcement Filter.  This has a SAML authorisation
    decision query interface to call to a remote authorisation service"""

    def test01CatchNoBeakerSessionFound(self):
        
        # PEPFilterConfigError is raised if no beaker.session is set in 
        # environ
        self.assertRaises(SamlPepFilterConfigError, self.app.get, 
                          '/test_200')
       
    def test02Ensure200WithNotLoggedInAndUnsecuredURI(self):
        
        # Check the authZ middleware leaves the response alone if the URI 
        # is not matched in the policy
        
        # Simulate a beaker.session in the environ
        extra_environ={self.__class__.SESSION_KEYNAME:BeakerSessionStub()}
        response = self.app.get('/test_200',
                                extra_environ=extra_environ)
        print response

    def test03Catch401WithLoggedIn(self):
        
        # Check that the application being secured can raise a HTTP 401
        # response and that this respected by the Authorization middleware
        # even though a user is set in the session
        
        extra_environ = {
            self.__class__.SESSION_KEYNAME:
                BeakerSessionStub(username=self.__class__.OPENID_URI),
            'REMOTE_USER': self.__class__.OPENID_URI
        }
        response = self.app.get('/test_401', 
                                extra_environ=extra_environ,
                                status=401)
        print response

    def test04Catch403WithLoggedIn(self):
        # Check that the application being secured can raise a HTTP 403
        # response and that this respected by the Authorization middleware
        # even though a user is set in the session
        
        extra_environ = {
            self.__class__.SESSION_KEYNAME:
                BeakerSessionStub(username=SamlPepFilterTestCase.OPENID_URI),
            'REMOTE_USER': self.__class__.OPENID_URI
        }
        response = self.app.get('/test_403', 
                                extra_environ=extra_environ,
                                status=403)
        print response

    def test05Catch401WithNotLoggedInAndSecuredURI(self):
        # User is not logged in and a secured resource has been requested so 401
        # response is returned
        
        # AuthZ middleware checks for username key in session set by AuthN
        # handler
        extra_environ = {self.__class__.SESSION_KEYNAME: BeakerSessionStub()}
        response = self.app.get('/test_accessDeniedToSecuredURI',
                                extra_environ=extra_environ,
                                status=401)
        print response
        
    def test06AccessDeniedForSecuredURI(self):
        # User is logged in but doesn't have the required credentials for 
        # access
        extra_environ = {
            self.__class__.SESSION_KEYNAME:
                BeakerSessionStub(username=SamlPepFilterTestCase.OPENID_URI),
            'REMOTE_USER': self.__class__.OPENID_URI
        }
        
        response = self.app.get('/test_accessDeniedToSecuredURI',
                                extra_environ=extra_environ,
                                status=403)
        print response

    def test07AccessGrantedForSecuredURI(self):      
        # User is logged in and has credentials for access to a URI secured
        # by the policy file
        extra_environ = {
            self.__class__.SESSION_KEYNAME:
                BeakerSessionStub(username=SamlPepFilterTestCase.OPENID_URI),
            'REMOTE_USER': self.__class__.OPENID_URI
        }
        
        response = self.app.get('/test_accessGrantedToSecuredURI',
                                extra_environ=extra_environ,
                                status=200)
        self.assert_(TestAuthZMiddleware.RESPONSE in response)
        print response
        
    def test08LocalPolicyFiltersOutRequest(self):
        # The local PDP filters out the incoming request as not applicable so
        # that the authorisation service is never invoked.
        extra_environ = {self.__class__.SESSION_KEYNAME: BeakerSessionStub()}
        response = self.app.get('/layout/my.css', extra_environ=extra_environ,
                                status=200)
        self.assert_(response.body)
        
    def test09ESGFGroupRoleAttributeValueProtectedResource(self):
        # Test a rule in the policy which makes use of ESGF Group/Role
        # Attribute Values
        extra_environ = {
            self.__class__.SESSION_KEYNAME:
                BeakerSessionStub(username=SamlPepFilterTestCase.OPENID_URI),
            'REMOTE_USER': self.__class__.OPENID_URI
        }
        
        response = self.app.get('/esgf-attribute-value-restricted',
                                extra_environ=extra_environ,
                                status=200)
        self.assert_(TestAuthZMiddleware.RESPONSE in response)
        print response        
                

class PEPResultHandlerTestCase(BaseAuthzFilterTestCase):
    """Test Authorisation Filter - this contains the PEP filter and a result
    handler which enables customisation of behaviour on 403 Forbidden responses
    """
    INI_FILE = 'pep-result-handler-test.ini'
    AUTHZ_FILTER_SECTION = 'filter:AuthZFilter'
    AUTHZ_RESULT_HANDLER_REDIRECT_URI_OPTNAME = \
        'authz.resultHandler.redirectURI'
    
    def __init__(self, *arg, **kw):
        BaseAuthzFilterTestCase.__init__(self, *arg, **kw)
        
        cfgParser = SafeConfigParser()
        cfgParser.read(self.__class__.INI_FILEPATH)
        
        self.redirectURI = cfgParser.get(self.__class__.AUTHZ_FILTER_SECTION,
                    self.__class__.AUTHZ_RESULT_HANDLER_REDIRECT_URI_OPTNAME)
        
    def test01RedirectPEPResultHandlerMiddleware(self):
        # User is logged in but doesn't have the required credentials for 
        extra_environ = {
            self.__class__.SESSION_KEYNAME:
                        BeakerSessionStub(username=self.__class__.OPENID_URI),
            'REMOTE_USER': self.__class__.OPENID_URI
        }
        
        # Expecting result handler to be invoked overriding the 403 response
        response = self.app.get('/test_accessDeniedToSecuredURI',
                                extra_environ=extra_environ,
                                status=302)
        print("Result handler has intercepted the 403 Forbidden response "
              "from the PEP and set this redirect response instead: %s" %
              response)
        self.assert_(response.header_dict.get('location') == self.redirectURI)

    def test02RedirectFollowingAccessDeniedForAdminQueryArg(self):
        
        # User is logged in but doesn't have the required credentials for 
        # access
        extra_environ = {
            self.__class__.SESSION_KEYNAME:
                BeakerSessionStub(username=SamlPepFilterTestCase.OPENID_URI),
            'REMOTE_USER': self.__class__.OPENID_URI
        }
        
        # Try this URI with the query arg admin=1.  This will be picked up
        # by the policy as a request requiring admin rights.  The request is
        # denied as the user doesn't have these rights but this then calls
        # into play the PEP result handler defined in this module,
        # RedirectFollowingAccessDenied.  This class reinvokes the request
        # but without the admin query argument (see the ini file for what this
        # location is.  Access is then granted because the user has access
        # rights for the new location.
        response = self.app.get('/test_accessGrantedToSecuredURI',
                                params={'admin': 1},
                                extra_environ=extra_environ,
                                status=302)

        print("Redirect Handler has interrupted the 403 Denied response and "
              "added this redirect response instead: %s" % response)
        
        # Follow the redirect - the policy should allow access to the new 
        # location 
        redirectResponse = response.follow(extra_environ=extra_environ,
                                           status=200)
        print("Following the redirect to location %r gives this response: %s" %
              (response.header_dict.get('location'), redirectResponse))
        
        
if __name__ == "__main__":
    unittest.main()        
