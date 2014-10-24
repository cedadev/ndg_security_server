#!/usr/bin/env python
"""Unit tests for WSGI SAML 2.0 SOAP Authorisation Decision Query Interface

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/02/2010"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import unittest
from uuid import uuid4
from datetime import datetime, timedelta
from cStringIO import StringIO

from ndg.soap.etree import SOAPEnvelope

from ndg.saml.saml2.core import (SAMLVersion, Subject, NameID, Issuer, 
                                 AuthzDecisionQuery, AuthzDecisionStatement, 
                                 Status, StatusCode, StatusMessage, 
                                 DecisionType, Action, Conditions, Assertion)
from ndg.saml.xml.etree import (AuthzDecisionQueryElementTree, 
                                ResponseElementTree)
from ndg.saml.test.binding.soap import WithPasteFixtureBaseTestCase


class TestAuthorisationServiceMiddleware(object):
    """Test Authorisation Service interface stub"""
    QUERY_INTERFACE_KEYNAME_OPTNAME = 'queryInterfaceKeyName'
    RESOURCE_URI = 'http://localhost/dap/data/'
    ISSUER_DN = '/O=Test/OU=Authorisation/CN=Service Stub'
    
    def __init__(self, app, global_conf, **app_conf):
        self.queryInterfaceKeyName = app_conf[
            TestAuthorisationServiceMiddleware.QUERY_INTERFACE_KEYNAME_OPTNAME]
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
    
    
class SOAPAuthzDecisionInterfaceMiddlewareTestCase(
                                        WithPasteFixtureBaseTestCase):
    CONFIG_FILENAME = 'authz-decision-interface.ini'
    RESOURCE_URI = TestAuthorisationServiceMiddleware.RESOURCE_URI
    
    def _createAuthzDecisionQuery(self, 
                            issuer="/O=Site A/CN=PEP",
                            subject="https://openid.localhost/philip.kershaw",
                            resource=RESOURCE_URI,
                            action=Action.HTTP_GET_ACTION,
                            actionNs=Action.GHPP_NS_URI):
        query = AuthzDecisionQuery()
        query.version = SAMLVersion(SAMLVersion.VERSION_20)
        query.id = str(uuid4())
        query.issueInstant = datetime.utcnow()
        
        query.issuer = Issuer()
        query.issuer.format = Issuer.X509_SUBJECT
        query.issuer.value = issuer
                        
        query.subject = Subject()  
        query.subject.nameID = NameID()
        query.subject.nameID.format = "urn:ndg:saml:test:openid"
        query.subject.nameID.value = subject
   
        query.resource = resource
                 
        query.actions.append(Action())
        query.actions[0].namespace = actionNs
        query.actions[0].value = action    

        return query
    
    def _makeRequest(self, query=None, **kw):
        """Convenience method to construct queries for tests"""
        
        if query is None:
            query = self._createAuthzDecisionQuery(**kw)
            
        elem = AuthzDecisionQueryElementTree.toXML(query)
        soapRequest = SOAPEnvelope()
        soapRequest.create()
        soapRequest.body.elem.append(elem)
        
        request = soapRequest.serialize()
        
        return request
    
    def _getSAMLResponse(self, responseBody):
        """Deserialise response string into ElementTree element"""
        soapResponse = SOAPEnvelope()
        
        responseStream = StringIO()
        responseStream.write(responseBody)
        responseStream.seek(0)
        
        soapResponse.parse(responseStream)
        
        print("Parsed response ...")
        print(soapResponse.serialize())
#        print(prettyPrint(soapResponse.elem))
        
        response = ResponseElementTree.fromXML(soapResponse.body.elem[0])
        
        return response
    
    def test01AccessGranted(self):
        query = self._createAuthzDecisionQuery()
        request = self._makeRequest(query=query)
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
        response = self.app.post('/authorisationservice/', 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        print("Response status=%d" % response.status)
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.SUCCESS_URI)
        self.assert_(samlResponse.inResponseTo == query.id)
        self.assert_(samlResponse.assertions[0].subject.nameID.value == \
                     query.subject.nameID.value)
        self.assert_(samlResponse.assertions[0])
        self.assert_(samlResponse.assertions[0].authzDecisionStatements[0])
        self.assert_(samlResponse.assertions[0].authzDecisionStatements[0
                                            ].decision == DecisionType.PERMIT)
   
    def test02AccessDenied(self):
        query = self._createAuthzDecisionQuery(action=Action.HTTP_POST_ACTION)
        request = self._makeRequest(query=query)
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
        response = self.app.post('/authorisationservice/', 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        print("Response status=%d" % response.status)
        
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.SUCCESS_URI)
        self.assert_(samlResponse.inResponseTo == query.id)
        self.assert_(samlResponse.assertions[0].subject.nameID.value == \
                     query.subject.nameID.value)
        self.assert_(samlResponse.assertions[0])
        self.assert_(samlResponse.assertions[0].authzDecisionStatements[0])
        self.assert_(samlResponse.assertions[0].authzDecisionStatements[0
                                            ].decision == DecisionType.DENY)
        
    def test03IndeterminateResponse(self):
        query = self._createAuthzDecisionQuery(
                            resource=self.__class__.RESOURCE_URI + 'invalid')
        request = self._makeRequest(query=query)
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
        response = self.app.post('/authorisationservice/', 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        print("Response status=%d" % response.status)
        
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.SUCCESS_URI)
        self.assert_(samlResponse.inResponseTo == query.id)
        self.assert_(samlResponse.assertions[0].subject.nameID.value == \
                     query.subject.nameID.value)
        self.assert_(samlResponse.assertions[0])
        self.assert_(samlResponse.assertions[0].authzDecisionStatements[0])
        self.assert_(samlResponse.assertions[0].authzDecisionStatements[0
                                    ].decision == DecisionType.INDETERMINATE)
        

if __name__ == "__main__":
    unittest.main()