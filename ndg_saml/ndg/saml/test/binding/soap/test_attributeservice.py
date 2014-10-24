#!/usr/bin/env python
"""Unit tests for WSGI SAML 2.0 SOAP Attribute Query Interface

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import unittest
from uuid import uuid4
from datetime import datetime, timedelta
from cStringIO import StringIO

from ndg.soap.etree import SOAPEnvelope

from ndg.saml.saml2.core import (Assertion, Attribute, AttributeStatement, 
                                 SAMLVersion, Subject, NameID, Issuer, 
                                 AttributeQuery, XSStringAttributeValue, 
                                 Conditions, StatusCode)
from ndg.saml.xml import XMLConstants
from ndg.saml.xml.etree import AttributeQueryElementTree, ResponseElementTree
from ndg.saml.test.binding.soap import WithPasteFixtureBaseTestCase


class TestAttributeServiceMiddleware(object):
    """Test Attribute Service interface stub"""
    QUERY_INTERFACE_KEYNAME_OPTNAME = 'queryInterfaceKeyName'
    ISSUER_DN = '/O=Test/OU=Attribute Service/CN=Service Stub'
    
    FIRSTNAME_ATTRNAME = "urn:ndg:saml:firstname"
    LASTNAME_ATTRNAME = "urn:ndg:saml:lastname"
    EMAILADDRESS_ATTRNAME = "urn:ndg:saml:emailaddress"
    
    VALID_QUERY_ISSUERS = (
        "/O=Site A/CN=Authorisation Service",
        "/O=Site B/CN=Authorisation Service"
    )
    VALID_SUBJECTS = ("https://openid.localhost/philip.kershaw", )
    VALID_ATTR_NAME_URIS = (
        FIRSTNAME_ATTRNAME, LASTNAME_ATTRNAME, EMAILADDRESS_ATTRNAME
    )
    
    def __init__(self, app, global_conf, **app_conf):
        self.queryInterfaceKeyName = app_conf[
            self.__class__.QUERY_INTERFACE_KEYNAME_OPTNAME]
        self._app = app

        self.firstName = "Philip"
        self.lastName = "Kershaw"
        self.emailAddress = "pkershaw@somewhere.ac.uk"
    
    def __call__(self, environ, start_response):
        environ[self.queryInterfaceKeyName] = self.attributeQueryFactory()
        return self._app(environ, start_response)
    
    def attributeQueryFactory(self):
        """Makes the attribute query method"""
        
        def attributeQuery(query, response):
            """Attribute Query interface called by the next middleware in the 
            stack the SAML SOAP Query interface middleware instance
            (ndg.saml.saml2.binding.soap.server.wsgi.queryinterface.SOAPQueryInterfaceMiddleware)
            """
            response.issueInstant = datetime.utcnow()
            response.id = str(uuid4())            
            response.inResponseTo = query.id

            if query.issuer.value not in self.__class__.VALID_QUERY_ISSUERS:
                response.status.statusCode.value = \
                                            StatusCode.REQUEST_DENIED_URI   
                return response    

            if query.subject.nameID.value not in self.__class__.VALID_SUBJECTS:
                response.status.statusCode.value = \
                                            StatusCode.UNKNOWN_PRINCIPAL_URI   
                return response    
                
            assertion = Assertion()
            
            assertion.version = SAMLVersion(SAMLVersion.VERSION_20)
            assertion.id = str(uuid4())
            assertion.issueInstant = response.issueInstant
            
            assertion.conditions = Conditions()
            assertion.conditions.notBefore = assertion.issueInstant
            assertion.conditions.notOnOrAfter = \
                assertion.conditions.notBefore + timedelta(seconds=60*60*8)
            
            assertion.subject = Subject()  
            assertion.subject.nameID = NameID()
            assertion.subject.nameID.format = query.subject.nameID.format
            assertion.subject.nameID.value = query.subject.nameID.value
    
            assertion.attributeStatements.append(AttributeStatement())                
            
            for attribute in query.attributes:
                if attribute.name == self.__class__.FIRSTNAME_ATTRNAME:
                    # special case handling for 'FirstName' attribute
                    fnAttribute = Attribute()
                    fnAttribute.name = attribute.name
                    fnAttribute.nameFormat = attribute.nameFormat
                    fnAttribute.friendlyName = attribute.friendlyName
        
                    firstName = XSStringAttributeValue()
                    firstName.value = self.firstName
                    fnAttribute.attributeValues.append(firstName)
        
                    assertion.attributeStatements[0].attributes.append(
                                                                    fnAttribute)
                
                elif attribute.name == self.__class__.LASTNAME_ATTRNAME:
                    lnAttribute = Attribute()
                    lnAttribute.name = attribute.name
                    lnAttribute.nameFormat = attribute.nameFormat
                    lnAttribute.friendlyName = attribute.friendlyName
        
                    lastName = XSStringAttributeValue()
                    lastName.value = self.lastName
                    lnAttribute.attributeValues.append(lastName)
        
                    assertion.attributeStatements[0].attributes.append(
                                                                    lnAttribute)
                   
                elif (attribute.name == self.__class__.EMAILADDRESS_ATTRNAME and
                      query.issuer.value == 
                                        self.__class__.VALID_QUERY_ISSUERS[0]):
                    emailAddressAttribute = Attribute()
                    emailAddressAttribute.name = attribute.name
                    emailAddressAttribute.nameFormat = attribute.nameFormat
                    emailAddressAttribute.friendlyName = attribute.friendlyName
        
                    emailAddress = XSStringAttributeValue()
                    emailAddress.value = self.emailAddress
                    emailAddressAttribute.attributeValues.append(emailAddress)
        
                    assertion.attributeStatements[0].attributes.append(
                                                        emailAddressAttribute)
                else:
                    response.status.statusCode.value = \
                                        StatusCode.INVALID_ATTR_NAME_VALUE_URI
                    return response
                                    
            
            response.assertions.append(assertion)
            response.status.statusCode.value = StatusCode.SUCCESS_URI        
    
            return response
        
        return attributeQuery


class SOAPAttributeInterfaceMiddlewareTestCase(WithPasteFixtureBaseTestCase):
    """Test SAML Attribute Query over SOAP Binding querying a test attribute
    server served using Paste Paster over HTTPS""" 
    CONFIG_FILENAME = 'attribute-interface.ini'
    SERVICE_URI = '/attributeauthority'
    
    @staticmethod
    def _createAttributeQuery(issuer="/O=Site A/CN=Authorisation Service",
                        subject="https://openid.localhost/philip.kershaw"):
        """Helper to create a query"""
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = issuer
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = "urn:ndg:saml:test:openid"
        attributeQuery.subject.nameID.value = subject
                                    
        
        # special case handling for 'FirstName' attribute
        fnAttribute = Attribute()
        fnAttribute.name = TestAttributeServiceMiddleware.FIRSTNAME_ATTRNAME
        fnAttribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"
        fnAttribute.friendlyName = "FirstName"

        attributeQuery.attributes.append(fnAttribute)
    
        # special case handling for 'LastName' attribute
        lnAttribute = Attribute()
        lnAttribute.name = TestAttributeServiceMiddleware.LASTNAME_ATTRNAME
        lnAttribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"
        lnAttribute.friendlyName = "LastName"

        attributeQuery.attributes.append(lnAttribute)
    
        # special case handling for 'LastName' attribute
        emailAddressAttribute = Attribute()
        emailAddressAttribute.name = \
                            TestAttributeServiceMiddleware.EMAILADDRESS_ATTRNAME
        emailAddressAttribute.nameFormat = XMLConstants.XSD_NS+"#"+\
                                    XSStringAttributeValue.TYPE_LOCAL_NAME
        emailAddressAttribute.friendlyName = "emailAddress"

        attributeQuery.attributes.append(emailAddressAttribute)  

        return attributeQuery
    
    @classmethod
    def _makeRequest(cls, attributeQuery=None, **kw):
        """Convenience method to construct queries for tests"""
        
        if attributeQuery is None:
            attributeQuery = cls._createAttributeQuery(**kw)
            
        elem = AttributeQueryElementTree.toXML(attributeQuery)
        soapRequest = SOAPEnvelope()
        soapRequest.create()
        soapRequest.body.elem.append(elem)
        
        request = soapRequest.serialize()
        
        return request
    
    @staticmethod
    def _getSAMLResponse(responseBody):
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
    
    def test01ValidQuery(self):
        attributeQuery = self._createAttributeQuery()
        request = self._makeRequest(attributeQuery=attributeQuery)
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
        response = self.app.post(self.__class__.SERVICE_URI, 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        print("Response status=%d" % response.status)
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.SUCCESS_URI)
        self.assert_(samlResponse.inResponseTo == attributeQuery.id)
        self.assert_(samlResponse.assertions[0].subject.nameID.value == \
                     attributeQuery.subject.nameID.value)

    def test02AttributeReleaseDenied(self):
        request = self._makeRequest(issuer="/O=Site B/CN=Authorisation Service")
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
        
        response = self.app.post(self.__class__.SERVICE_URI, 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        
        print("Response status=%d" % response.status)
        
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.INVALID_ATTR_NAME_VALUE_URI)

    def test03InvalidAttributesRequested(self):
        attributeQuery = self._createAttributeQuery()
        
        # Add an unsupported Attribute name
        attribute = Attribute()
        attribute.name = "urn:my:attribute"
        attribute.nameFormat = XMLConstants.XSD_NS+"#"+\
                                    XSStringAttributeValue.TYPE_LOCAL_NAME
        attribute.friendlyName = "myAttribute"
        attributeQuery.attributes.append(attribute)     
        
        request = self._makeRequest(attributeQuery=attributeQuery)
           
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
       
        response = self.app.post(self.__class__.SERVICE_URI, 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        
        print("Response status=%d" % response.status)
        
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.INVALID_ATTR_NAME_VALUE_URI)
        
    def test04InvalidQueryIssuer(self):
        request = self._makeRequest(issuer="/CN=My Attribute Query Issuer")
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
       
        response = self.app.post(self.__class__.SERVICE_URI, 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        
        print("Response status=%d" % response.status)
        
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.REQUEST_DENIED_URI)

    def test05UnknownPrincipal(self):
        request = self._makeRequest(subject="Joe.Bloggs")
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
        
        response = self.app.post(self.__class__.SERVICE_URI, 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        
        print("Response status=%d" % response.status)
        
        samlResponse = self._getSAMLResponse(response.body)

        self.assert_(samlResponse.status.statusCode.value == \
                     StatusCode.UNKNOWN_PRINCIPAL_URI)

 
if __name__ == "__main__":
    unittest.main()