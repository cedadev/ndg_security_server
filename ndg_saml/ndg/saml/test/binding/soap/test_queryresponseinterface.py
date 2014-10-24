"""SAML Generic SOAP Binding Query/Response Interface unit test module

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)
import unittest

from datetime import datetime, timedelta
import os
from uuid import uuid4
import paste.fixture
from cStringIO import StringIO

from ndg.saml import importElementTree
ElementTree = importElementTree()

from ndg.saml.utils import SAMLDateTime
from ndg.saml.saml2.core import (Response, Assertion, Attribute, 
                             AttributeStatement, SAMLVersion, Subject, NameID,
                             Issuer, AttributeQuery, XSStringAttributeValue, 
                             Conditions, Status, StatusCode)
from ndg.saml.xml import XMLConstants
from ndg.saml.xml.etree import AttributeQueryElementTree, ResponseElementTree
from ndg.saml.saml2.binding.soap.client.requestbase import (
    ResponseIssueInstantInvalid, AssertionIssueInstantInvalid,
    AssertionConditionNotBeforeInvalid, AssertionConditionNotOnOrAfterInvalid)
from ndg.saml.saml2.binding.soap.client.subjectquery import (
                                                        SubjectQuerySOAPBinding)

from ndg.soap.client import (UrlLib2SOAPClient, UrlLib2SOAPRequest)
from ndg.soap.etree import SOAPEnvelope
from ndg.soap.utils.etree import QName, prettyPrint


class SamlSoapBindingApp(object):
    """Simple WSGI application to handle SAML Attribute Query/Response
    """
    FIRSTNAME_ATTRNAME = "urn:ndg:saml:firstname"
    LASTNAME_ATTRNAME = "urn:ndg:saml:lastname"
    EMAILADDRESS_ATTRNAME = "urn:ndg:saml:emailaddress"
    NAMEID_FORMAT = "urn:ndg:saml:openid"
    
    def __init__(self):
        self.firstName = "Philip"
        self.lastName = "Kershaw"
        self.emailAddress = "pkershaw@somewhere.ac.uk"
                  
    def __call__(self, environ, start_response):
        soapRequestStream = environ['wsgi.input']
        soapRequest = SOAPEnvelope()
        soapRequest.parse(soapRequestStream)
        attributeQueryElem = soapRequest.body.elem[0]
        attributeQuery = AttributeQueryElementTree.fromXML(attributeQueryElem)
        
        print("Received request from client:\n")
        print soapRequest.prettyPrint()
        
        samlResponse = Response()
        
        samlResponse.issueInstant = datetime.utcnow()
        samlResponse.id = str(uuid4())
        samlResponse.issuer = Issuer()
        
        # SAML 2.0 spec says format must be omitted
        #samlResponse.issuer.format = Issuer.X509_SUBJECT
        samlResponse.issuer.value = \
                        "/O=NDG/OU=BADC/CN=attributeauthority.badc.rl.ac.uk"
        
        samlResponse.inResponseTo = attributeQuery.id
        
        assertion = Assertion()
        
        assertion.version = SAMLVersion(SAMLVersion.VERSION_20)
        assertion.id = str(uuid4())
        assertion.issueInstant = samlResponse.issueInstant
        
        assertion.conditions = Conditions()
        assertion.conditions.notBefore = assertion.issueInstant
        assertion.conditions.notOnOrAfter = assertion.conditions.notBefore + \
            timedelta(seconds=60*60*8)
        
        assertion.subject = Subject()  
        assertion.subject.nameID = NameID()
        assertion.subject.nameID.format = attributeQuery.subject.nameID.format
        assertion.subject.nameID.value = attributeQuery.subject.nameID.value

        assertion.attributeStatements.append(AttributeStatement())
        
        for attribute in attributeQuery.attributes:
            if attribute.name == SamlSoapBindingApp.FIRSTNAME_ATTRNAME:
                # special case handling for 'FirstName' attribute
                fnAttribute = Attribute()
                fnAttribute.name = attribute.name
                fnAttribute.nameFormat = attribute.nameFormat
                fnAttribute.friendlyName = attribute.friendlyName
    
                firstName = XSStringAttributeValue()
                firstName.value = self.firstName
                fnAttribute.attributeValues.append(firstName)
    
                assertion.attributeStatements[0].attributes.append(fnAttribute)
            
            elif attribute.name == SamlSoapBindingApp.LASTNAME_ATTRNAME:
                lnAttribute = Attribute()
                lnAttribute.name = attribute.name
                lnAttribute.nameFormat = attribute.nameFormat
                lnAttribute.friendlyName = attribute.friendlyName
    
                lastName = XSStringAttributeValue()
                lastName.value = self.lastName
                lnAttribute.attributeValues.append(lastName)
    
                assertion.attributeStatements[0].attributes.append(lnAttribute)
               
            elif attribute.name == SamlSoapBindingApp.EMAILADDRESS_ATTRNAME:
                emailAddressAttribute = Attribute()
                emailAddressAttribute.name = attribute.name
                emailAddressAttribute.nameFormat = attribute.nameFormat
                emailAddressAttribute.friendlyName = attribute.friendlyName
    
                emailAddress = XSStringAttributeValue()
                emailAddress.value = self.emailAddress
                emailAddressAttribute.attributeValues.append(emailAddress)
    
                assertion.attributeStatements[0].attributes.append(
                                                        emailAddressAttribute)
        
        samlResponse.assertions.append(assertion)
        
        samlResponse.status = Status()
        samlResponse.status.statusCode = StatusCode()
        samlResponse.status.statusCode.value = StatusCode.SUCCESS_URI        

        
        # Convert to ElementTree representation to enable attachment to SOAP
        # response body
        samlResponseElem = ResponseElementTree.toXML(samlResponse)
        xml = ElementTree.tostring(samlResponseElem)
        log.debug('Sending response to query:\n%s', xml)
        
        # Create SOAP response and attach the SAML Response payload
        soapResponse = SOAPEnvelope()
        soapResponse.create()
        soapResponse.body.elem.append(samlResponseElem)
        
        response = soapResponse.serialize()
        
        start_response("200 OK",
                       [('Content-length', str(len(response))),
                        ('Content-type', 'text/xml')])
        return [response]

        
class SamlAttributeQueryTestCase(unittest.TestCase):
    """Test the SAML SOAP binding using an Attribute Query as an example"""
    thisDir = os.path.dirname(os.path.abspath(__file__))
    RESPONSE = '''\
<soap11:Envelope xmlns:soap11="http://schemas.xmlsoap.org/soap/envelope/">
   <soap11:Body>
      <samlp:Response ID="05680cb2-4973-443d-9d31-7bc99bea87c1" InResponseTo="e3183380-ae82-4285-8827-8c40613842de" IssueInstant="%(issueInstant)s" Version="2.0" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
         <saml:Issuer Format="urn:esg:issuer" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">Somewhere</saml:Issuer>
         <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
         </samlp:Status>
         <saml:Assertion ID="192c67d9-f9cd-457a-9242-999e7b943166" IssueInstant="%(assertionIssueInstant)s" Version="2.0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Issuer Format="urn:esg:issuer">Somewhere</saml:Issuer>
            <saml:Subject>
               <saml:NameID Format="urn:esg:openid">https://somewhere.edu/myopenid/testUser</saml:NameID>
            </saml:Subject>
            <saml:Conditions NotBefore="%(notBefore)s" NotOnOrAfter="%(notOnOrAfter)s" />
            <saml:AttributeStatement>
               <saml:Attribute FriendlyName="FirstName" Name="urn:esg:first:name" NameFormat="http://www.w3.org/2001/XMLSchema#string">
                  <saml:AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Test</saml:AttributeValue>
               </saml:Attribute>
               <saml:Attribute FriendlyName="LastName" Name="urn:esg:last:name" NameFormat="http://www.w3.org/2001/XMLSchema#string">
                  <saml:AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">User</saml:AttributeValue>
               </saml:Attribute>
               <saml:Attribute FriendlyName="EmailAddress" Name="urn:esg:first:email:address" NameFormat="http://www.w3.org/2001/XMLSchema#string">
                  <saml:AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">someone@somewhere.edu</saml:AttributeValue>
               </saml:Attribute>
            </saml:AttributeStatement>
         </saml:Assertion>
      </samlp:Response>
   </soap11:Body>
</soap11:Envelope>
'''

    def __init__(self, *args, **kwargs):
        wsgiApp = SamlSoapBindingApp()
        self.app = paste.fixture.TestApp(wsgiApp)
         
        unittest.TestCase.__init__(self, *args, **kwargs)
        
    def test01AttributeQuery(self):
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = \
                        "/O=NDG/OU=BADC/CN=attributeauthority.badc.rl.ac.uk"
                        
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = SamlSoapBindingApp.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = \
                                    "https://openid.localhost/philip.kershaw"
        
        # special case handling for 'FirstName' attribute
        fnAttribute = Attribute()
        fnAttribute.name = SamlSoapBindingApp.FIRSTNAME_ATTRNAME
        fnAttribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"
        fnAttribute.friendlyName = "FirstName"

        attributeQuery.attributes.append(fnAttribute)
    
        # special case handling for 'LastName' attribute
        lnAttribute = Attribute()
        lnAttribute.name = SamlSoapBindingApp.LASTNAME_ATTRNAME
        lnAttribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"
        lnAttribute.friendlyName = "LastName"

        attributeQuery.attributes.append(lnAttribute)
    
        # special case handling for 'LastName' attribute
        emailAddressAttribute = Attribute()
        emailAddressAttribute.name = SamlSoapBindingApp.EMAILADDRESS_ATTRNAME
        emailAddressAttribute.nameFormat = XMLConstants.XSD_NS+"#"+\
                                    XSStringAttributeValue.TYPE_LOCAL_NAME
        emailAddressAttribute.friendlyName = "emailAddress"

        attributeQuery.attributes.append(emailAddressAttribute)                                   
        
        elem = AttributeQueryElementTree.toXML(attributeQuery)
        soapRequest = SOAPEnvelope()
        soapRequest.create()
        soapRequest.body.elem.append(elem)
        
        request = soapRequest.serialize()
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
        response = self.app.post('/attributeauthority', 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        print("Response status=%d" % response.status)

        soapResponse = SOAPEnvelope()
        
        responseStream = StringIO()
        responseStream.write(response.body)
        responseStream.seek(0)
        
        soapResponse.parse(responseStream)
        
        print("Parsed response ...")
        print(soapResponse.serialize())
#        print(prettyPrint(soapResponse.elem))
        
        response = ResponseElementTree.fromXML(soapResponse.body.elem[0])
        self.assert_(response.status.statusCode.value==StatusCode.SUCCESS_URI)
        self.assert_(response.inResponseTo == attributeQuery.id)
        self.assert_(response.assertions[0].subject.nameID.value == \
                     attributeQuery.subject.nameID.value)

    def _parseResponse(self, responseStr):
        """Helper to parse a response from a string"""
        soapResponse = SOAPEnvelope()
        
        responseStream = StringIO()
        responseStream.write(responseStr)
        responseStream.seek(0)
        
        soapResponse.parse(responseStream)
        
        print("Parsed response ...")
        print(soapResponse.serialize())
        
        response = ResponseElementTree.fromXML(soapResponse.body.elem[0])
        return response
        
    def test03ParseResponse(self):
        utcNow = datetime.utcnow()
        respDict = {
            'issueInstant': SAMLDateTime.toString(utcNow),
            'assertionIssueInstant': SAMLDateTime.toString(utcNow),
            'notBefore': SAMLDateTime.toString(utcNow),
            'notOnOrAfter': SAMLDateTime.toString(utcNow + timedelta(
                                                            seconds=60*60*8))
        }
        responseStr = self.__class__.RESPONSE % respDict
        response = self._parseResponse(responseStr)
        self.assert_(response)

    def test04AssertionConditionExpired(self):
        # issued 9 hours ago
        issueInstant = datetime.utcnow() - timedelta(seconds=60*60*9)
        respDict = {
            'issueInstant': SAMLDateTime.toString(issueInstant),
            'assertionIssueInstant': SAMLDateTime.toString(issueInstant),
            'notBefore': SAMLDateTime.toString(issueInstant),
            # It lasts for 8 hours so it's expired by one hour
            'notOnOrAfter': SAMLDateTime.toString(issueInstant + timedelta(
                                                            seconds=60*60*8))
        }
        responseStr = self.__class__.RESPONSE % respDict
        response = self._parseResponse(responseStr)
        binding = SubjectQuerySOAPBinding()
        try:
            binding._verifyTimeConditions(response)
            self.fail("Expecting not on or after timestamp error")
        except AssertionConditionNotOnOrAfterInvalid, e:
            print("PASSED: %s" % e)

    def test05ResponseIssueInstantInvalid(self):
        utcNow = datetime.utcnow()
        respDict = {
            'issueInstant': SAMLDateTime.toString(utcNow + timedelta(
                                                                    seconds=1)),
            'assertionIssueInstant': SAMLDateTime.toString(utcNow),
            'notBefore': SAMLDateTime.toString(utcNow),
            'notOnOrAfter': SAMLDateTime.toString(utcNow + timedelta(
                                                            seconds=60*60*8))
        }
        responseStr = self.__class__.RESPONSE % respDict
        response = self._parseResponse(responseStr)
        binding = SubjectQuerySOAPBinding()
        try:
            binding._verifyTimeConditions(response)
            self.fail("Expecting issue instant timestamp error")
        except ResponseIssueInstantInvalid, e:
            print("PASSED: %s" % e)

    def test06NotBeforeConditionInvalid(self):
        utcNow = datetime.utcnow()
        respDict = {
            'issueInstant': SAMLDateTime.toString(utcNow),
            'assertionIssueInstant': SAMLDateTime.toString(utcNow),
            'notBefore': SAMLDateTime.toString(utcNow + timedelta(seconds=1)),
            'notOnOrAfter': SAMLDateTime.toString(utcNow + timedelta(
                                                            seconds=60*60*8))
        }
        responseStr = self.__class__.RESPONSE % respDict
        response = self._parseResponse(responseStr)
        binding = SubjectQuerySOAPBinding()
        try:
            binding._verifyTimeConditions(response)
            self.fail("Expecting issue instant timestamp error")
        except AssertionConditionNotBeforeInvalid, e:
            print("PASSED: %s" % e)

    def test07AssertionIssueInstantInvalid(self):
        utcNow = datetime.utcnow()
        respDict = {
            'issueInstant': SAMLDateTime.toString(utcNow),
            'assertionIssueInstant': SAMLDateTime.toString(utcNow + timedelta(
                                                                    seconds=1)),
            'notBefore': SAMLDateTime.toString(utcNow),
            'notOnOrAfter': SAMLDateTime.toString(utcNow + timedelta(
                                                            seconds=60*60*8))
        }
        responseStr = self.__class__.RESPONSE % respDict
        response = self._parseResponse(responseStr)
        binding = SubjectQuerySOAPBinding()
        try:
            binding._verifyTimeConditions(response)
            self.fail("Expecting issue instant timestamp error")
        except AssertionIssueInstantInvalid, e:
            print("PASSED: %s" % e)

    def test07ClockSkewCorrectedAssertionIssueInstantInvalid(self):
        utcNow = datetime.utcnow()
        respDict = {
            'issueInstant': SAMLDateTime.toString(utcNow),
            'assertionIssueInstant': SAMLDateTime.toString(utcNow + timedelta(
                                                                    seconds=1)),
            'notBefore': SAMLDateTime.toString(utcNow),
            'notOnOrAfter': SAMLDateTime.toString(utcNow + timedelta(
                                                            seconds=60*60*8))
        }
        responseStr = self.__class__.RESPONSE % respDict
        response = self._parseResponse(responseStr)
        binding = SubjectQuerySOAPBinding()
        
        # Set a skew to correct the error
        binding.clockSkewTolerance = 1
        
        try:
            binding._verifyTimeConditions(response)
        except AssertionIssueInstantInvalid, e:
            self.fail("issue instant timestamp error should be corrected for")

    def test08ClockSkewCorrectedAssertionConditionExpired(self):
        # Issued 9 hours ago
        issueInstant = datetime.utcnow() - timedelta(seconds=60*60*9)
        respDict = {
            'issueInstant': SAMLDateTime.toString(issueInstant),
            'assertionIssueInstant': SAMLDateTime.toString(issueInstant),
            'notBefore': SAMLDateTime.toString(issueInstant),
            # Assertion lasts 8 hours so it has expired by one hour
            'notOnOrAfter': SAMLDateTime.toString(issueInstant + timedelta(
                                                            seconds=60*60*8))
        }
        responseStr = self.__class__.RESPONSE % respDict
        response = self._parseResponse(responseStr)
        binding = SubjectQuerySOAPBinding()
        
        # Set a skew of over one hour to correct for the assertion expiry
        binding.clockSkewTolerance = 60*60 + 3
        
        try:
            binding._verifyTimeConditions(response)
            
        except AssertionConditionNotOnOrAfterInvalid, e:
            self.fail("Not on or after timestamp error should be corrected for")
            
            
if __name__ == "__main__":
    unittest.main()        

