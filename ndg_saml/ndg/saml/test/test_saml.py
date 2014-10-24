"""SAML unit test package

NERC DataGrid Project

This implementation is adapted from the Java OpenSAML implementation.  The 
copyright and licence information are included here:

Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
__author__ = "P J Kershaw"
__date__ = "21/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
    
from datetime import datetime, timedelta
from uuid import uuid4
from cStringIO import StringIO

import unittest
import pickle

from ndg.saml import importElementTree
ElementTree = importElementTree()

from ndg.saml.utils import SAMLDateTime
from ndg.saml.saml2.core import (SAMLVersion, Attribute, AttributeStatement, 
                                 AuthzDecisionStatement, Assertion, 
                                 AttributeQuery, Response, Issuer, Subject, 
                                 NameID, StatusCode, StatusMessage, Status, 
                                 Conditions, DecisionType, 
                                 XSStringAttributeValue, Action, 
                                 AuthzDecisionQuery)

from ndg.saml.common.xml import SAMLConstants
from ndg.saml.xml.etree import (prettyPrint, AssertionElementTree, 
                            AttributeQueryElementTree, ResponseElementTree,
                            AuthzDecisionQueryElementTree)


class SAMLUtil(object):
    """SAML utility class based on ANL examples for Earth System Grid:
    http://www.ci.uchicago.edu/wiki/bin/view/ESGProject/ESGSAMLAttributes#ESG_Attribute_Service
    """
    NAMEID_FORMAT = "urn:esg:openid"
    NAMEID_VALUE = "https://openid.localhost/philip.kershaw"
    ISSUER_DN = "/O=NDG/OU=BADC/CN=attributeauthority.badc.rl.ac.uk"
    UNCORRECTED_RESOURCE_URI = "http://LOCALHOST:80/My Secured URI"
    RESOURCE_URI = "http://localhost/My%20Secured%20URI"
    XSSTRING_NS = "http://www.w3.org/2001/XMLSchema#string"
    
    def __init__(self):
        """Set-up ESG core attributes, Group/Role and miscellaneous 
        attributes lists
        """
        self.firstName = None
        self.lastName = None
        self.emailAddress = None
        
        self.__miscAttrList = []
    
    def addAttribute(self, name, value):
        """Add a generic attribute
        @type name: basestring
        @param name: attribute name
        @type value: basestring
        @param value: attribute value
        """
        self.__miscAttrList.append((name, value))

    def buildAssertion(self):
        """Create a SAML Assertion containing ESG core attributes: First
        Name, Last Name, e-mail Address; ESG Group/Role type attributes
        and generic attributes
        @rtype: ndg.security.common.saml.Assertion
        @return: new SAML Assertion object
        """
        
        assertion = Assertion()
        assertion.version = SAMLVersion(SAMLVersion.VERSION_20)
        assertion.id = str(uuid4())
        assertion.issueInstant = datetime.utcnow()
        attributeStatement = AttributeStatement()
        
        for attribute in self.createAttributes():
            attributeStatement.attributes.append(attribute)
            
        assertion.attributeStatements.append(attributeStatement)
        
        return assertion

    def buildAttributeQuery(self, issuer, subjectNameID):
        """Make a SAML Attribute Query
        @type issuer: basestring
        @param issuer: attribute issuer name
        @type subjectNameID: basestring
        @param subjectNameID: identity to query attributes for
        """
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = issuer
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = SAMLTestCase.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = subjectNameID
                                    
        attributeQuery.attributes = self.createAttributes()
        
        return attributeQuery
    
    def createAttributes(self):
        """Create SAML Attributes for use in an Assertion or AttributeQuery"""
        
        attributes = []
        if self.firstName is not None:    
            # special case handling for 'FirstName' attribute
            fnAttribute = Attribute()
            fnAttribute.name = "urn:esg:first:name"
            fnAttribute.nameFormat = SAMLUtil.XSSTRING_NS
            fnAttribute.friendlyName = "FirstName"

            firstName = XSStringAttributeValue()
            firstName.value = self.firstName
            fnAttribute.attributeValues.append(firstName)

            attributes.append(fnAttribute)
        

        if self.lastName is not None:
            # special case handling for 'LastName' attribute
            lnAttribute = Attribute()
            lnAttribute.name = "urn:esg:last:name"
            lnAttribute.nameFormat = SAMLUtil.XSSTRING_NS
            lnAttribute.friendlyName = "LastName"

            lastName = XSStringAttributeValue()
            lastName.value = self.lastName
            lnAttribute.attributeValues.append(lastName)

            attributes.append(lnAttribute)
        

        if self.emailAddress is not None:
            # special case handling for 'LastName' attribute
            emailAddressAttribute = Attribute()
            emailAddressAttribute.name = "urn:esg:email:address"
            emailAddressAttribute.nameFormat = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME
            emailAddressAttribute.friendlyName = "emailAddress"

            emailAddress = XSStringAttributeValue()
            emailAddress.value = self.emailAddress
            emailAddressAttribute.attributeValues.append(emailAddress)

            attributes.append(emailAddressAttribute)
        
        for name, value in self.__miscAttrList:
            attribute = Attribute()
            attribute.name = name
            attribute.nameFormat = SAMLUtil.XSSTRING_NS

            stringAttributeValue = XSStringAttributeValue()
            stringAttributeValue.value = value
            attribute.attributeValues.append(stringAttributeValue)

            attributes.append(attribute)
            
        return attributes
    
    def buildAuthzDecisionQuery(self, 
                                issuer=ISSUER_DN,
                                issuerFormat=Issuer.X509_SUBJECT,
                                subjectNameID=NAMEID_VALUE, 
                                subjectNameIdFormat=NAMEID_FORMAT,
                                resource=UNCORRECTED_RESOURCE_URI,
                                actions=((Action.HTTP_GET_ACTION, 
                                          Action.GHPP_NS_URI),)):
        """Convenience utility to make an Authorisation decision query"""
        authzDecisionQuery = AuthzDecisionQuery()

        authzDecisionQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        authzDecisionQuery.id = str(uuid4())
        authzDecisionQuery.issueInstant = datetime.utcnow()
        
        authzDecisionQuery.issuer = Issuer()
        authzDecisionQuery.issuer.format = issuerFormat
        authzDecisionQuery.issuer.value = issuer
        
        authzDecisionQuery.subject = Subject()
        authzDecisionQuery.subject.nameID = NameID()
        authzDecisionQuery.subject.nameID.format = subjectNameIdFormat
        authzDecisionQuery.subject.nameID.value = subjectNameID
        
        authzDecisionQuery.resource = resource
        
        for action, namespace in actions:
            authzDecisionQuery.actions.append(Action())
            authzDecisionQuery.actions[-1].namespace = namespace
            authzDecisionQuery.actions[-1].value = action
            
        return authzDecisionQuery
            

class SAMLTestCase(unittest.TestCase):
    """Test SAML implementation for use with CMIP5 federation"""
    NAMEID_FORMAT = SAMLUtil.NAMEID_FORMAT
    NAMEID_VALUE = SAMLUtil.NAMEID_VALUE
    ISSUER_DN = SAMLUtil.ISSUER_DN
    UNCORRECTED_RESOURCE_URI = SAMLUtil.UNCORRECTED_RESOURCE_URI
    RESOURCE_URI = SAMLUtil.RESOURCE_URI
    
    def _createAttributeAssertionHelper(self):
        samlUtil = SAMLUtil()
        
        # ESG core attributes
        samlUtil.firstName = "Philip"
        samlUtil.lastName = "Kershaw"
        samlUtil.emailAddress = "p.j.k@somewhere"
        
        # BADC specific attributes
        badcRoleList = (
            'urn:badc:security:authz:1.0:attr:admin', 
            'urn:badc:security:authz:1.0:attr:rapid', 
            'urn:badc:security:authz:1.0:attr:coapec', 
            'urn:badc:security:authz:1.0:attr:midas', 
            'urn:badc:security:authz:1.0:attr:quest', 
            'urn:badc:security:authz:1.0:attr:staff'
        )
        for role in badcRoleList:
            samlUtil.addAttribute("urn:badc:security:authz:1.0:attr", role)
        
        # Make an assertion object
        assertion = samlUtil.buildAssertion()
        
        return assertion
        
    def test01CreateAssertion(self):
         
        assertion = self._createAttributeAssertionHelper()

        
        # Create ElementTree Assertion Element
        assertionElem = AssertionElementTree.toXML(assertion)
        
        self.assert_(ElementTree.iselement(assertionElem))
        
        # Serialise to output 
        xmlOutput = prettyPrint(assertionElem)       
        self.assert_(len(xmlOutput))
        
        print("\n"+"_"*80)
        print(xmlOutput)
        print("_"*80)

    def test02ParseAssertion(self):
        assertion = self._createAttributeAssertionHelper()
        
        # Create ElementTree Assertion Element
        assertionElem = AssertionElementTree.toXML(assertion)
        
        self.assert_(ElementTree.iselement(assertionElem))
        
        # Serialise to output 
        xmlOutput = prettyPrint(assertionElem)       
           
        print("\n"+"_"*80)
        print(xmlOutput)
        print("_"*80)
                
        assertionStream = StringIO()
        assertionStream.write(xmlOutput)
        assertionStream.seek(0)

        tree = ElementTree.parse(assertionStream)
        elem2 = tree.getroot()
        
        assertion2 = AssertionElementTree.fromXML(elem2)
        self.assert_(assertion2)
        
    def test03CreateAttributeQuery(self):
        samlUtil = SAMLUtil()
        samlUtil.firstName = ''
        samlUtil.lastName = ''
        samlUtil.emailAddress = ''
        attributeQuery = samlUtil.buildAttributeQuery(SAMLTestCase.ISSUER_DN,
                                                      SAMLTestCase.NAMEID_VALUE)
        
        elem = AttributeQueryElementTree.toXML(attributeQuery)
        xmlOutput = prettyPrint(elem)
           
        print("\n"+"_"*80)
        print(xmlOutput)
        print("_"*80)

    def test04ParseAttributeQuery(self):
        samlUtil = SAMLUtil()
        samlUtil.firstName = ''
        samlUtil.lastName = ''
        samlUtil.emailAddress = ''
        attributeQuery = samlUtil.buildAttributeQuery(SAMLTestCase.ISSUER_DN,
                                                      SAMLTestCase.NAMEID_VALUE)
        
        elem = AttributeQueryElementTree.toXML(attributeQuery)        
        xmlOutput = prettyPrint(elem)       
        print("\n"+"_"*80)
        print(xmlOutput)
                
        attributeQueryStream = StringIO()
        attributeQueryStream.write(xmlOutput)
        attributeQueryStream.seek(0)

        tree = ElementTree.parse(attributeQueryStream)
        elem2 = tree.getroot()
        
        attributeQuery2 = AttributeQueryElementTree.fromXML(elem2)
        self.assert_(attributeQuery2.id == attributeQuery.id)
        self.assert_(attributeQuery2.issuer.value==attributeQuery.issuer.value)
        self.assert_(attributeQuery2.subject.nameID.value == \
                     attributeQuery.subject.nameID.value)
        
        self.assert_(attributeQuery2.attributes[1].name == \
                     attributeQuery.attributes[1].name)
        
        xmlOutput2 = prettyPrint(elem2)       
        print("_"*80)
        print(xmlOutput2)
        print("_"*80)

    def _createAttributeQueryResponse(self):
        response = Response()
        response.issueInstant = datetime.utcnow()
        
        # Make up a request ID that this response is responding to
        response.inResponseTo = str(uuid4())
        response.id = str(uuid4())
        response.version = SAMLVersion(SAMLVersion.VERSION_20)
            
        response.issuer = Issuer()
        response.issuer.format = Issuer.X509_SUBJECT
        response.issuer.value = \
                        SAMLTestCase.ISSUER_DN
        
        response.status = Status()
        response.status.statusCode = StatusCode()
        response.status.statusCode.value = StatusCode.SUCCESS_URI
        response.status.statusMessage = StatusMessage()        
        response.status.statusMessage.value = "Response created successfully"
           
        assertion = self._createAttributeAssertionHelper()
        
        # Add a conditions statement for a validity of 8 hours
        assertion.conditions = Conditions()
        assertion.conditions.notBefore = datetime.utcnow()
        assertion.conditions.notOnOrAfter = (assertion.conditions.notBefore + 
                                             timedelta(seconds=60*60*8))
        
        assertion.subject = Subject()  
        assertion.subject.nameID = NameID()
        assertion.subject.nameID.format = SAMLTestCase.NAMEID_FORMAT
        assertion.subject.nameID.value = SAMLTestCase.NAMEID_VALUE    
            
        assertion.issuer = Issuer()
        assertion.issuer.format = Issuer.X509_SUBJECT
        assertion.issuer.value = SAMLTestCase.ISSUER_DN

        response.assertions.append(assertion)
        
        return response
        
    def test05CreateAttributeQueryResponse(self):
        response = self._createAttributeQueryResponse()
        
        # Create ElementTree Assertion Element
        responseElem = ResponseElementTree.toXML(response)
        
        self.assert_(ElementTree.iselement(responseElem))
        
        # Serialise to output        
        xmlOutput = prettyPrint(responseElem)       
        self.assert_(len(xmlOutput))
        print("\n"+"_"*80)
        print(xmlOutput)
        print("_"*80)
        
    def _createAuthzDecisionQuery(self):
        authzDecisionQuery = AuthzDecisionQuery()

        authzDecisionQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        authzDecisionQuery.id = str(uuid4())
        authzDecisionQuery.issueInstant = datetime.utcnow()
        
        authzDecisionQuery.issuer = Issuer()
        authzDecisionQuery.issuer.format = Issuer.X509_SUBJECT
        authzDecisionQuery.issuer.value = SAMLTestCase.ISSUER_DN
        
        authzDecisionQuery.subject = Subject()
        authzDecisionQuery.subject.nameID = NameID()
        authzDecisionQuery.subject.nameID.format = SAMLTestCase.NAMEID_FORMAT
        authzDecisionQuery.subject.nameID.value = SAMLTestCase.NAMEID_VALUE
        
        authzDecisionQuery.resource = "http://LOCALHOST:80/My Secured URI"
        
        return authzDecisionQuery
    
    def test06CreateAuthzDecisionQuery(self):
        samlUtil = SAMLUtil()
        authzDecisionQuery = samlUtil.buildAuthzDecisionQuery()
        
        self.assert_(":80" not in authzDecisionQuery.resource)
        self.assert_("localhost" in authzDecisionQuery.resource)
        self.assert_(" " not in authzDecisionQuery.resource)
        
        authzDecisionQuery.resource = \
            "https://Somewhere.ac.uk:443/My Secured URI?blah=4&yes=True"
            
        self.assert_(":443" not in authzDecisionQuery.resource)
        self.assert_("somewhere.ac.uk" in authzDecisionQuery.resource)
        self.assert_("yes=True" in authzDecisionQuery.resource)
        
        authzDecisionQuery.actions.append(Action())
        authzDecisionQuery.actions[0].namespace = Action.GHPP_NS_URI
        authzDecisionQuery.actions[0].value = Action.HTTP_GET_ACTION
        
        self.assert_(
            authzDecisionQuery.actions[0].value == Action.HTTP_GET_ACTION)
        self.assert_(
            authzDecisionQuery.actions[0].namespace == Action.GHPP_NS_URI)
        
        # Try out the restricted vocabulary
        try:
            authzDecisionQuery.actions[0].value = "delete everything"
            self.fail("Expecting AttributeError raised for incorrect action "
                      "setting.")
        except AttributeError, e:
            print("Caught incorrect action type setting: %s" % e)
        
        authzDecisionQuery.actions[0].actionTypes = {'urn:malicious': 
                                                     ("delete everything",)}
        
        # Try again now that the actipn types have been adjusted
        authzDecisionQuery.actions[0].namespace = 'urn:malicious'
        authzDecisionQuery.actions[0].value = "delete everything"
        
    def test07SerializeAuthzDecisionQuery(self):
        samlUtil = SAMLUtil()
        authzDecisionQuery = samlUtil.buildAuthzDecisionQuery()
        
        # Create ElementTree Assertion Element
        authzDecisionQueryElem = AuthzDecisionQueryElementTree.toXML(
                                                            authzDecisionQuery)
        
        self.assert_(ElementTree.iselement(authzDecisionQueryElem))
        
        # Serialise to output 
        xmlOutput = prettyPrint(authzDecisionQueryElem)       
        self.assert_(len(xmlOutput))
        
        print("\n"+"_"*80)
        print(xmlOutput)
        print("_"*80)
   
    def test08DeserializeAuthzDecisionQuery(self):
        samlUtil = SAMLUtil()
        authzDecisionQuery = samlUtil.buildAuthzDecisionQuery()
        
        # Create ElementTree Assertion Element
        authzDecisionQueryElem = AuthzDecisionQueryElementTree.toXML(
                                                            authzDecisionQuery)
        
        self.assert_(ElementTree.iselement(authzDecisionQueryElem))
        
        # Serialise to output 
        xmlOutput = prettyPrint(authzDecisionQueryElem)       
        self.assert_(len(xmlOutput))
        
        authzDecisionQueryStream = StringIO()
        authzDecisionQueryStream.write(xmlOutput)
        authzDecisionQueryStream.seek(0)

        tree = ElementTree.parse(authzDecisionQueryStream)
        elem2 = tree.getroot()
        
        authzDecisionQuery2 = AuthzDecisionQueryElementTree.fromXML(elem2)
        self.assert_(authzDecisionQuery2)
        self.assert_(
        authzDecisionQuery2.subject.nameID.value == SAMLTestCase.NAMEID_VALUE)
        self.assert_(
        authzDecisionQuery2.subject.nameID.format == SAMLTestCase.NAMEID_FORMAT)
        self.assert_(
            authzDecisionQuery2.issuer.value == SAMLTestCase.ISSUER_DN)
        self.assert_(
            authzDecisionQuery2.resource == SAMLTestCase.RESOURCE_URI)
        self.assert_(len(authzDecisionQuery2.actions) == 1)
        self.assert_(
            authzDecisionQuery2.actions[0].value == Action.HTTP_GET_ACTION)
        self.assert_(
            authzDecisionQuery2.actions[0].namespace == Action.GHPP_NS_URI)
        self.assert_(authzDecisionQuery2.evidence is None)

    def _createAuthzDecisionQueryResponse(self):
        """Helper method for Authz Decision Response"""
        response = Response()
        now = datetime.utcnow()
        response.issueInstant = now
        
        # Make up a request ID that this response is responding to
        response.inResponseTo = str(uuid4())
        response.id = str(uuid4())
        response.version = SAMLVersion(SAMLVersion.VERSION_20)
            
        response.issuer = Issuer()
        response.issuer.format = Issuer.X509_SUBJECT
        response.issuer.value = SAMLTestCase.ISSUER_DN
        
        response.status = Status()
        response.status.statusCode = StatusCode()
        response.status.statusCode.value = StatusCode.SUCCESS_URI
        response.status.statusMessage = StatusMessage()        
        response.status.statusMessage.value = "Response created successfully"
           
        assertion = Assertion()
        assertion.version = SAMLVersion(SAMLVersion.VERSION_20)
        assertion.id = str(uuid4())
        assertion.issueInstant = now
        
        authzDecisionStatement = AuthzDecisionStatement()
        authzDecisionStatement.decision = DecisionType.PERMIT
        authzDecisionStatement.resource = SAMLTestCase.RESOURCE_URI
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
        assertion.subject.nameID.format = SAMLTestCase.NAMEID_FORMAT
        assertion.subject.nameID.value = SAMLTestCase.NAMEID_VALUE    
            
        assertion.issuer = Issuer()
        assertion.issuer.format = Issuer.X509_SUBJECT
        assertion.issuer.value = SAMLTestCase.ISSUER_DN

        response.assertions.append(assertion)
        
        return response
        
    def test09CreateAuthzDecisionQueryResponse(self):
        response = self._createAuthzDecisionQueryResponse()
        self.assert_(response.assertions[0])
        self.assert_(response.assertions[0].authzDecisionStatements[0])
        self.assert_(response.assertions[0].authzDecisionStatements[0
            ].decision == DecisionType.PERMIT)
        self.assert_(response.assertions[0].authzDecisionStatements[0
            ].resource == SAMLTestCase.RESOURCE_URI)
        self.assert_(response.assertions[0].authzDecisionStatements[0
            ].decision == DecisionType.PERMIT)
        self.assert_(response.assertions[0].authzDecisionStatements[0
            ].actions[-1].namespace == Action.GHPP_NS_URI)
        self.assert_(response.assertions[0].authzDecisionStatements[0
            ].actions[-1].value == Action.HTTP_GET_ACTION)
     
    def _serializeAuthzDecisionQueryResponse(self):
        response = self._createAuthzDecisionQueryResponse()
        
        # Create ElementTree Assertion Element
        responseElem = ResponseElementTree.toXML(response)
        self.assert_(ElementTree.iselement(responseElem))
        
        # Serialise to output        
        xmlOutput = prettyPrint(responseElem)
        return xmlOutput
    
    def test10SerializeAuthzDecisionQueryResponse(self):
        xmlOutput = self._serializeAuthzDecisionQueryResponse()
        self.assert_(len(xmlOutput))
        print("\n"+"_"*80)
        print(xmlOutput)
        print("_"*80)
        
        self.assert_('AuthzDecisionStatement' in xmlOutput)
        self.assert_('GET' in xmlOutput)
        self.assert_('Permit' in xmlOutput)

    def test11DeserializeAuthzDecisionResponse(self):
        xmlOutput = self._serializeAuthzDecisionQueryResponse()
        
        authzDecisionResponseStream = StringIO()
        authzDecisionResponseStream.write(xmlOutput)
        authzDecisionResponseStream.seek(0)

        tree = ElementTree.parse(authzDecisionResponseStream)
        elem = tree.getroot()
        response = ResponseElementTree.fromXML(elem)
        
        self.assert_(response.assertions[0])
        self.assert_(response.assertions[0].authzDecisionStatements[0])
        self.assert_(response.assertions[0].authzDecisionStatements[0
            ].decision == DecisionType.PERMIT)
        self.assert_(response.assertions[0].authzDecisionStatements[0
            ].resource == SAMLTestCase.RESOURCE_URI)
        self.assert_(response.assertions[0].authzDecisionStatements[0
            ].decision == DecisionType.PERMIT)
        self.assert_(response.assertions[0].authzDecisionStatements[0
            ].actions[-1].namespace == Action.GHPP_NS_URI)
        self.assert_(response.assertions[0].authzDecisionStatements[0
            ].actions[-1].value == Action.HTTP_GET_ACTION)
        
 
    def test12PickleAssertion(self):
        # Test pickling with __slots__
        assertion = self._createAttributeAssertionHelper()
        assertion.issuer = Issuer()
        assertion.issuer.format = Issuer.X509_SUBJECT
        assertion.issuer.value = SAMLTestCase.ISSUER_DN
        
        jar = pickle.dumps(assertion)
        assertion2 = pickle.loads(jar)
        self.assert_(isinstance(assertion2, Assertion))
        self.assert_(assertion2.issuer.value == assertion.issuer.value)
        self.assert_(assertion2.issuer.format == assertion.issuer.format)
        self.assert_(len(assertion2.attributeStatements)==1)
        self.assert_(len(assertion2.attributeStatements[0].attributes) > 0)
        self.assert_(assertion2.attributeStatements[0].attributes[0
                     ].attributeValues[0
                     ].value == assertion.attributeStatements[0].attributes[0
                                ].attributeValues[0].value)
        
    def test13PickleAttributeQuery(self):
        # Test pickling with __slots__
        samlUtil = SAMLUtil()
        samlUtil.firstName = ''
        samlUtil.lastName = ''
        samlUtil.emailAddress = ''
        query = samlUtil.buildAttributeQuery(SAMLTestCase.ISSUER_DN,
                                             SAMLTestCase.NAMEID_VALUE)
        
        jar = pickle.dumps(query)
        query2 = pickle.loads(jar)

        self.assert_(isinstance(query2, AttributeQuery))
        self.assert_(query2.subject.nameID.value == query.subject.nameID.value)
        self.assert_((query2.subject.nameID.format == 
                      query.subject.nameID.format))
        self.assert_(query2.issuer.value == query.issuer.value)
        self.assert_(query2.issuer.format == query.issuer.format)
        self.assert_(query2.issueInstant == query.issueInstant)
        self.assert_(query2.id == query.id)
        self.assert_(len(query2.attributes) == 3)
        self.assert_(query2.attributes[0].name == "urn:esg:first:name")
        self.assert_(query2.attributes[1].nameFormat == SAMLUtil.XSSTRING_NS)

    def test14PickleAttributeQueryResponse(self):
        response = self._createAttributeQueryResponse()
        
        jar = pickle.dumps(response)
        response2 = pickle.loads(jar)
        
        self.assert_(isinstance(response2, Response))
        self.assert_((response2.status.statusCode.value == 
                      response.status.statusCode.value))
        self.assert_((response2.status.statusMessage.value == 
                      response.status.statusMessage.value))
        self.assert_(len(response2.assertions) == 1)
        self.assert_(response2.assertions[0].id == response.assertions[0].id)
        self.assert_((response2.assertions[0].conditions.notBefore == 
                      response.assertions[0].conditions.notBefore))
        self.assert_((response2.assertions[0].conditions.notOnOrAfter == 
                      response.assertions[0].conditions.notOnOrAfter))
        self.assert_(len(response2.assertions[0].attributeStatements) == 1)
        self.assert_(len(response2.assertions[0].attributeStatements[0
                                                            ].attributes) == 9)
        self.assert_(response2.assertions[0].attributeStatements[0].attributes[1
                     ].attributeValues[0
                     ].value == response.assertions[0].attributeStatements[0
                                    ].attributes[1].attributeValues[0].value)
             
    def test15PickleAuthzDecisionQuery(self):
        samlUtil = SAMLUtil()
        query = samlUtil.buildAuthzDecisionQuery()
             
        jar = pickle.dumps(query)
        query2 = pickle.loads(jar)
        
        self.assert_(isinstance(query2, AuthzDecisionQuery))
        self.assert_(query.resource == query2.resource)
        self.assert_(query.version == query2.version)
        self.assert_(len(query2.actions) == 1)
        self.assert_(query2.actions[0].value == Action.HTTP_GET_ACTION)
        self.assert_(query2.actions[0].namespace == Action.GHPP_NS_URI)

    def test16PickleAuthzDecisionResponse(self):
        response = self._createAuthzDecisionQueryResponse()
        
        jar = pickle.dumps(response)
        response2 = pickle.loads(jar)
        
        self.assert_(isinstance(response2, Response))
        
        self.assert_(len(response.assertions) == 1)
        self.assert_(len(response.assertions[0].authzDecisionStatements) == 1)
         
        self.assert_(response.assertions[0].authzDecisionStatements[0
                        ].resource == response2.assertions[0
                                        ].authzDecisionStatements[0].resource)
        
        self.assert_(len(response.assertions[0].authzDecisionStatements[0
                        ].actions) == 1)
        self.assert_(response.assertions[0].authzDecisionStatements[0
                        ].actions[0].value == response2.assertions[0
                                        ].authzDecisionStatements[0
                                                ].actions[0].value)
        
        self.assert_(response2.assertions[0].authzDecisionStatements[0
                        ].actions[0].namespace == Action.GHPP_NS_URI)        

        self.assert_(response2.assertions[0].authzDecisionStatements[0
                        ].decision == DecisionType.PERMIT)        
        
    def test17SAMLDatetime(self):
        # Test parsing of Datetimes following 
        # http://www.w3.org/TR/xmlschema-2/#dateTime 
        
        # No seconds fraction
        self.assert_(SAMLDateTime.fromString('2010-10-20T14:49:50Z'))
        
        self.assertRaises(TypeError, SAMLDateTime.fromString, 
                          None)
        
        
if __name__ == "__main__":
    unittest.main()        
