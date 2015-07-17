#!/usr/bin/env python
"""NDG Attribute Authority

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/12/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import unittest
import os
import logging
logging.basicConfig(level=logging.DEBUG)

from warnings import warn
from uuid import uuid4
from datetime import datetime
from os import path
import pickle

from ndg.security.server.test.base import BaseTestCase

from ndg.security.common.utils.configfileparsers import (
    CaseSensitiveConfigParser)
from ndg.security.server.attributeauthority import (AttributeAuthority, 
    SQLAlchemyAttributeInterface, InvalidAttributeFormat, AttributeInterface)

from ndg.saml.saml2.core import (Response, Attribute, SAMLVersion, Subject, 
                                 NameID, Issuer, AttributeQuery, 
                                 XSStringAttributeValue, Status, StatusMessage, 
                                 StatusCode)
from ndg.saml.xml import XMLConstants
from ndg.security.common.saml_utils.esgf import ESGFSamlNamespaces

THIS_DIR = path.dirname(__file__)


class AttributeAuthorityTestCase(BaseTestCase):
    THIS_DIR = THIS_DIR
    PROPERTIES_FILENAME = 'test_attributeauthority.cfg'
    PROPERTIES_FILEPATH = path.join(THIS_DIR, PROPERTIES_FILENAME)
    ASSERTION_LIFETIME = "86400"

    def test01ParsePropertiesFile(self):
        cls = AttributeAuthorityTestCase
        aa = AttributeAuthority.fromPropertyFile(cls.PROPERTIES_FILEPATH)
        self.assert_(aa)
        self.assert_(aa.assertionLifetime == 3600)
        
    def _createAttributeAuthorityHelper(self):
        """Helper method to creat an Attribute Authority instance for use with 
        tests
        """
        
        cls = AttributeAuthorityTestCase
        
        attributeInterfaceClassName = ('ndg.security.server.attributeauthority.'
                                       'AttributeInterface')
        
        aa = AttributeAuthority.fromProperties(
                    assertionLifetime=cls.ASSERTION_LIFETIME,
                    attributeInterface_className=attributeInterfaceClassName)
        
        return aa
            
    def test02FromProperties(self):
        
        cls = AttributeAuthorityTestCase
        aa = self._createAttributeAuthorityHelper()
        
        self.assert_(aa)
        
        # Check lifetime property converted from string input to float
        self.assert_(aa.assertionLifetime == float(cls.ASSERTION_LIFETIME))
        self.assert_(isinstance(aa.attributeInterface, AttributeInterface))

    def test03Pickle(self):
        # Test pickling with __slots__
        aa = self._createAttributeAuthorityHelper()        
        jar = pickle.dumps(aa)
        aa2 = pickle.loads(jar)
        
        self.assert_(aa2)
        self.assert_(aa2.assertionLifetime == aa.assertionLifetime)
        self.assert_(isinstance(aa2.attributeInterface, AttributeInterface))
    
        
class SQLAlchemyAttributeInterfaceTestCase(BaseTestCase):
    THIS_DIR = THIS_DIR
    PROPERTIES_FILENAME = 'test_sqlalchemyattributeinterface.cfg'
    PROPERTIES_FILEPATH = path.join(THIS_DIR, PROPERTIES_FILENAME)
    
    SAML_SUBJECT_SQLQUERY = ("select count(*) from users where openid = "
                             "'${userId}'")
    
    SAML_FIRSTNAME_SQLQUERY = ("select firstname from users where openid = "
                               "'${userId}'")
            
    SAML_LASTNAME_SQLQUERY = ("select lastname from users where openid = "
                              "'${userId}'")
        
    SAML_EMAILADDRESS_SQLQUERY = ("select emailaddress from users where "
                                  "openid = '${userId}'")
        
    SAML_ATTRIBUTES_SQLQUERY = ("select attributename from attributes, users "
                                "where users.openid = '${userId}' and "
                                "attributes.username = users.username")
                                
    def __init__(self, *arg, **kw):
        super(SQLAlchemyAttributeInterfaceTestCase, self).__init__(*arg, **kw)
        self.skipTests = False
        try:
            import sqlalchemy

        except NotImplementedError:
            # Don't proceed with tests because SQLAlchemy is not installed
            warn("Skipping SQLAlchemyAttributeInterfaceTestCase because "
                 "SQLAlchemy is not installed")
            self.skipTests = True
        
        if 'NDGSEC_AA_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_AA_UNITTEST_DIR'
                       ] = os.path.abspath(os.path.dirname(__file__))
            
        self.init_db()
        
    def test01TrySamlAttribute2SqlQuery__setattr__(self):
        if self.skipTests:
            return
        
        attributeInterface = SQLAlchemyAttributeInterface()
        
        # Define queries for SAML attribute names
        attributeInterface.samlAttribute2SqlQuery_firstName = '"%s" "%s"' % (
            ESGFSamlNamespaces.FIRSTNAME_ATTRNAME,                                                               
            SQLAlchemyAttributeInterfaceTestCase.SAML_FIRSTNAME_SQLQUERY)
            
        setattr(attributeInterface, 
                'samlAttribute2SqlQuery.lastName',
                "%s %s" % (ESGFSamlNamespaces.LASTNAME_ATTRNAME,
                SQLAlchemyAttributeInterfaceTestCase.SAML_LASTNAME_SQLQUERY))
        
        attributeInterface.samlAttribute2SqlQuery[
            ESGFSamlNamespaces.EMAILADDRESS_ATTRNAME] = (
                SQLAlchemyAttributeInterfaceTestCase.SAML_EMAILADDRESS_SQLQUERY)
        
        attributeInterface.samlAttribute2SqlQuery[
            SQLAlchemyAttributeInterfaceTestCase.ATTRIBUTE_NAMES[0]] = (
            SQLAlchemyAttributeInterfaceTestCase.SAML_ATTRIBUTES_SQLQUERY)
        
    def test02SetProperties(self):
        # test setProperties interface for instance attribute assignment
        if self.skipTests:
            return
        
        # samlAttribute2SqlQuery* suffixes have no particular requirement
        # only that they are unique and start with an underscore or period.
        properties = {
            'connectionString': 
                SQLAlchemyAttributeInterfaceTestCase.DB_CONNECTION_STR,
            
            'samlSubjectSqlQuery':
                SQLAlchemyAttributeInterfaceTestCase.SAML_SUBJECT_SQLQUERY,
                
            'samlAttribute2SqlQuery.firstname': '"%s" "%s"' % (
                ESGFSamlNamespaces.FIRSTNAME_ATTRNAME,
                SQLAlchemyAttributeInterfaceTestCase.SAML_FIRSTNAME_SQLQUERY),
            
            'samlAttribute2SqlQuery.blah': '"%s" "%s"' % (
                ESGFSamlNamespaces.LASTNAME_ATTRNAME,
                SQLAlchemyAttributeInterfaceTestCase.SAML_LASTNAME_SQLQUERY),
        
            'samlAttribute2SqlQuery.3': '%s "%s"' % (
            ESGFSamlNamespaces.EMAILADDRESS_ATTRNAME,
            SQLAlchemyAttributeInterfaceTestCase.SAML_EMAILADDRESS_SQLQUERY),
        
            'samlAttribute2SqlQuery_0': '%s %s' % (
                SQLAlchemyAttributeInterfaceTestCase.ATTRIBUTE_NAMES[0],
                SQLAlchemyAttributeInterfaceTestCase.SAML_ATTRIBUTES_SQLQUERY),
            
            'samlValidRequestorDNs': ('/O=STFC/OU=CEDA/CN=AuthorisationService',
                                      '/O=ESG/OU=NCAR/CN=Gateway'),
            'samlAssertionLifetime': 86400,

        }
        attributeInterface = SQLAlchemyAttributeInterface()
        attributeInterface.setProperties(**properties)
        
        self.assert_(
            attributeInterface.samlAttribute2SqlQuery[
                ESGFSamlNamespaces.FIRSTNAME_ATTRNAME] == \
            SQLAlchemyAttributeInterfaceTestCase.SAML_FIRSTNAME_SQLQUERY)
        
        self.assert_(attributeInterface.connectionString == \
                     SQLAlchemyAttributeInterfaceTestCase.DB_CONNECTION_STR)
        
        # Test constructor setting properties
        attributeInterface2 = SQLAlchemyAttributeInterface(**properties)
        self.assert_(attributeInterface2.samlAssertionLifetime.days == 1)

    def test03FromConfigFile(self):
        if self.skipTests:
            return
        cfgParser = CaseSensitiveConfigParser()
        cls = SQLAlchemyAttributeInterfaceTestCase
        cfgFilePath = cls.PROPERTIES_FILEPATH
        cfgParser.read(cfgFilePath)
        
        cfg = dict(cfgParser.items('DEFAULT'))
        attributeInterface = SQLAlchemyAttributeInterface()
        attributeInterface.setProperties(prefix='attributeInterface.', **cfg)
        
        self.assert_(
            attributeInterface.samlAttribute2SqlQuery[
                ESGFSamlNamespaces.EMAILADDRESS_ATTRNAME] == \
            SQLAlchemyAttributeInterfaceTestCase.SAML_EMAILADDRESS_SQLQUERY)

    def test04SamlAttributeQuery(self):
        if self.skipTests:
            return
        
        # Prepare a client query
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = '/O=ESG/OU=NCAR/CN=Gateway'
                        
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = ESGFSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = \
                                SQLAlchemyAttributeInterfaceTestCase.OPENID_URI
        
        fnAttribute = Attribute()
        fnAttribute.name = ESGFSamlNamespaces.FIRSTNAME_ATTRNAME
        fnAttribute.nameFormat = XSStringAttributeValue.DEFAULT_FORMAT
        fnAttribute.friendlyName = "FirstName"

        attributeQuery.attributes.append(fnAttribute)
    
        lnAttribute = Attribute()
        lnAttribute.name = ESGFSamlNamespaces.LASTNAME_ATTRNAME
        lnAttribute.nameFormat = XSStringAttributeValue.DEFAULT_FORMAT
        lnAttribute.friendlyName = "LastName"

        attributeQuery.attributes.append(lnAttribute)
    
        emailAddressAttribute = Attribute()
        emailAddressAttribute.name = ESGFSamlNamespaces.EMAILADDRESS_ATTRNAME
        emailAddressAttribute.nameFormat = XSStringAttributeValue.DEFAULT_FORMAT
        emailAddressAttribute.friendlyName = "EmailAddress"

        attributeQuery.attributes.append(emailAddressAttribute)                                   
    
        authzAttribute = Attribute()
        authzAttribute.name = \
            SQLAlchemyAttributeInterfaceTestCase.ATTRIBUTE_NAMES[0]
        authzAttribute.nameFormat = XSStringAttributeValue.DEFAULT_FORMAT
        authzAttribute.friendlyName = "authz"

        attributeQuery.attributes.append(authzAttribute)                                   
        
        # Add the response - the interface will populate with an assertion as
        # appropriate
        samlResponse = Response()
        
        samlResponse.issueInstant = datetime.utcnow()
        samlResponse.id = str(uuid4())
        samlResponse.issuer = Issuer()
        
        # Initialise to success status but reset on error
        samlResponse.status = Status()
        samlResponse.status.statusCode = StatusCode()
        samlResponse.status.statusMessage = StatusMessage()
        samlResponse.status.statusCode.value = StatusCode.SUCCESS_URI
        
        # Nb. SAML 2.0 spec says issuer format must be omitted
        samlResponse.issuer.value = "CEDA"
        
        samlResponse.inResponseTo = attributeQuery.id
        
        # Set up the interface object
        
        # Define queries for SAML attribute names
        samlAttribute2SqlQuery = {
            ESGFSamlNamespaces.FIRSTNAME_ATTRNAME: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_FIRSTNAME_SQLQUERY,
            
            ESGFSamlNamespaces.LASTNAME_ATTRNAME: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_LASTNAME_SQLQUERY,
        
            ESGFSamlNamespaces.EMAILADDRESS_ATTRNAME: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_EMAILADDRESS_SQLQUERY,
        
            SQLAlchemyAttributeInterfaceTestCase.ATTRIBUTE_NAMES[0]: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_ATTRIBUTES_SQLQUERY                    
        }
        
        attributeInterface = SQLAlchemyAttributeInterface(
                                samlAttribute2SqlQuery=samlAttribute2SqlQuery)
        
        attributeInterface.connectionString = \
                        SQLAlchemyAttributeInterfaceTestCase.DB_CONNECTION_STR
                
        attributeInterface.samlValidRequestorDNs = (
            '/O=STFC/OU=CEDA/CN=AuthorisationService',
            '/O=ESG/OU=NCAR/CN=Gateway')
        
        attributeInterface.setProperties(samlAssertionLifetime=28800.)
        
        attributeInterface.samlSubjectSqlQuery = (
            SQLAlchemyAttributeInterfaceTestCase.SAML_SUBJECT_SQLQUERY)
        
        # Make the query
        attributeInterface.getAttributes(attributeQuery, samlResponse)
        
        self.assert_(
                samlResponse.status.statusCode.value == StatusCode.SUCCESS_URI)
        self.assert_(samlResponse.inResponseTo == attributeQuery.id)
        self.assert_(samlResponse.assertions[0].subject.nameID.value == \
                     attributeQuery.subject.nameID.value)
        self.assert_(
            samlResponse.assertions[0].attributeStatements[0].attributes[1
                ].attributeValues[0].value == 'Kershaw')
        
        self.assert_(
            len(samlResponse.assertions[0].attributeStatements[0].attributes[3
                ].attributeValues) == \
                    SQLAlchemyAttributeInterfaceTestCase.N_ATTRIBUTE_VALUES)

    def test05SamlAttributeQuery(self):
        if self.skipTests:
            return
        
        # Prepare a client query
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = '/O=ESG/OU=NCAR/CN=Gateway'
                        
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = ESGFSamlNamespaces.NAMEID_FORMAT
        attributeQuery.subject.nameID.value = \
                                SQLAlchemyAttributeInterfaceTestCase.OPENID_URI
    
        emailAddressAttribute = Attribute()
        emailAddressAttribute.name = ESGFSamlNamespaces.EMAILADDRESS_ATTRNAME
        emailAddressAttribute.nameFormat = "InvalidFormat"
        emailAddressAttribute.friendlyName = "EmailAddress"

        attributeQuery.attributes.append(emailAddressAttribute)                                   
    
        authzAttribute = Attribute()
        authzAttribute.name = \
            SQLAlchemyAttributeInterfaceTestCase.ATTRIBUTE_NAMES[0]
        authzAttribute.nameFormat = XSStringAttributeValue.DEFAULT_FORMAT
        authzAttribute.friendlyName = "authz"

        attributeQuery.attributes.append(authzAttribute)                                   
        
        # Add the response - the interface will populate with an assertion as
        # appropriate
        samlResponse = Response()
        
        samlResponse.issueInstant = datetime.utcnow()
        samlResponse.id = str(uuid4())
        samlResponse.issuer = Issuer()
        
        # Initialise to success status but reset on error
        samlResponse.status = Status()
        samlResponse.status.statusCode = StatusCode()
        samlResponse.status.statusMessage = StatusMessage()
        samlResponse.status.statusCode.value = StatusCode.SUCCESS_URI
        
        # Nb. SAML 2.0 spec says issuer format must be omitted
        samlResponse.issuer.value = "CEDA"
        
        samlResponse.inResponseTo = attributeQuery.id
        
        # Set up the interface object
        
        # Define queries for SAML attribute names
        samlAttribute2SqlQuery = {
            ESGFSamlNamespaces.FIRSTNAME_ATTRNAME: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_FIRSTNAME_SQLQUERY,
            
            ESGFSamlNamespaces.LASTNAME_ATTRNAME: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_LASTNAME_SQLQUERY,
        
            ESGFSamlNamespaces.EMAILADDRESS_ATTRNAME: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_EMAILADDRESS_SQLQUERY,
        
            SQLAlchemyAttributeInterfaceTestCase.ATTRIBUTE_NAMES[0]: 
                SQLAlchemyAttributeInterfaceTestCase.SAML_ATTRIBUTES_SQLQUERY
        }
        
        attributeInterface = SQLAlchemyAttributeInterface(
                                samlAttribute2SqlQuery=samlAttribute2SqlQuery)
        
        attributeInterface.connectionString = \
                        SQLAlchemyAttributeInterfaceTestCase.DB_CONNECTION_STR
                
        attributeInterface.samlValidRequestorDNs = (
            '/O=STFC/OU=CEDA/CN=AuthorisationService',
            '/O=ESG/OU=NCAR/CN=Gateway')
        
        attributeInterface.setProperties(samlAssertionLifetime=28800.)
        
        attributeInterface.samlSubjectSqlQuery = (
            SQLAlchemyAttributeInterfaceTestCase.SAML_SUBJECT_SQLQUERY)
        
        # Make the query
        try:
            attributeInterface.getAttributes(attributeQuery, samlResponse)
        except InvalidAttributeFormat:
            print("PASSED: caught InvalidAttributeFormat exception")
        else:
            self.fail("Expecting InvalidAttributeFormat exception")
        
if __name__ == "__main__":
    unittest.main()
