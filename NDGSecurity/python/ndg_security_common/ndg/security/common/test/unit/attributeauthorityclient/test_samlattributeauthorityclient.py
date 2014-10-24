#!/usr/bin/env python
"""NDG Attribute Authority SAML SOAP Binding client unit tests

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/02/10 (moved from test_attributeauthorityclient)"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
import os
from os import path, environ
from datetime import datetime
import unittest
from uuid import uuid4
from urllib2 import URLError

from ndg.security.common.config import importElementTree
ElementTree = importElementTree()

from ndg.saml.common import SAMLVersion
from ndg.saml.common.xml import SAMLConstants
from ndg.saml.xml.etree import AttributeQueryElementTree, ResponseElementTree
from ndg.saml.saml2.core import (Subject, Issuer, Attribute, NameID, 
                                 AttributeQuery, XSStringAttributeValue)

from ndg.saml.saml2.binding.soap.client import SOAPBinding
from ndg.saml.saml2.binding.soap.client.attributequery import (
                                        AttributeQuerySOAPBinding, 
                                        AttributeQuerySslSOAPBinding)
from ndg.security.common.saml_utils.esgf import (ESGFSamlNamespaces,
                                                 ESGFDefaultQueryAttributes,
                                                 ESGFGroupRoleAttributeValue)
from ndg.security.common.test.unit.base import BaseTestCase
from ndg.security.common.utils.configfileparsers import (
    CaseSensitiveConfigParser)


class AttributeAuthoritySAMLInterfaceTestCase(BaseTestCase):
    """NDG Attribute Authority SAML SOAP Binding client unit tests"""

    HERE_DIR = os.path.dirname(__file__)
    CONFIG_FILENAME = 'test_samlattributeauthorityclient.cfg'
    CONFIG_FILEPATH = os.path.join(HERE_DIR, CONFIG_FILENAME)
    
    def __init__(self, *arg, **kw):
        super(AttributeAuthoritySAMLInterfaceTestCase, self).__init__(*arg, 
                                                                      **kw)

        if 'NDGSEC_AACLNT_UNITTEST_DIR' not in environ:
            environ['NDGSEC_AACLNT_UNITTEST_DIR'
                                        ] = path.abspath(path.dirname(__file__))

        self.cfgParser = CaseSensitiveConfigParser()
        self.cfgFilePath = path.join(environ['NDGSEC_AACLNT_UNITTEST_DIR'],
                                     self.__class__.CONFIG_FILENAME)
        self.cfgParser.read(self.cfgFilePath)
        
        self.cfg = {}
        for section in self.cfgParser.sections():
            self.cfg[section] = dict(self.cfgParser.items(section))
    
    def test01AttributeQuery(self):
        _cfg = self.cfg['test01AttributeQuery']
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "/CN=Authorisation Service/O=Site A"    
                        
        attributeQuery.subject = Subject()
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = \
            ESGFSamlNamespaces.NAMEID_FORMAT #@UndefinedVariable
        attributeQuery.subject.nameID.value = _cfg['subject']
        xsStringNs = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME
        fnAttribute = Attribute()
        fnAttribute.name = ESGFSamlNamespaces.FIRSTNAME_ATTRNAME #@UndefinedVariable
        fnAttribute.nameFormat = xsStringNs
        fnAttribute.friendlyName = "FirstName"

        attributeQuery.attributes.append(fnAttribute)
    
        lnAttribute = Attribute()
        lnAttribute.name = ESGFSamlNamespaces.LASTNAME_ATTRNAME #@UndefinedVariable
        lnAttribute.nameFormat = xsStringNs
        lnAttribute.friendlyName = "LastName"

        attributeQuery.attributes.append(lnAttribute)
    
        emailAddressAttribute = Attribute()
        emailAddressAttribute.name = ESGFSamlNamespaces.EMAILADDRESS_ATTRNAME #@UndefinedVariable
        emailAddressAttribute.nameFormat = xsStringNs
        emailAddressAttribute.friendlyName = "emailAddress"
        
        attributeQuery.attributes.append(emailAddressAttribute) 

        siteAAttribute = Attribute()
        siteAAttribute.name = _cfg['siteAttributeName']
        siteAAttribute.nameFormat = xsStringNs
        
        attributeQuery.attributes.append(siteAAttribute) 

        binding = SOAPBinding()
        binding.serialise = AttributeQueryElementTree.toXML
        binding.deserialise = ResponseElementTree.fromXML
        
        self.assertRaises(URLError, binding.send, attributeQuery, _cfg['uri'])
             
    def test02AttributeQueryInvalidIssuer(self):
        _cfg = self.cfg['test02AttributeQueryInvalidIssuer']
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "/O=Invalid Site/CN=PDP"    
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = \
            ESGFSamlNamespaces.NAMEID_FORMAT #@UndefinedVariable
        attributeQuery.subject.nameID.value = _cfg['subject']
        xsStringNs = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME

        siteAAttribute = Attribute()
        siteAAttribute.name = _cfg['siteAttributeName']
        siteAAttribute.nameFormat = xsStringNs
        
        attributeQuery.attributes.append(siteAAttribute) 

        binding = SOAPBinding()
        binding.serialise = AttributeQueryElementTree.toXML
        binding.deserialise = ResponseElementTree.fromXML
        
        self.assertRaises(URLError, binding.send, attributeQuery, _cfg['uri'])
                   
    def test03AttributeQueryUnknownSubject(self):
        _cfg = self.cfg['test03AttributeQueryUnknownSubject']
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "/CN=Authorisation Service/O=Site A"    
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = \
            ESGFSamlNamespaces.NAMEID_FORMAT #@UndefinedVariable
        attributeQuery.subject.nameID.value = _cfg['subject']
        xsStringNs = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME

        siteAAttribute = Attribute()
        siteAAttribute.name = _cfg['siteAttributeName']
        siteAAttribute.nameFormat = xsStringNs
        
        attributeQuery.attributes.append(siteAAttribute) 

        binding = SOAPBinding()
        binding.serialise = AttributeQueryElementTree.toXML
        binding.deserialise = ResponseElementTree.fromXML
        
        self.assertRaises(URLError, binding.send, attributeQuery, _cfg['uri'])
             
    def test04AttributeQueryInvalidAttrName(self):
        thisSection = 'test04AttributeQueryInvalidAttrName'
        _cfg = self.cfg[thisSection]
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "/CN=Authorisation Service/O=Site A"    
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = \
            ESGFSamlNamespaces.NAMEID_FORMAT #@UndefinedVariable
        attributeQuery.subject.nameID.value = _cfg['subject']
        xsStringNs = SAMLConstants.XSD_NS+"#"+\
                                        XSStringAttributeValue.TYPE_LOCAL_NAME

        invalidAttribute = Attribute()
        invalidAttribute.name = "myInvalidAttributeName"
        invalidAttribute.nameFormat = xsStringNs
        
        attributeQuery.attributes.append(invalidAttribute) 

        binding = SOAPBinding.fromConfig(
                     AttributeAuthoritySAMLInterfaceTestCase.CONFIG_FILEPATH, 
                     prefix='saml.', 
                     section=thisSection)
        
        self.assertRaises(URLError, binding.send, attributeQuery, _cfg['uri'])
             
    def test05AttributeQueryWithESGFAttributeType(self):
        # Test interface with custom ESGF Group/Role attribute type
        thisSection = 'test05AttributeQueryWithESGFAttributeType'
        _cfg = self.cfg[thisSection]
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = "/CN=Authorisation Service/O=Site A"    
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = \
            ESGFSamlNamespaces.NAMEID_FORMAT #@UndefinedVariable
        attributeQuery.subject.nameID.value = _cfg['subject']
        
        groupRoleAttribute = Attribute()
        groupRoleAttribute.name = self.__class__.ATTRIBUTE_NAMES[-1]
        groupRoleAttribute.nameFormat = \
            ESGFGroupRoleAttributeValue.TYPE_LOCAL_NAME
        
        attributeQuery.attributes.append(groupRoleAttribute) 

        binding = SOAPBinding.fromConfig(
                     AttributeAuthoritySAMLInterfaceTestCase.CONFIG_FILEPATH, 
                     prefix='saml.',
                     section=thisSection)
        
        self.assertRaises(URLError, binding.send, attributeQuery, _cfg['uri'])
       
    def test06AttributeQuerySOAPBindingInterface(self):
        _cfg = self.cfg['test06AttributeQuerySOAPBindingInterface']
        
        binding = AttributeQuerySOAPBinding()
        
        binding.subjectIdFormat = \
            ESGFSamlNamespaces.NAMEID_FORMAT #@UndefinedVariable
        binding.issuerName = \
            str(AttributeAuthoritySAMLInterfaceTestCase.VALID_REQUESTOR_IDS[0])
        binding.issuerFormat = Issuer.X509_SUBJECT
        
        binding.queryAttributes = ESGFDefaultQueryAttributes.ATTRIBUTES

        query = binding.makeQuery()
        binding.setQuerySubjectId(query,
                            AttributeAuthoritySAMLInterfaceTestCase.OPENID_URI)

        self.assertRaises(URLError, binding.send, query, uri=_cfg['uri'])

    def test07AttributeQueryFromConfig(self):
        thisSection = 'test07AttributeQueryFromConfig'
        _cfg = self.cfg[thisSection]
        
        binding = AttributeQuerySOAPBinding.fromConfig(self.cfgFilePath, 
                                                       section=thisSection,
                                                       prefix='attributeQuery.')
        query = binding.makeQuery()
        binding.setQuerySubjectId(query, _cfg['subject'])
        
        self.assertRaises(URLError, binding.send, query, uri=_cfg['uri'])
        
    def test08AttributeQuerySslSOAPBindingInterface(self):
        thisSection = 'test08AttributeQuerySslSOAPBindingInterface'
        _cfg = self.cfg[thisSection]
        
        binding = AttributeQuerySslSOAPBinding.fromConfig(self.cfgFilePath, 
                                                       section=thisSection,
                                                       prefix='attributeQuery.')
        
        query = binding.makeQuery()
        binding.setQuerySubjectId(query, _cfg['subject'])
        
        self.assertRaises(URLError, binding.send, query, uri=_cfg['uri'])

       
if __name__ == "__main__":
    unittest.main()
