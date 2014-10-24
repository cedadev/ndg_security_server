#!/usr/bin/env python
"""Test ESG Attribute Service - based on NDG SAML Attribute Authority unit
tests

"""
__author__ = "P J Kershaw"
__date__ = "02/08/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
import os
import unittest

from datetime import datetime

from ndg.security.common.config import Config, importElementTree
ElementTree = importElementTree()

from ndg.saml.saml2.core import StatusCode
from ndg.saml.saml2.binding.soap.client.attributequery import (
                                        AttributeQuerySslSOAPBinding)

from ndg.security.common.saml_utils.esgf.xml.etree import ESGFResponseElementTree
from ndg.security.common.utils.etree import prettyPrint
from ndg.security.common.utils.configfileparsers import (
    CaseSensitiveConfigParser)

   
class EsgAttributeServiceIntegrationTestCase(unittest.TestCase):
    """NDG Attribute Authority SAML SOAP Binding client unit tests"""
    HERE_DIR = os.path.dirname(__file__)
    CONFIG_FILENAME = 'test_attributeserviceclient.cfg'
    CONFIG_FILEPATH = os.path.join(HERE_DIR, CONFIG_FILENAME)
    
    def __init__(self, *arg, **kw):
        self.cfgParser = CaseSensitiveConfigParser()
        self.cfgParser.read(self.__class__.CONFIG_FILEPATH)
        
        super(EsgAttributeServiceIntegrationTestCase, self).__init__(*arg, **kw)
                
    def _attributeQuery(self, thisSection):
        
        uri = self.cfgParser.get(thisSection, 'uri')
        print("Testing %s ..." % thisSection)
        print("Calling Attribute Service %r ..." % uri)
        
        binding = AttributeQuerySslSOAPBinding.fromConfig(
                                                self.__class__.CONFIG_FILEPATH, 
                                                section=thisSection,
                                                prefix='attributeQuery.')
        
        binding.subjectID = self.cfgParser.get(thisSection, 'subject')
        
        response = binding.send(uri=uri)
        
        # ESGFResponseElementTree has an extension to support ESG Group/Role 
        # Attribute Value 
        samlResponseElem = ESGFResponseElementTree.toXML(response)
        
        print("SAML Response ...")
#        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(response.status.statusCode.value==StatusCode.SUCCESS_URI)
#        
#    def test01ncarAttributeQuery(self):
#        self._attributeQuery('test01ncarAttributeQuery')
        
    def test02pcmdiAttributeQuery(self):
        self._attributeQuery('test02pcmdiAttributeQuery')
        
    def test03pcmdiAttributeQuery(self):
        self._attributeQuery('test03pcmdiAttributeQuery')
        
#    def test04cedaAttributeQuery(self):
#        self._attributeQuery('test04cedaAttributeQuery')

       
if __name__ == "__main__":
    unittest.main()
