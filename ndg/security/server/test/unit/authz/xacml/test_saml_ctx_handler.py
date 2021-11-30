"""Unit tests XACML Context handler.  This PIP presents a SAML interface for its
Policy Enforcement Point and has a SAML interface to query a remote attribute 
authority for attributes
"""
__author__ = "P J Kershaw"
__date__ = "13/08/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

from os import path
import unittest

from configparser import SafeConfigParser
from ndg.security.server.test.base import BaseTestCase
from ndg.security.server.xacml.ctx_handler.saml_ctx_handler import SamlCtxHandler


class SamlCtxHandlerTestCase(BaseTestCase):
    """Test XACML Context handler.  This PIP presents a SAML interface for its
    Policy Enforcement Point and has a SAML interface to query a remote 
    attribute authority for attributes
    """
    THIS_DIR = path.abspath(path.dirname(__file__))
    CONFIG_FILENAME = 'saml_ctx_handler.cfg'
    CONFIG_FILEPATH = path.join(THIS_DIR, CONFIG_FILENAME)
        
    def test01Init(self):
        handler = SamlCtxHandler()
        self.assertTrue(handler)
        
    def test02InitFromConfigFile(self):
        # Initialise from settings in a config file
        handler = SamlCtxHandler.fromConfig(self.__class__.CONFIG_FILEPATH)
        self.assertTrue(handler)
        self.assertTrue(handler.policyFilePath)
        
    def test03InitFromKeywords(self):
        # Initialise from a dictionary
        
        # Populate by reading from the config file
        cfg = SafeConfigParser(defaults={'here': self.__class__.THIS_DIR})
        cfg.optionxform = str
        cfg.read(self.__class__.CONFIG_FILEPATH)
        kw = dict(cfg.items('DEFAULT'))
        
        handler = SamlCtxHandler.fromKeywords(**kw)
        self.assertTrue(handler)
        self.assertTrue(handler.pip.attributeQuery)
        self.assertTrue(handler.policyFilePath)
        self.assertTrue(handler.issuerName)
        self.assertTrue(handler.issuerFormat)
        self.assertTrue(handler.assertionLifetime)
        self.assertTrue(handler.xacmlExtFunc)
        
        
if __name__ == "__main__":
    unittest.main()