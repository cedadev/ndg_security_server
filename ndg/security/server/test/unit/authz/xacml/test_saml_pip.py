"""Unit tests for XACML Policy Information Point with SAML interface to 
Attribute Authority

"""
__author__ = "P J Kershaw"
__date__ = "11/08/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

from os import path
from urllib.error import URLError
import unittest

from ndg.xacml.core.attributedesignator import SubjectAttributeDesignator
from ndg.xacml.core.attribute import Attribute
from ndg.xacml.core.attributevalue import AttributeValueClassFactory
from ndg.xacml.core.context.request import Request
from ndg.xacml.core.context.subject import Subject

from ndg.saml.saml2.core import Issuer as SamlIssuer

from ndg.security.server.test.base import BaseTestCase
from ndg.security.server.test.test_util import TestUserDatabase
from ndg.security.server.xacml.pip.saml_pip import PIP


class SamlPipTestCase(BaseTestCase):
    """Test XACML Policy Information Point.  This PIP has a SAML interface to
    query a remote attribute authority for attributes
    """
    THIS_DIR = path.abspath(path.dirname(__file__))
    MAPPING_FILENAME = "pip-mapping.txt"
    MAPPING_FILEPATH = path.join(THIS_DIR, MAPPING_FILENAME)
    CONFIG_FILENAME = 'saml_pip.cfg'
    CONFIG_FILEPATH = path.join(THIS_DIR, CONFIG_FILENAME)
    
    NDGS_ATTR_ID = TestUserDatabase.ATTRIBUTE_NAMES[0]
    OPENID_URI = TestUserDatabase.OPENID_URI
    OPENID_ATTR_ID = 'urn:esg:openid'
    
    CLNT_CERT_FILEPATH = path.join(BaseTestCase.PKI_DIR, 'localhost.crt')
    CLNT_PRIKEY_FILEPATH = path.join(BaseTestCase.PKI_DIR, 'localhost.key')
                                   
    attributeValueClassFactory = AttributeValueClassFactory()
      
    def test01CreateAndCheckAttributes(self):
        pip = PIP()
        self.assertTrue(pip)
        self.assertTrue(pip.mappingFilePath is None)
        try:
            pip.attribute2AttributeAuthorityMap = {}
            self.fail("pip.attribute2AttributeAuthorityMap should be read-only")
        except AttributeError:
            pass
        
        setattr(pip, 'sessionCacheDataDir', 'My data dir')
        self.assertTrue(pip.sessionCacheDataDir == 'My data dir')
        self.assertTrue(pip.sessionCacheTimeout is None)
        
        try:
            pip.sessionCacheTimeout = {}
            self.fail("pip.sessionCacheTimeout accepts only float/int/long/"
                      "string or None type value")
        except TypeError:
            pass
        
        pip.sessionCacheTimeout = 86400
        self.assertTrue(pip.sessionCacheTimeout == 86400)

        # Check default
        self.assertTrue(pip.sessionCacheAssertionClockSkewTol == 1.0)
        
        try:
            pip.sessionCacheAssertionClockSkewTol = []
            self.fail("pip.sessionCacheAssertionClockSkewTol accepts only "
                      "float/int/long/string or None type value")
        except TypeError:
            pass
        
        pip.sessionCacheAssertionClockSkewTol = 0.3
        self.assertTrue(pip.sessionCacheAssertionClockSkewTol == 0.3)
        
    def test02ReadMappingFile(self):
        pip = PIP()
        pip.mappingFilePath = self.__class__.MAPPING_FILEPATH
        pip.readMappingFile()
        self.assertTrue(len(list(pip.attribute2AttributeAuthorityMap.keys())) > 0)
        self.assertTrue(self.__class__.NDGS_ATTR_ID in
                     pip.attribute2AttributeAuthorityMap)
        print((pip.attribute2AttributeAuthorityMap))
        
    @classmethod
    def _createXacmlRequestCtx(cls):
        """Helper to create a XACML request context"""
        ctx = Request()
        
        ctx.subjects.append(Subject())
        openidAttr = Attribute()
        ctx.subjects[-1].attributes.append(openidAttr)
        openidAttr.attributeId = cls.OPENID_ATTR_ID
        openidAttr.dataType = 'http://www.w3.org/2001/XMLSchema#anyURI'
        
        anyUriAttrValue = cls.attributeValueClassFactory(openidAttr.dataType)
        
        openidAttrVal = anyUriAttrValue(TestUserDatabase.OPENID_URI)
        openidAttr.attributeValues.append(openidAttrVal) 
        
        return ctx
    
    @classmethod
    def _createPIP(cls):   
        """Create PIP from test attribute settings"""              
        pip = PIP()
        pip.mappingFilePath = cls.MAPPING_FILEPATH
        pip.readMappingFile()
        
        pip.attribute_query.subject.nameID.value = cls.OPENID_URI
        pip.attribute_query.subject.nameID.format = cls.OPENID_ATTR_ID
        
        pip.attribute_query.issuer.value = 'O=NDG, OU=Security, CN=localhost'
        pip.attribute_query.issuer.format = SamlIssuer.X509_SUBJECT
        
        pip.attribute_query_binding.sslCertFilePath = cls.CLNT_CERT_FILEPATH
        pip.attribute_query_binding.sslPriKeyFilePath = cls.CLNT_PRIKEY_FILEPATH
            
        pip.attribute_query_binding.sslCACertDir = cls.CACERT_DIR
        
        return pip

    @classmethod
    def _createSubjectAttributeDesignator(cls):
        '''Make attribute designator - in practice this would be passed back 
        from the PDP via the context handler
        '''
        designator = SubjectAttributeDesignator()
        designator.attributeId = cls.NDGS_ATTR_ID
        designator.dataType = 'http://www.w3.org/2001/XMLSchema#string'
        
        stringAttrValue = cls.attributeValueClassFactory(
                                    'http://www.w3.org/2001/XMLSchema#string')
        
        return designator
    
    @classmethod
    def _initQuery(cls):
        '''Convenience method to set-up the parameters needed for a query'''
        pip = cls._createPIP()
        designator = cls._createSubjectAttributeDesignator()
        ctx = cls._createXacmlRequestCtx()
        return pip, designator, ctx
        
        
if __name__ == "__main__":
    unittest.main()