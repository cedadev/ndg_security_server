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
import unittest

from urllib2 import URLError

from ndg.xacml.core.attributedesignator import SubjectAttributeDesignator
from ndg.xacml.core.attribute import Attribute
from ndg.xacml.core.attributevalue import AttributeValueClassFactory
from ndg.xacml.core.context.request import Request
from ndg.xacml.core.context.subject import Subject

from ndg.saml.saml2.core import Issuer as SamlIssuer

from ndg.security.test.unit.base import BaseTestCase
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
    
    NDGS_ATTR_ID = BaseTestCase.ATTRIBUTE_NAMES[0]
    OPENID_ATTR_ID = 'urn:esg:openid'
    
    CLNT_CERT_FILEPATH = path.join(BaseTestCase.PKI_DIR, 'localhost.crt')
    CLNT_PRIKEY_FILEPATH = path.join(BaseTestCase.PKI_DIR, 'localhost.key')
                                   
    attributeValueClassFactory = AttributeValueClassFactory()
            
    def test01CreateAndCheckAttributes(self):
        pip = PIP()
        self.assert_(pip)
        self.assert_(pip.mappingFilePath is None)
        try:
            pip.attribute2AttributeAuthorityMap = {}
            self.fail("pip.attribute2AttributeAuthorityMap should be read-only")
        except AttributeError:
            pass
        
        setattr(pip, 'sessionCacheDataDir', 'My data dir')
        self.assert_(pip.sessionCacheDataDir == 'My data dir')
        self.assert_(pip.sessionCacheTimeout is None)
        
        try:
            pip.sessionCacheTimeout = {}
            self.fail("pip.sessionCacheTimeout accepts only float/int/long/"
                      "string or None type value")
        except TypeError:
            pass
        
        pip.sessionCacheTimeout = 86400L
        self.assert_(pip.sessionCacheTimeout == 86400L)

        # Check default
        self.assert_(pip.sessionCacheAssertionClockSkewTol == 1.0)
        
        try:
            pip.sessionCacheAssertionClockSkewTol = []
            self.fail("pip.sessionCacheAssertionClockSkewTol accepts only "
                      "float/int/long/string or None type value")
        except TypeError:
            pass
        
        pip.sessionCacheAssertionClockSkewTol = 0.3
        self.assert_(pip.sessionCacheAssertionClockSkewTol == 0.3)
        
    def test02ReadMappingFile(self):
        pip = PIP()
        pip.mappingFilePath = self.__class__.MAPPING_FILEPATH
        pip.readMappingFile()
        self.assert_(len(pip.attribute2AttributeAuthorityMap.keys()) > 0)
        self.assert_(self.__class__.NDGS_ATTR_ID in
                     pip.attribute2AttributeAuthorityMap)
        print(pip.attribute2AttributeAuthorityMap)
        
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
        
        openidAttrVal = anyUriAttrValue(cls.OPENID_URI)
        openidAttr.attributeValues.append(openidAttrVal) 
        
        return ctx
    
    @classmethod
    def _createPIP(cls):   
        """Create PIP from test attribute settings"""              
        pip = PIP()
        pip.mappingFilePath = cls.MAPPING_FILEPATH
        pip.readMappingFile()
        pip.subjectAttributeId = cls.OPENID_ATTR_ID
        
        pip.attributeQueryBinding.issuerName = \
                                            'O=NDG, OU=Security, CN=localhost'
        pip.attributeQueryBinding.issuerFormat = SamlIssuer.X509_SUBJECT
        pip.attributeQueryBinding.sslCertFilePath = cls.CLNT_CERT_FILEPATH
        pip.attributeQueryBinding.sslPriKeyFilePath = cls.CLNT_PRIKEY_FILEPATH
            
        pip.attributeQueryBinding.sslCACertDir = cls.CACERT_DIR
        
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
    
    def test03Query(self):
        self.startSiteAAttributeAuthority(withSSL=True, 
                    port=self.__class__.SITEA_SSL_ATTRIBUTEAUTHORITY_PORTNUM)
        
        pip, designator, ctx = self.__class__._initQuery()
        
        # Avoid caching to avoid impacting other tests in this class
        pip.cacheSessions = False
        
        attributeValues = pip.attributeQuery(ctx, designator)
        self.assert_(len(attributeValues) > 0)
        print("PIP retrieved attribute values %r" % attributeValues)
        
        self.stopAllServices()
        
    def test04InitFromConfigFile(self):
        # Initialise from settings in a config file
        pip = PIP.fromConfig(self.__class__.CONFIG_FILEPATH)
        self.assert_(pip.mappingFilePath)
        self.assert_(pip.sessionCacheTimeout == 1800)
        self.assert_(pip.sessionCacheAssertionClockSkewTol == 3.0)
        
# TODO: fix test - left out for now because can't get threading to correctly 
# close down the Attribute Authority thread.
#    def test05SessionCaching(self):
#        self.startSiteAAttributeAuthority(withSSL=True, 
#                    port=self.__class__.SITEA_SSL_ATTRIBUTEAUTHORITY_PORTNUM)
#        
#        pipA, designator, ctx = self._initQuery()
#        attributeValuesA = pipA.attributeQuery(ctx, designator)
#        
#        pipB = self._createPIP()
#        pipB.cacheSessions = False
#        
#        attributeValuesB = pipB.attributeQuery(ctx, designator)
#        
#        self.stopAllServices()
#        
#        attributeValuesA2 = pipA.attributeQuery(ctx, designator)
#        self.assert_(len(attributeValuesA2) > 0)
#        
#        try:
#            attributeValuesB2 = pipB.attributeQuery(ctx, designator)
#            self.fail("Expected URLError exception for call with no-caching "
#                      "set")
#        except URLError, e:
#            print("Pass: expected %r error for call with no-caching set" % e)
        
        
        
if __name__ == "__main__":
    unittest.main()