"""SAML SOAP Binding Query/Response Interface with service hosted in
Paste paster web server

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "01/07/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
from os import path
from ndg.saml import importElementTree
ElementTree = importElementTree()

from ndg.soap.utils.etree import prettyPrint

from ndg.saml.saml2.core import Attribute, StatusCode
from ndg.saml.xml.etree import ResponseElementTree
from ndg.saml.saml2.binding.soap.client.attributequery import \
    AttributeQuerySslSOAPBinding
from ndg.saml.test.binding.soap import WithPasterBaseTestCase    
    
    
class SamlSslSoapBindingTestCase(WithPasterBaseTestCase):
    """Test SAML SOAP Binding with SSL"""
    SERVICE_URI = 'https://localhost:5443/attributeauthority'
    SUBJECT = "https://openid.localhost/philip.kershaw"
    SUBJECT_FORMAT = "urn:ndg:saml:openid"
    CONFIG_FILENAME = 'attribute-interface.ini'
    
    CLIENT_CERT_FILEPATH = path.join(WithPasterBaseTestCase.THIS_DIR, 
                                     'test.crt')
    CLIENT_PRIKEY_FILEPATH = path.join(WithPasterBaseTestCase.THIS_DIR, 
                                       'test.key')
    CLIENT_CACERT_DIR = path.join(WithPasterBaseTestCase.THIS_DIR, 'ca')
    VALID_DNS = [
        '/O=NDG/OU=Security/CN=localhost', 
    ]
    
    def __init__(self, *arg, **kw):
        kw['withSSL'] = True
        super(SamlSslSoapBindingTestCase, self).__init__(*arg, **kw)
                
    def test01M2CryptoInstalled(self):
        # Force error for M2Crypto not present
        _support = AttributeQuerySslSOAPBinding.SSL_CONTEXT_PROXY_SUPPORT
        AttributeQuerySslSOAPBinding.SSL_CONTEXT_PROXY_SUPPORT = False
        try:
            self.assertRaises(ImportError, AttributeQuerySslSOAPBinding)
        finally:
            AttributeQuerySslSOAPBinding.SSL_CONTEXT_PROXY_SUPPORT = _support
        
        # Try again to really test all is well
        try:
            AttributeQuerySslSOAPBinding()
        except ImportError, e:
            self.fail('Import error with AttributeQuerySslSoapBinding: %s' % e)
     
    def test02SendQuery(self):
        attributeQuery = AttributeQuerySslSOAPBinding()
        
        attributeQuery.subjectIdFormat = self.__class__.SUBJECT_FORMAT
        attributeQuery.clockSkewTolerance = 2.
        attributeQuery.issuerName = '/O=Site A/CN=Authorisation Service'

        query = attributeQuery.makeQuery()
        attributeQuery.setQuerySubjectId(query, self.__class__.SUBJECT)

        attribute = Attribute()
        attribute.name = 'urn:ndg:saml:emailaddress'
        attribute.friendlyName = 'emailAddress'
        attribute.nameFormat = 'http://www.w3.org/2001/XMLSchema'
        
        query.attributes.append(attribute)
        
        attributeQuery.sslCACertDir = self.__class__.CLIENT_CACERT_DIR
        attributeQuery.sslCertFilePath = self.__class__.CLIENT_CERT_FILEPATH
        attributeQuery.sslPriKeyFilePath = self.__class__.CLIENT_PRIKEY_FILEPATH
        attributeQuery.sslValidDNs = self.__class__.VALID_DNS
        
        response = attributeQuery.send(query, uri=self.__class__.SERVICE_URI)
        
        # Convert back to ElementTree instance read for string output
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))
        
        self.assert_(response.status.statusCode.value==StatusCode.SUCCESS_URI)
  
 
if __name__ == "__main__":
    unittest.main()        
