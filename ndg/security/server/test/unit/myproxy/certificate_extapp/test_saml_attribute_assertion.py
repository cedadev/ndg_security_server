#!/usr/bin/env python
"""Unit tests for NDG Security MyProxy Extensions callout for adding SAML 
Attribute Assertions to issued X.509 Certificates

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "29/10/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)

import os
import sys
from cStringIO import StringIO
import unittest

from ndg.security.common.saml_utils.esgf import ESGFSamlNamespaces
from ndg.security.test.unit.base import BaseTestCase
from ndg.security.server.myproxy.certificate_extapp.saml_attribute_assertion \
    import CertExtApp, CertExtConsoleApp


class CertExtAppTestCase(BaseTestCase):
    """Test SAML Assertion Certificate Extension plugin for MyProxy"""
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    OPENID_SQL_QUERY = ("select openid from users where username = "
                        "'${username}'") 
    INI_FILEPATH = os.path.join(THIS_DIR, 'config.ini')
    
    def __init__(self, *arg, **kw):
        super(CertExtAppTestCase, self).__init__(*arg, **kw)            
        self.startSiteAAttributeAuthority(withSSL=True, 
                port=CertExtAppTestCase.SITEA_SSL_ATTRIBUTEAUTHORITY_PORTNUM)
        self.initDb()
        
    def test01DbQuery(self):
        myProxyCertExtApp = CertExtApp()
        myProxyCertExtApp.connectionString = \
                                            CertExtAppTestCase.DB_CONNECTION_STR
                    
        myProxyCertExtApp.openIdSqlQuery = CertExtAppTestCase.OPENID_SQL_QUERY
        
        openid = myProxyCertExtApp.queryOpenId(CertExtAppTestCase.USERNAME)
        self.assert_(openid == CertExtAppTestCase.OPENID_URI)
        
    def test02AttributeQuery(self):
        myProxyCertExtApp = CertExtApp()
        myProxyCertExtApp.attributeQuery.issuerName = \
                                        "/CN=Authorisation Service/O=Site A"
        myProxyCertExtApp.attributeQuery.subjectIdFormat = \
                                        ESGFSamlNamespaces.NAMEID_FORMAT                                
        myProxyCertExtApp.attributeQuery.subjectID = \
                                        CertExtAppTestCase.OPENID_URI
                                        
        myProxyCertExtApp.attributeQuery.sslCACertDir = \
                                                CertExtAppTestCase.CACERT_DIR
        myProxyCertExtApp.attributeQuery.sslCertFilePath = \
                        os.path.join(CertExtAppTestCase.PKI_DIR, 'test.crt')
        myProxyCertExtApp.attributeQuery.sslPriKeyFilePath = \
                        os.path.join(CertExtAppTestCase.PKI_DIR, 'test.key')
        myProxyCertExtApp.attributeQuery.sslValidDNs = \
                                                CertExtAppTestCase.SSL_CERT_DN
                                
        response = myProxyCertExtApp.attributeQuery.send(
                uri=CertExtAppTestCase.SITEA_SSL_ATTRIBUTEAUTHORITY_URI)
        print(response)
        
    def test03End2End(self):
        myProxyCertExtApp = CertExtApp()
        
        myProxyCertExtApp.connectionString = \
                                        CertExtAppTestCase.DB_CONNECTION_STR
                    
        myProxyCertExtApp.openIdSqlQuery = ("select openid from users where "
                                            "username = '%s'" %
                                            CertExtAppTestCase.USERNAME)

        myProxyCertExtApp.attributeAuthorityURI = \
                    CertExtAppTestCase.SITEA_SSL_ATTRIBUTEAUTHORITY_URI
        myProxyCertExtApp.attributeQuery.issuerName = \
                            "/CN=Authorisation Service/O=Site A"

        myProxyCertExtApp.attributeQuery.subjectIdFormat = \
                                        ESGFSamlNamespaces.NAMEID_FORMAT                                        
        myProxyCertExtApp.attributeQuery.sslCACertDir = \
                                                CertExtAppTestCase.CACERT_DIR
        myProxyCertExtApp.attributeQuery.sslCertFilePath = \
                        os.path.join(CertExtAppTestCase.PKI_DIR, 'test.crt')
        myProxyCertExtApp.attributeQuery.sslPriKeyFilePath = \
                        os.path.join(CertExtAppTestCase.PKI_DIR, 'test.key')
        myProxyCertExtApp.attributeQuery.sslValidDNs = \
                                                CertExtAppTestCase.SSL_CERT_DN
        
        assertion = myProxyCertExtApp(CertExtAppTestCase.USERNAME)
        self.assert_(assertion)
        print(assertion)

    def test04FromConfigFile(self):
        myProxyCertExtApp = CertExtApp.fromConfigFile(
                                            CertExtAppTestCase.INI_FILEPATH)
        assertion = myProxyCertExtApp(CertExtAppTestCase.USERNAME)
        self.assert_(assertion)
        print(assertion)

    def test05ConsoleApp(self):
        import sys
        sys.argv = [
            None, 
            "-f", CertExtAppTestCase.INI_FILEPATH, 
            "-u", CertExtAppTestCase.USERNAME
        ]
        try:
            stdOut = sys.stdout
            sys.stdout = StringIO()
            
            CertExtConsoleApp.run()
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = stdOut
        
        self.assert_(output)        
        print(output)
        
        
if __name__ == "__main__":
    unittest.main()