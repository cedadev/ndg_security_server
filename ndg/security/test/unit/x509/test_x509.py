#!/usr/bin/env python
"""NDG X509 Module unit tests

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "03/01/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:test_x509.py 4335 2008-10-14 12:44:22Z pjkersha $'
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

import unittest
import os
import sys
import getpass
from StringIO import StringIO

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath = lambda file: jnPath(os.environ['NDGSEC_X509_UNITTEST_DIR'], file)

from ConfigParser import SafeConfigParser

from ndg.security.test.unit import BaseTestCase
from ndg.security.common.X509 import (X509CertRead, X509CertParse, X500DN, 
    X509Stack, X509StackEmptyError, SelfSignedCert, X509CertIssuerNotFound)


class X509TestCase(BaseTestCase):
    """Unit test X509 module"""
    CA_DIR = os.path.join(BaseTestCase.NDGSEC_TEST_CONFIG_DIR, 'ca')
        
    def setUp(self):
        super(X509TestCase, self).setUp()
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_X509_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_X509_UNITTEST_DIR'] = os.path.abspath(
                                                    os.path.dirname(__file__))
        
        configParser = SafeConfigParser()
        configFilePath = jnPath(os.environ['NDGSEC_X509_UNITTEST_DIR'],
                                "x509Test.cfg")
        configParser.read(configFilePath)
        
        self.cfg = {}
        for section in configParser.sections():
            self.cfg[section] = dict(configParser.items(section))
                    
    def test01X509CertRead(self):
        # test01X509CertRead: read in a cert from file
        self.x509Cert = X509CertRead(
                            xpdVars(self.cfg['test01X509CertRead']['certfile']))
        self.assert_(self.x509Cert)

    def test02X509CertAsPEM(self):
        # test02X509CertAsPEM: display as a PEM format string
        self.test01X509CertRead()
        self.pemString = self.x509Cert.asPEM()
        print(self.pemString)


    def test03X509CertParse(self):
        # test03X509CertParse: parse from a PEM format string
        self.test02X509CertAsPEM()
        self.assert_(X509CertParse(self.pemString))


    def test04GetDN(self):
        # test04GetDN: extract distinguished name
        self.test01X509CertRead()
        self.dn = self.x509Cert.dn
        print(self.dn)
        
    def test05DN(self):
        # test05DN: test X.500 Distinguished Name attributes
        self.test04GetDN()
        for item in self.dn.items():
            print("%s=%s" % item)
        
    def test06DNCmp(self):
        # test06DNCmp: test X.500 Distinguished Name comparison operators
        self.test04GetDN()
        testDN = X500DN(dn="/O=a/OU=b/CN=c")

        self.assert_(not(testDN == self.dn))
        self.assert_(testDN != self.dn)
        self.assert_(self.dn == self.dn)
        self.assert_(not(self.dn != self.dn))
            
    def test07x509Stack(self):
        # test07X509Stack: test X509Stack functionality

        self.test01X509CertRead()
        stack = X509Stack()
        self.assert_(len(stack)==0)
        self.assert_(stack.push(self.x509Cert))
        self.assert_(len(stack)==1)
        print("stack[0] = %s" % stack[0])
        for i in stack:
            print("stack iterator i = %s" % i)
        print("stack.pop() = %s" % stack.pop())
        self.assert_(len(stack)==0)
            
    def test08x509StackVerifyCertChain(self):
        # test08X509StackVerifyCertChain: testVerifyCertChain method

        self.test01X509CertRead()
        proxyCert=X509CertRead(xpdVars(
                   self.cfg['test08X509StackVerifyCertChain']['proxycertfile']))

        stack1 = X509Stack()
        stack1.push(self.x509Cert)
        
        caCert=X509CertRead(xpdVars(\
                   self.cfg['test08X509StackVerifyCertChain']['cacertfile']))
        caStack = X509Stack()
        caStack.push(caCert)
        
        print("Verification of external cert with external CA stack...")
        stack1.verifyCertChain(x509Cert2Verify=proxyCert, 
                               caX509Stack=caStack)
        
        print("Verification of stack content using CA stack...")
        stack1.push(proxyCert)
        stack1.verifyCertChain(caX509Stack=caStack)
        
        print("Verification of stack alone...")
        stack1.push(caCert)
        stack1.verifyCertChain()
        
        print("Reject self-signed cert. ...")
        stack2 = X509Stack()
        try:
            stack2.verifyCertChain()
            self.fail("Empty stack error expected")
        except X509StackEmptyError:
            pass

        stack2.push(caCert)
        try:
            stack2.verifyCertChain()
            self.fail("Reject of self-signed cert. expected")
        except SelfSignedCert:
            pass
        
        print("Accept self-signed cert. ...")
        stack2.verifyCertChain(rejectSelfSignedCert=False)
        
        self.assert_(stack2.pop())
        print("Test no cert. issuer found ...")
        stack2.push(proxyCert)
        try:
            stack2.verifyCertChain()
            self.fail("No cert. issuer error expected")
        except X509CertIssuerNotFound:
            pass
        
        print("Test no cert. issuer found again with incomplete chain ...")
        stack2.push(self.x509Cert)
        try:
            stack2.verifyCertChain()
            self.fail("No cert. issuer error expected")
        except X509CertIssuerNotFound:
            pass

    def test09ExpiryTime(self):
        self.test01X509CertRead()
        
        warningMsg = None
        
        # Capture stderr
        try:
            warningOutput = StringIO()
            _stderr = sys.stderr
            sys.stderr = warningOutput
            
            # Set ridiculous bounds for expiry warning to ensure a warning 
            # message is output
            validStatus = self.x509Cert.isValidTime(
                                                nDaysBeforeExpiryLimit=36500)
            self.assert_(validStatus, "Certificate has expired")
        finally:
            sys.stderr = _stderr
            warningMsg = warningOutput.getvalue()
            
        self.assert_("UserWarning" in str(warningMsg), 
                     "No warning message was set")
        
        print("PASSED - Got warning message from X509Cert.isValidTime: %s" % 
              warningMsg)

        
class X500DNTestCase(BaseTestCase):
    def test01VerifyParsingForFieldsContainingSlash(self):
        # Slash is the delimiter but fields can contain a slash too - ensure
        # correct parsing based on a regular expression which handles this
        # scenario
        dnStr = ("/C=UK/O=eScience/OU=CLRC/L=RAL/CN=host/localhost/"
                 "emailAddress=somebody@somewhere.ac.uk")
        dn = X500DN.fromString(dnStr)
        self.assert_(str(dn))
        print(dn)
        
    def test02VerifyCommaSeparatedDnParsing(self):
        # Test parsing for ',' delimited fields
        dnStr = 'O=NDG, OU=Security, CN=localhost'
        dn = X500DN.fromString(dnStr)
        self.assert_(str(dn))
        print(dn)
        
                                      
if __name__ == "__main__":
    unittest.main()