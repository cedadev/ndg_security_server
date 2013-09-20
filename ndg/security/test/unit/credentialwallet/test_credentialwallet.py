#!/usr/bin/env python
"""Unit tests for Credential Wallet class

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "03/10/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
import os

from string import Template
from cStringIO import StringIO
import cPickle as pickle

from elementtree import ElementTree

from time import sleep
from datetime import datetime, timedelta

from ndg.saml.utils import SAMLDateTime
from ndg.saml.xml.etree import AssertionElementTree

from ndg.security.test.unit import BaseTestCase
from ndg.security.common.utils.etree import prettyPrint
from ndg.security.common.credentialwallet import SAMLAssertionWallet


class CredentialWalletBaseTestCase(BaseTestCase):
    THIS_DIR = os.path.dirname(__file__)
    CONFIG_FILENAME = 'test_samlcredentialwallet.cfg'
    CONFIG_FILEPATH = os.path.join(THIS_DIR, CONFIG_FILENAME)
    
    
class SAMLAttributeWalletTestCase(CredentialWalletBaseTestCase):
    PICKLE_FILENAME = 'SAMLAttributeWalletPickle.dat'
    PICKLE_FILEPATH = os.path.join(CredentialWalletBaseTestCase.THIS_DIR, 
                                   PICKLE_FILENAME)
    
    ASSERTION_STR = (
"""<saml:Assertion ID="192c67d9-f9cd-457a-9242-999e7b943166" IssueInstant="$timeNow" Version="2.0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
   <saml:Issuer Format="urn:esg:issuer">$issuerName</saml:Issuer>
   <saml:Subject>
      <saml:NameID Format="urn:esg:openid">https://esg.prototype.ucar.edu/myopenid/testUser</saml:NameID>
   </saml:Subject>
   <saml:Conditions NotBefore="$timeNow" NotOnOrAfter="$timeExpires" />
   <saml:AttributeStatement>
      <saml:Attribute FriendlyName="FirstName" Name="urn:esg:first:name" NameFormat="http://www.w3.org/2001/XMLSchema#string">
         <saml:AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="LastName" Name="urn:esg:last:name" NameFormat="http://www.w3.org/2001/XMLSchema#string">
         <saml:AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">User</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute FriendlyName="EmailAddress" Name="urn:esg:first:email:address" NameFormat="http://www.w3.org/2001/XMLSchema#string">
         <saml:AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">test@sitea.ac.uk</saml:AttributeValue>
      </saml:Attribute>
   </saml:AttributeStatement>
</saml:Assertion>
"""
    )
    
    def __init__(self, *arg, **kw):
        super(SAMLAttributeWalletTestCase, self).__init__(*arg, **kw)
        
    def setUp(self):
        self.assertion = self._createAssertion()
        
    def _createAssertion(self, timeNow=None, validityDuration=60*60*8,
                         issuerName=BaseTestCase.SITEA_SAML_ISSUER_NAME):
        if timeNow is None:
            timeNow = datetime.utcnow()
            
        timeExpires = timeNow + timedelta(seconds=validityDuration)
        assertionStr = Template(
            self.__class__.ASSERTION_STR).substitute(
                dict(
                 issuerName=issuerName,
                 timeNow=SAMLDateTime.toString(timeNow), 
                 timeExpires=SAMLDateTime.toString(timeExpires)
                )
            )

        assertionStream = StringIO()
        assertionStream.write(assertionStr)
        assertionStream.seek(0)
        assertionElem = ElementTree.parse(assertionStream).getroot()
        return AssertionElementTree.fromXML(assertionElem)

    def _addCredentials(self):
        wallet = SAMLAssertionWallet()   
        wallet.addCredentials(self.__class__.SITEA_ATTRIBUTEAUTHORITY_URI,
                              [self.assertion])
        return wallet
    
    def test01AddCredentials(self):
        wallet = self._addCredentials()
        k = self.__class__.SITEA_ATTRIBUTEAUTHORITY_URI
        self.assert_(len(wallet.retrieveCredentials(k)) == 1)
        assertions = wallet.retrieveCredentials(
                            self.__class__.SITEA_ATTRIBUTEAUTHORITY_URI)
        self.assert_(assertions)
        
        print("SAML Assertion:\n%s" % 
              prettyPrint(AssertionElementTree.toXML(assertions[0])))
    
    def test02VerifyCredential(self):
        wallet = SAMLAssertionWallet()
        self.assert_(wallet.isValidCredential(self.assertion))
        
        expiredAssertion = self._createAssertion(
                                timeNow=datetime.utcnow() - timedelta(hours=24))
                                
        self.assert_(not wallet.isValidCredential(expiredAssertion))
        
        futureAssertion = self._createAssertion(
                                timeNow=datetime.utcnow() + timedelta(hours=24))

        self.assert_(not wallet.isValidCredential(futureAssertion))
        
    def test03AuditCredentials(self):
        # Add a short lived credential and ensure it's removed when an audit
        # is carried to prune expired credentials
        shortExpiryAssertion = self._createAssertion(validityDuration=1)
        wallet = SAMLAssertionWallet()
        wallet.addCredentials('a', [shortExpiryAssertion])
        
        self.assert_(wallet.retrieveCredentials('a'))
        sleep(2)
        wallet.audit()
        self.assert_(wallet.retrieveCredentials('a') is None)

    def test04ClockSkewTolerance(self):
        # Add a short lived credential but with the wallet set to allow for
        # a clock skew of 
        shortExpiryAssertion = self._createAssertion(validityDuration=1)
        wallet = SAMLAssertionWallet()
        
        # Set a tolerance of five seconds
        wallet.clockSkewTolerance = 5.*60*60
        wallet.addCredentials('a', [shortExpiryAssertion])
        
        self.assert_(wallet.retrieveCredentials('a'))
        sleep(2)
        wallet.audit()
        self.assert_(wallet.retrieveCredentials('a'))
        
    def test05ReplaceCredential(self):
        # Replace an existing credential from a given institution with a more
        # up to date one
        k = self.__class__.SITEA_ATTRIBUTEAUTHORITY_URI
        wallet = self._addCredentials()
        self.assert_(len(wallet.retrieveCredentials(k)) == 1)
        
        newAssertion = self._createAssertion()  

        wallet.addCredentials(k, [newAssertion])
        self.assert_(len(wallet.retrieveCredentials(k)) == 1)
        self.assert_(newAssertion.conditions.notOnOrAfter == \
                     wallet.retrieveCredentials(k)[0].conditions.notOnOrAfter)
        
    def test06CredentialsFromSeparateKeys(self):
        wallet = self._addCredentials()
        wallet.addCredentials("MySite",
                              [self._createAssertion(issuerName="MySite"),
                               self._createAssertion()])
        self.assert_(len(wallet.retrieveCredentials("MySite")) == 2)
        k = self.__class__.SITEA_ATTRIBUTEAUTHORITY_URI
        self.assert_(len(wallet.retrieveCredentials(k)) == 1)

    def test07Pickle(self):
        wallet = self._addCredentials()
        outFile = open(self.__class__.PICKLE_FILEPATH, 'w')
        pickle.dump(wallet, outFile)
        outFile.close()
        
        inFile = open(self.__class__.PICKLE_FILEPATH)
        unpickledWallet = pickle.load(inFile)
        
        assertions = unpickledWallet.retrieveCredentials(
            self.__class__.SITEA_ATTRIBUTEAUTHORITY_URI)
        self.assert_(assertions)
        
        self.assert_(assertions[0].issuer.value == \
                     self.__class__.SITEA_SAML_ISSUER_NAME)

    def test08CreateFromConfig(self):
        wallet = SAMLAssertionWallet.fromConfig(
                                self.__class__.CONFIG_FILEPATH)
        self.assert_(wallet.clockSkewTolerance == timedelta(seconds=0.01))
        self.assert_(wallet.userId == 'https://openid.localhost/philip.kershaw')
        

class SAMLAuthzDecisionWalletTestCase(CredentialWalletBaseTestCase):
    """Test wallet for caching Authorisation Decision statements"""
    PICKLE_FILENAME = 'SAMLAuthzDecisionWalletPickle.dat'
    PICKLE_FILEPATH = os.path.join(CredentialWalletBaseTestCase.THIS_DIR, 
                                   PICKLE_FILENAME)
    
    RESOURCE_ID = 'http://localhost/My%20Secured%20URI'
    ASSERTION_STR = """
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" IssueInstant="$timeNow" ID="c32235a9-85df-4325-99a2-bad73668c01d">
        <saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName">/O=NDG/OU=BADC/CN=attributeauthority.badc.rl.ac.uk</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:esg:openid">https://openid.localhost/philip.kershaw</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotOnOrAfter="$timeExpires" NotBefore="$timeNow"></saml:Conditions>
        <saml:AuthzDecisionStatement Decision="Permit" Resource="$resourceId">
            <saml:Action Namespace="urn:oasis:names:tc:SAML:1.0:action:ghpp">GET</saml:Action>
        </saml:AuthzDecisionStatement>
    </saml:Assertion>
    """
    
    def setUp(self):
        self.assertion = self._createAssertion()
        
    def _createAssertion(self, timeNow=None, validityDuration=60*60*8,
                         issuerName=BaseTestCase.SITEA_SAML_ISSUER_NAME):
        if timeNow is None:
            timeNow = datetime.utcnow()
            
        timeExpires = timeNow + timedelta(seconds=validityDuration)
        assertionStr = Template(
            self.__class__.ASSERTION_STR).substitute(
                dict(
                 issuerName=issuerName,
                 timeNow=SAMLDateTime.toString(timeNow), 
                 timeExpires=SAMLDateTime.toString(timeExpires),
                 resourceId=self.__class__.RESOURCE_ID,
                )
            )

        assertionStream = StringIO()
        assertionStream.write(assertionStr)
        assertionStream.seek(0)
        assertionElem = ElementTree.parse(assertionStream).getroot()
        return AssertionElementTree.fromXML(assertionElem)
                    
    def _addCredentials(self):
        wallet = SAMLAssertionWallet()   
        wallet.addCredentials(self.__class__.RESOURCE_ID, [self.assertion])
        return wallet
    
    def test01AddCredentials(self):
        wallet = self._addCredentials()
        
        self.assert_(
            len(wallet.retrieveCredentials(self.__class__.RESOURCE_ID)) == 1)

        assertion = wallet.retrieveCredentials(self.__class__.RESOURCE_ID)[-1]
        
        print("SAML Assertion:\n%s" % 
              prettyPrint(AssertionElementTree.toXML(assertion)))
    
    def test02VerifyCredential(self):
        wallet = SAMLAssertionWallet()
        self.assert_(wallet.isValidCredential(self.assertion))
        
        expiredAssertion = self._createAssertion(
                                timeNow=datetime.utcnow() - timedelta(hours=24))
                                
        self.assert_(not wallet.isValidCredential(expiredAssertion))
        
        futureAssertion = self._createAssertion(
                                timeNow=datetime.utcnow() + timedelta(hours=24))

        self.assert_(not wallet.isValidCredential(futureAssertion))

    def test06Pickle(self):
        wallet = self._addCredentials()
        outFile = open(self.__class__.PICKLE_FILEPATH, 'w')
        pickle.dump(wallet, outFile)
        outFile.close()
        
        inFile = open(self.__class__.PICKLE_FILEPATH)
        unpickledWallet = pickle.load(inFile)
        self.assert_(unpickledWallet.retrieveCredentials(
                                                    self.__class__.RESOURCE_ID))
        
    def test07CreateFromConfig(self):
        wallet = SAMLAssertionWallet.fromConfig(
                                self.__class__.CONFIG_FILEPATH)
        self.assert_(wallet.clockSkewTolerance == timedelta(seconds=0.01))
        self.assert_(wallet.userId == 'https://openid.localhost/philip.kershaw')


if __name__ == "__main__":
    unittest.main()        
