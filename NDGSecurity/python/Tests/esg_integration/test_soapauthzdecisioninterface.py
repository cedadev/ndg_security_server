#!/usr/bin/env python
"""Unit tests for WSGI SAML 2.0 SOAP Authorisation Decision Query Interface

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/02/2010"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
from os import path

from ndg.security.common.config import importElementTree
ElementTree = importElementTree()

from ndg.saml.saml2.core import StatusCode, DecisionType, Action
from ndg.saml.xml.etree import ResponseElementTree
from ndg.security.common.utils.etree import prettyPrint
from ndg.saml.saml2.binding.soap.client.authzdecisionquery import ( 
                                        AuthzDecisionQuerySslSOAPBinding)

class EsgAuthzServiceTestCase(unittest.TestCase):
    THIS_DIR = path.dirname(__file__)
    CA_DIR = path.join(THIS_DIR, 'ca')

    def _readParamFile(filePath):
        try:
            return open(filePath).read().strip()
        except IOError:
            return None
    
    RESOURCE_URI = _readParamFile(path.join(THIS_DIR, 'resource.txt'))
    SUBJECT = _readParamFile(path.join(THIS_DIR, 'subject.txt'))
    ISSUER_NAME = '/O=STFC/OU=BADC/CN=TestAuthorizationClient'
    ACTION = 'Read'
    ACTION_NS_URI = Action.RWEDC_NEGATION_NS_URI
    AUTHZ_SERVICE_URI = _readParamFile(path.join(THIS_DIR, 'endpoint.txt'))
        
    def test01ValidQuery(self):        
        binding = AuthzDecisionQuerySslSOAPBinding()
        binding.actions.append(Action())
        binding.actions[0].namespace = EsgAuthzServiceTestCase.ACTION_NS_URI
        binding.actions[0].value = EsgAuthzServiceTestCase.ACTION    
        binding.resourceURI = EsgAuthzServiceTestCase.RESOURCE_URI
        binding.subjectID = EsgAuthzServiceTestCase.SUBJECT
        binding.issuerName = EsgAuthzServiceTestCase.ISSUER_NAME
        
        # SSL Context Proxy settings
        binding.sslCACertDir = EsgAuthzServiceTestCase.CA_DIR

        # Add tolerance of 1 second for clock skew either side of issue instant
        # and not before / notOnOrAfter times
        binding.clockSkewTolerance = 1
        
        response = binding.send(uri=EsgAuthzServiceTestCase.AUTHZ_SERVICE_URI)
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print(ElementTree.tostring(samlResponseElem))
        print("Pretty print SAML Response ...")
        print(prettyPrint(samlResponseElem))


        self.assert_(response.status.statusCode.value == \
                     StatusCode.SUCCESS_URI)
        self.assert_(response.inResponseTo == binding.query.id)
        self.assert_(response.assertions[0])
        self.assert_(response.assertions[0].subject.nameID.value == \
                     binding.query.subject.nameID.value)
        self.assert_(response.assertions[0].authzDecisionStatements[0])
        self.assert_(response.assertions[0].authzDecisionStatements[0
                                            ].decision == DecisionType.PERMIT)
        

 
if __name__ == "__main__":
    unittest.main()