#!/usr/bin/env python
"""Unit tests for authorisation service using XACML-SAML profile.

NERC DataGrid Project
"""
__author__ = "R B Wilkinson"
__date__ = "06/01/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

# Provided this file is loaded before any other that imports ElementTree, this
# can be used to control whether lxml is used:
#use_lxml = False
#from ndg.xacml import Config as XacmlConfig
#XacmlConfig.use_lxml = use_lxml
#from ndg.saml import Config as SamlConfig
#SamlConfig.use_lxml = use_lxml
#from ndg.soap import Config as SoapConfig
#SoapConfig.use_lxml = use_lxml
#from ndg.security.common.config import Config as SecurityConfig
#SecurityConfig.use_lxml = use_lxml

from datetime import datetime
import logging
import os.path
from StringIO import StringIO
import unittest
from uuid import uuid4

import paste.fixture
from paste.deploy import loadapp

from ndg.saml.saml2.core import SAMLVersion, Issuer
from ndg.saml.saml2.xacml_profile import XACMLAuthzDecisionQuery
from ndg.saml.xml.etree import ResponseElementTree
from ndg.saml.xml.etree_xacml_profile import XACMLAuthzDecisionQueryElementTree
from ndg.security.server.wsgi.authz.pep_xacml_profile import XacmlSamlPepFilter
from ndg.soap.etree import SOAPEnvelope

logging.basicConfig()
log = logging.getLogger(__name__)

class TestApp(object):
    '''Test Application'''
    response = "Test application"

    def __init__(self, app_conf, **local_conf):
        pass

    def __call__(self, environ, start_response):
        status = "200 OK"
        start_response(status,
                       [('Content-length',
                         str(len(TestApp.response))),
                        ('Content-type', 'text/plain')])
        return [TestApp.response]

    @classmethod
    def app_factory(cls, globalConfig, **localConfig):
        return cls(globalConfig, **localConfig)

class AuthServiceWithXacmlProfileTestCase(unittest.TestCase):
    """Tests calls to the authorisation service using the XACML-SAML profile.
    The authorisation service is called directly using paste.fixture.TestApp
    """
    INI_FILE = 'test-pdp.ini'
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    INI_FILEPATH = None # Set in __init__ to enable derived classes to alter
    AUTHZ_SERVICE_URI = '/AuthorisationService/'
    RESOURCE_URI = 'http://localhost:7080/test'
    SUBJECT_ID = 'https://localhost:7443/openid/philip.kershaw'
    SUBJECT_ID_FORMAT = 'urn:esg:openid'
    ISSUER_DN = '/O=Test/OU=Authorisation/CN=Service Stub'

    def test01(self):
        """Test with a policy using an AttributeSelector in a target resource
        match. The result should be permit.
        """
        resourceContentsStr = \
'''<wps:GetCapabilities xmlns:ows="http://www.opengis.net/ows/1.1"
                     xmlns:wps="http://www.opengis.net/wps/1.0.0"
                     xmlns:xlink="http://www.w3.org/1999/xlink"
                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                     xsi:schemaLocation="http://www.opengis.net/wps/1.0.0/wpsGetCapabilities_request.xsd"
                     language="en-CA" service="WPS">
    <wps:AcceptVersions>
        <ows:Version>1.0.0</ows:Version>
    </wps:AcceptVersions>
</wps:GetCapabilities>
'''
        # Policy permits if /wps:GetCapabilities/wps:AcceptVersions/ows:Version
        # == 1.0.0
        self._do_test(resourceContentsStr, None, 'Permit')

    def test02(self):
        """Test with a policy using an AttributeSelector in a target resource
        match. The result should be that access is forbidden.
        """
        resourceContentsStr = \
'''<wps:GetCapabilities xmlns:ows="http://www.opengis.net/ows/1.1"
                     xmlns:wps="http://www.opengis.net/wps/1.0.0"
                     xmlns:xlink="http://www.w3.org/1999/xlink"
                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                     xsi:schemaLocation="http://www.opengis.net/wps/1.0.0/wpsGetCapabilities_request.xsd"
                     language="en-CA" service="WPS">
    <wps:AcceptVersions>
        <ows:Version>2.0.0</ows:Version>
    </wps:AcceptVersions>
</wps:GetCapabilities>
'''
        # Policy permits if /wps:GetCapabilities/wps:AcceptVersions/ows:Version
        # == 1.0.0 - value in resource contents is 2.0.0.
        self._do_test(resourceContentsStr, 403, 'Deny')


    def _do_test(self, resourceContentsStr, expected_status, expected_decision):
        """Constructs, sends and evaluates the response from a SAML SOAP request
        using the XACML-SAML profile, with specified resource contents.
        """
        # Load the AuthorisationServiceMiddleware and
        # SOAPQueryInterfaceMiddleware so that the authorisation service can be
        # called.
        self.__class__.INI_FILEPATH = os.path.join(self.__class__.THIS_DIR, 
                                                   self.__class__.INI_FILE)
        wsgiapp = loadapp('config:'+self.__class__.INI_FILEPATH)
        self.app = paste.fixture.TestApp(wsgiapp)

        # Construct a SOAP request.
        (header, request) = self._makeRequest(resourceContentsStr,
                                              issuer=self.ISSUER_DN)

        # Send the SOAP request to the authorisation service.
        httpResponse = self.app.post(self.AUTHZ_SERVICE_URI, 
                                          params=request,
                                          headers=header,
                                          status=200)
        log.debug("Response status=%d", httpResponse.status)

        # Parse the SOAP response.
        envelope = SOAPEnvelope()
        respFile = StringIO(httpResponse.body)
        envelope.parse(respFile)

        # Extract the SAML response.
        samlAuthzResponse = ResponseElementTree.fromXML(envelope.body.elem[0])

#        serialisedResponse = pickle.dumps(samlAuthzResponse)
#        response2 = pickle.loads(serialisedResponse)

        assertions = samlAuthzResponse.assertions
        (assertion,
         error_status,
         error_message) = XacmlSamlPepFilter._evaluate_assertions(assertions,
                                                        self.SUBJECT_ID,
                                                        self.RESOURCE_URI,
                                                        self.AUTHZ_SERVICE_URI)
        if expected_status is None:
            self.assertTrue(error_status is None,
                            ("Unexpected error %d: %s" %
                             (0 if error_status is None else error_status,
                              error_message)))

            self.assertEqual(
                assertion.statements[0].xacmlContextResponse.results[0].decision.value,
                expected_decision)
        else:
            self.assertEqual(error_status, expected_status)

    def _makeRequest(self, resourceContentsStr, issuer):
        """Constructs the headers and body for a SAML SOAP request using the
        XACML-SAML profile, with specified resource contents.
        """
        xacmlContextRequest = XacmlSamlPepFilter._make_xacml_context_request(
                    httpMethod='POST',
                    resourceURI=self.RESOURCE_URI,
                    resourceContents=resourceContentsStr,
                    subjectID=self.SUBJECT_ID,
                    subjectIdFormat=self.SUBJECT_ID_FORMAT,
                    actions=[])

        query = self._createAuthzDecisionQuery(issuer)
        query.xacmlContextRequest = xacmlContextRequest

        request = self._makeRequestForQuery(query)

        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
        return (header, request)

    def _createAuthzDecisionQuery(self, issuer):
        """Constructs an XACMLAuthzDecisionQuery.
        """
        query = XACMLAuthzDecisionQuery()
        query.version = SAMLVersion(SAMLVersion.VERSION_20)
        query.id = str(uuid4())
        query.issueInstant = datetime.utcnow()

        query.issuer = Issuer()
        query.issuer.format = Issuer.X509_SUBJECT
        query.issuer.value = issuer

        return query

    def _makeRequestForQuery(self, query):
        """Wraps an XACMLAuthzDecisionQuery in a SOAP request.
        """
        elem = XACMLAuthzDecisionQueryElementTree.toXML(query)
        soapRequest = SOAPEnvelope()
        soapRequest.create()
        soapRequest.body.elem.append(elem)

        request = soapRequest.serialize()

        return request

if __name__ == "__main__":
    unittest.main()        
