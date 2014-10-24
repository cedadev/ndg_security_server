#!/usr/bin/env python
"""Unit tests for serialisation of authorisation service requests.

NERC DataGrid Project
"""
__author__ = "R B Wilkinson"
__date__ = "18/01/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

from datetime import datetime
import logging
import os.path
import pickle
import unittest
from uuid import uuid4

from ndg.saml.saml2.core import SAMLVersion, Issuer
from ndg.saml.saml2.xacml_profile import XACMLAuthzDecisionQuery
from ndg.security.server.wsgi.authz.pep_xacml_profile import XacmlSamlPepFilter

logging.basicConfig()
log = logging.getLogger(__name__)

class AuthServiceSerialisationTestCase(unittest.TestCase):
    """Tests serialisation of authorisation service requests.

    NOTE: This currently fails owing to a an pickling the request:
    PicklingError: Can't pickle <class 'abc.AnyURIAttributeValue'>: it's not
    found as abc.AnyURIAttributeValue
    """
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    INI_FILEPATH = None # Set in __init__ to enable derived classes to alter
    AUTHZ_SERVICE_URI = '/AuthorisationService/'
    RESOURCE_URI = 'http://localhost:7080/test'
    SUBJECT_ID = 'https://localhost:7443/openid/philip.kershaw'
    SUBJECT_ID_FORMAT = 'urn:esg:openid'
    ISSUER_DN = '/O=Test/OU=Authorisation/CN=Service Stub'

    def test01(self):
        """Constructs a SAML decision query and checks that it can be pickled
        and unpickled.
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
        # Construct a SAML decision query.
        query = self._makeDecisionQuery(resourceContentsStr,
                                        issuer=self.ISSUER_DN)

        serialisedQuery = pickle.dumps(query)

        query2 = pickle.loads(serialisedQuery)
        self.assertTrue(query2 is not None)
        resourceContent = query2.xacmlContextRequest.resources[0].resourceContent
        self.assertEqual(resourceContent[0][0][0].text, '1.0.0', '')


    def _makeDecisionQuery(self, resourceContentsStr, issuer):
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

        return query

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


if __name__ == "__main__":
    unittest.main()        
