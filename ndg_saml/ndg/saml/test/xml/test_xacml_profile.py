from datetime import datetime
import logging
import unittest
import uuid

from ndg.saml import importElementTree
ET = importElementTree()

from ndg.saml.saml2.core import (SAMLVersion, Issuer)

try:
    from ndg.saml.saml2.xacml_profile import XACMLAuthzDecisionQuery
    from ndg.saml.xml.etree_xacml_profile import \
        XACMLAuthzDecisionQueryElementTree
    _xacml_support = True
    
except ImportError, e:
    from warnings import warn
    warn('Error importing XACML packages - skipping XACML profile unit ' + \
         'tests module.  (Error is: %s)' % e)
    _xacml_support = False
    
    
if _xacml_support:

    from ndg.xacml.core.context.action import Action
    from ndg.xacml.core.context.environment import Environment
    from ndg.xacml.core.context.request import Request
    from ndg.xacml.core.context.resource import Resource
    from ndg.xacml.core.context.subject import Subject
    
    logging.basicConfig(level=logging.DEBUG)
    
    class XacmlProfileTestCase(unittest.TestCase):
        """Test XML handling for XACML profile elements"""
        ISSUER_DN = "/O=NDG/OU=BADC/CN=attributeauthority.badc.rl.ac.uk"
    
        def _getSingleElementText(self, contextElem, path):
            elems = contextElem.findall(path)
            self.assertEquals(len(elems), 1, "Single element not selected")
            return elems[0].text
    
        def test01(self):
            # Construct a ResourceContent element.
            rcContentsStr = '''<wps:GetCapabilities
        xmlns:ows="http://www.opengis.net/ows/1.1"
        xmlns:wps="http://www.opengis.net/wps/1.0.0"
        xmlns:xlink="http://www.w3.org/1999/xlink"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://schemas.opengis.net/wps/1.0.0/wpsGetCapabilities_request.xsd"
        language="en-CA" service="WPS">
        <wps:AcceptVersions>
            <ows:Version>1.0.0</ows:Version>
        </wps:AcceptVersions>
    </wps:GetCapabilities>
    '''
            # Construct XACMLAuthzDecisionQuery including resource content XML.
            rcContentsElem = ET.XML(rcContentsStr)
            resourceContent = ET.Element(
                "{urn:oasis:names:tc:xacml:2.0:context:schema:os}ResourceContent")
            resourceContent.append(rcContentsElem)
            resourceContent.set('TestAttribute', 'Test Value')
    
            resource = Resource()
            resource.resourceContent = resourceContent
    
            request = Request()
            request.subjects.append(Subject())
            request.resources.append(resource)
            request.action = Action()
            request.environment = Environment()
    
            query = XACMLAuthzDecisionQuery()
            query.xacmlContextRequest = request
    
            query.version = SAMLVersion(SAMLVersion.VERSION_20)
            query.id = str(uuid.uuid4())
            query.issueInstant = datetime.utcnow()
            
            query.issuer = Issuer()
            query.issuer.format = Issuer.X509_SUBJECT
            query.issuer.value = self.ISSUER_DN
    
            # Convert to element tree.
            queryElem = XACMLAuthzDecisionQueryElementTree.toXML(query)
            print ET.tostring(queryElem)
    
            # Check some values from query and resource content XML.
            self.assertEqual(queryElem.get("Version"), "2.0")
    
            self.assertEqual(self._getSingleElementText(queryElem,
                            "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"),
                            self.ISSUER_DN)
    
            self.assertEqual(self._getSingleElementText(queryElem,
                "{urn:oasis:names:tc:xacml:2.0:context:schema:os}Request/"
                "{urn:oasis:names:tc:xacml:2.0:context:schema:os}Resource/"
                "{urn:oasis:names:tc:xacml:2.0:context:schema:os}ResourceContent/"
                "{http://www.opengis.net/wps/1.0.0}GetCapabilities/"
                "{http://www.opengis.net/wps/1.0.0}AcceptVersions/"
                "{http://www.opengis.net/ows/1.1}Version"), "1.0.0")
    
    
        def test02(self):
            # Construct a ResourceContent element.
            rcContentsStr = '''<wps:GetCapabilities
        xmlns:ows="http://www.opengis.net/ows/1.1"
        xmlns:wps="http://www.opengis.net/wps/1.0.0"
        xmlns:xlink="http://www.w3.org/1999/xlink"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://schemas.opengis.net/wps/1.0.0/wpsGetCapabilities_request.xsd"
        language="en-CA" service="WPS">
        <wps:AcceptVersions>
            <ows:Version>1.0.0</ows:Version>
        </wps:AcceptVersions>
    </wps:GetCapabilities>
    '''
            # Construct XACMLAuthzDecisionQuery including resource content XML.
            rcContentsElem = ET.XML(rcContentsStr)
            resourceContent = ET.Element(
            "{urn:oasis:names:tc:xacml:2.0:context:schema:os}ResourceContent")
            resourceContent.append(rcContentsElem)
            resourceContent.set('TestAttribute', 'Test Value')
    
            resource = Resource()
            resource.resourceContent = resourceContent
    
            request = Request()
            request.subjects.append(Subject())
            request.resources.append(resource)
            request.action = Action()
            request.environment = Environment()
    
            query = XACMLAuthzDecisionQuery()
            query.xacmlContextRequest = request
    
            query.version = SAMLVersion(SAMLVersion.VERSION_20)
            query.id = str(uuid.uuid4())
            query.issueInstant = datetime.utcnow()
            
            query.issuer = Issuer()
            query.issuer.format = Issuer.X509_SUBJECT
            query.issuer.value = self.ISSUER_DN
    
            # Convert to element tree.
            queryElem = XACMLAuthzDecisionQueryElementTree.toXML(query)
    
            # Convert back to object tree.
            query2 = XACMLAuthzDecisionQueryElementTree.fromXML(queryElem)
    
            # Check some values from the query and the resource content XML.
            self.assertEqual(query2.version, SAMLVersion(SAMLVersion.VERSION_20))
            self.assertEqual(query2.issuer.value, self.ISSUER_DN)
            self.assertEqual(len(query2.xacmlContextRequest.resources), 1)
    
            rcContentsElem2 = query2.xacmlContextRequest.resources[0
                                                            ].resourceContent
            self.assertEqual(self._getSingleElementText(rcContentsElem2,
                "{http://www.opengis.net/wps/1.0.0}GetCapabilities/"
                "{http://www.opengis.net/wps/1.0.0}AcceptVersions/"
                "{http://www.opengis.net/ows/1.1}Version"), "1.0.0")
    
if __name__ == "__main__":
    unittest.main()
