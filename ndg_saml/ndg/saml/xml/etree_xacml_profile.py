"""ElementTree module for ElementTree representation of objects in XACML 2.0
profile for  SAML 2.0

NERC DataGrid Project
"""
__author__ = "R B Wilkinson"
__date__ = "23/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import logging
log = logging.getLogger(__name__)

from ndg.saml import importElementTree
ElementTree = importElementTree()

from ndg.saml.common import SAMLVersion
from ndg.saml.saml2.core import Issuer
from ndg.saml.saml2.xacml_profile import (XACMLAuthzDecisionQuery,
                                          XACMLAuthzDecisionStatement)
from ndg.saml.utils import SAMLDateTime
from ndg.saml.xml import XMLTypeParseError, UnknownAttrProfile
import ndg.saml.xml.etree as etree
from ndg.saml.xml.etree import (IssuerElementTree, QName,
                                setElementTreeImplementationForQName)

from ndg.xacml.core.context.request import Request
from ndg.xacml.core.context.response import Response
from ndg.xacml.parsers.etree.context import (RequestElementTree,
                                             ResponseElementTree)


class XACMLAuthzDecisionQueryElementTree(XACMLAuthzDecisionQuery):
    """Represent a SAML Attribute Query in XML using ElementTree"""

    @classmethod
    def toXML(cls, xacmlAuthzDecisionQuery):
        """Create an XML representation of the input SAML Authorization
        Decision Query object

        @type xacmlAuthzDecisionQuery: saml.saml2.core.AuthzDecisionQuery
        @param xacmlAuthzDecisionQuery: SAML Authorization Decision Query
        @rtype: ElementTree.Element
        @return: Attribute Query as ElementTree XML element
        """
        if not isinstance(xacmlAuthzDecisionQuery, XACMLAuthzDecisionQuery):
            raise TypeError("Expecting %r class got %r" % (XACMLAuthzDecisionQuery, 
                                                    type(xacmlAuthzDecisionQuery)))

        if not xacmlAuthzDecisionQuery.xacmlContextRequest:
            raise AttributeError("No xacmlContextRequest has been set for the "
                                 "XACMLAuthzDecisionQuery")

        issueInstant = SAMLDateTime.toString(xacmlAuthzDecisionQuery.issueInstant)
        attrib = {
            cls.ID_ATTRIB_NAME: xacmlAuthzDecisionQuery.id,
            cls.ISSUE_INSTANT_ATTRIB_NAME: issueInstant,

            # Nb. Version is a SAMLVersion instance and requires explicit cast
            cls.VERSION_ATTRIB_NAME: str(xacmlAuthzDecisionQuery.version),
        }

        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))
        elem = etree.makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                      cls.DEFAULT_ELEMENT_NAME.namespaceURI,
                                      **attrib)

        issuerElem = IssuerElementTree.toXML(xacmlAuthzDecisionQuery.issuer)
        elem.append(issuerElem)

        requestElem = RequestElementTree.toXML(
                                    xacmlAuthzDecisionQuery.xacmlContextRequest)
        elem.append(requestElem)

        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree element into a SAML XACMLAuthzDecisionQuery object
        
        @type elem: ElementTree.Element
        @param elem: XML element containing the AuthzDecisionQuery
        @rtype: saml.saml2.core.AuthzDecisionQuery
        @return: AuthzDecisionQuery object
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                    cls.DEFAULT_ELEMENT_LOCAL_NAME)
        
        # Unpack attributes from top-level element
        attributeValues = []
        for attributeName in (cls.VERSION_ATTRIB_NAME,
                              cls.ISSUE_INSTANT_ATTRIB_NAME,
                              cls.ID_ATTRIB_NAME):
            attributeValue = elem.attrib.get(attributeName)
            if attributeValue is None:
                raise XMLTypeParseError('No "%s" attribute found in "%s" '
                                 'element' %
                                 (attributeName,
                                  cls.DEFAULT_ELEMENT_LOCAL_NAME))
                
            attributeValues.append(attributeValue)
        
        authzDecisionQuery = XACMLAuthzDecisionQuery()
        authzDecisionQuery.version = SAMLVersion(attributeValues[0])
        if authzDecisionQuery.version != SAMLVersion.VERSION_20:
            raise NotImplementedError("Parsing for %r is implemented for "
                                      "SAML version %s only; version %s is " 
                                      "not supported" % 
                                      (cls,
                                       SAMLVersion(SAMLVersion.VERSION_20),
                                       SAMLVersion(authzDecisionQuery.version)))
            
        authzDecisionQuery.issueInstant = SAMLDateTime.fromString(
                                                            attributeValues[1])
        authzDecisionQuery.id = attributeValues[2]
        
        for childElem in elem:
            localName = QName.getLocalPart(childElem.tag)
            if localName == Issuer.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse Issuer
                authzDecisionQuery.issuer = IssuerElementTree.fromXML(childElem)

            elif localName == Request.ELEMENT_LOCAL_NAME:
                # Create XACML context request from Request element.
                authzDecisionQuery.xacmlContextRequest = \
                    RequestElementTree.fromXML(childElem)

            else:
                raise XMLTypeParseError("Unrecognised XACMLAuthzDecisionQuery child "
                                        "element \"%s\"" % localName)
        
        return authzDecisionQuery

class XACMLAuthzDecisionStatementElementTree(XACMLAuthzDecisionStatement):
    @classmethod
    def toXML(cls, xacmlAuthzDecisionStatement):
        if not isinstance(xacmlAuthzDecisionStatement,
                          XACMLAuthzDecisionStatement):
            raise TypeError("Expecting %r class got %r" %
                            (XACMLAuthzDecisionStatement, 
                            type(xacmlAuthzDecisionStatement)))

        if not xacmlAuthzDecisionStatement.xacmlContextResponse:
            raise AttributeError("No xacmlContextResponse has been set for the "
                                 "XACMLAuthzDecisionStatement")

        tag = str(QName.fromGeneric(cls.DEFAULT_ELEMENT_NAME))
        elem = etree.makeEtreeElement(tag, cls.DEFAULT_ELEMENT_NAME.prefix,
                                      cls.DEFAULT_ELEMENT_NAME.namespaceURI)

        xacmlContextResponseElem = ResponseElementTree.toXML(
                            xacmlAuthzDecisionStatement.xacmlContextResponse)
        elem.append(xacmlContextResponseElem)

        if xacmlAuthzDecisionStatement.xacmlContextRequest:
            xacmlContextRequestElem = RequestElementTree.toXML(
                                xacmlAuthzDecisionStatement.xacmlContextRequest)
            elem.append(xacmlContextRequestElem)

        return elem

    @classmethod
    def fromXML(cls, elem):
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if QName.getLocalPart(elem.tag) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                    cls.DEFAULT_ELEMENT_LOCAL_NAME)

        authzDecisionStatement = XACMLAuthzDecisionStatement()

        for childElem in elem:
            localName = QName.getLocalPart(childElem.tag)
            if localName == Response.ELEMENT_LOCAL_NAME:
                # Create XACML context request from Response element.
                authzDecisionStatement.xacmlContextResponse = \
                    ResponseElementTree.fromXML(childElem)

            elif localName == Request.ELEMENT_LOCAL_NAME:
                # Create XACML context request from Request element.
                authzDecisionStatement.xacmlContextRequest = \
                    RequestElementTree.fromXML(childElem)

            else:
                raise XMLTypeParseError("Unrecognised XACMLAuthzDecisionQuery child "
                                        "element \"%s\"" % localName)

        return authzDecisionStatement

def setElementTreeMap():
    """
    Sets a mapping of XACMLAuthzDecisionStatement element name to the
    corresponding ElementTree class so that statements of this type
    can be processed.
    """
    setElementTreeImplementationForQName(
                XACMLAuthzDecisionStatement.DEFAULT_ELEMENT_NAME,
                XACMLAuthzDecisionStatementElementTree)
