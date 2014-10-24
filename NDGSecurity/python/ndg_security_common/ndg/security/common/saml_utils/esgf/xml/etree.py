"""SAML 2.0 Earth System Grid Group/Role ElementTree representation

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "09/11/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

from ndg.security.common.config import Config, importElementTree
ElementTree = importElementTree()

from ndg.saml.xml import XMLTypeParseError, UnknownAttrProfile
from ndg.saml.xml.etree import (AttributeValueElementTreeBase, 
                                ResponseElementTree,
                                QName)

import ndg.security.common.utils.etree as etree
from ndg.security.common.saml_utils.esgf import ESGFGroupRoleAttributeValue


class ESGFGroupRoleAttributeValueElementTree(AttributeValueElementTreeBase,
                                             ESGFGroupRoleAttributeValue):
    """ElementTree XML representation of Earth System Grid custom Group/Role 
    Attribute Value""" 

    @classmethod
    def toXML(cls, attributeValue):
        """Create an XML representation of the input SAML ESG Group/Role type
        Attribute Value
        
        @type attributeValue: ndg.security.common.saml_utils.esgf.ESGFGroupRoleAttributeValue
        @param attributeValue: Group/Role Attribute Value to be represented as 
        an ElementTree Element
        @rtype: ElementTree.Element
        @return: ElementTree Element
        """
        elem = AttributeValueElementTreeBase.toXML(attributeValue)
        
        if not isinstance(attributeValue, ESGFGroupRoleAttributeValue):
            raise TypeError("Expecting %r type; got: %r" % 
                            (ESGFGroupRoleAttributeValue, type(attributeValue)))
            
        if not Config.use_lxml:
            ElementTree._namespace_map[attributeValue.namespaceURI
                                       ] = attributeValue.namespacePrefix
                                   
        tag = str(QName.fromGeneric(cls.TYPE_NAME))    
        groupRoleElem = etree.makeEtreeElement(tag,
                                        cls.DEFAULT_ELEMENT_NAME.prefix,
                                        cls.DEFAULT_ELEMENT_NAME.namespaceURI)
        
        groupRoleElem.set(cls.GROUP_ATTRIB_NAME, attributeValue.group)
        groupRoleElem.set(cls.ROLE_ATTRIB_NAME, attributeValue.role)

        elem.append(groupRoleElem)
        
        return elem

    @classmethod
    def fromXML(cls, elem):
        """Parse ElementTree ESG Group/Role attribute element into a SAML 
        ESGFGroupRoleAttributeValue object
        
        @type elem: ElementTree.Element
        @param elem: Attribute value as ElementTree XML element
        @rtype: saml.saml2.core.ESGFGroupRoleAttributeValue
        @return: SAML ESG Group/Role Attribute value
        """
        
        # Update namespace map for the Group/Role type referenced.  
        if not Config.use_lxml:
            ElementTree._namespace_map[cls.DEFAULT_NS] = cls.DEFAULT_PREFIX
        
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        localName = QName.getLocalPart(elem.tag)
        if localName != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                    cls.DEFAULT_ELEMENT_LOCAL_NAME)
                                   
        # Check for group/role child element
        if len(elem) == 0:
            raise XMLTypeParseError('Expecting "%s" child element to "%s" '
                                    'element' % (cls.TYPE_LOCAL_NAME,
                                               cls.DEFAULT_ELEMENT_LOCAL_NAME))
        
        childElem = elem[0]
        childLocalName = QName.getLocalPart(childElem.tag)
        if childLocalName != cls.TYPE_LOCAL_NAME:
            raise XMLTypeParseError("No \"%s\" element found" %
                                    cls.TYPE_LOCAL_NAME)

                                      
        attributeValue = ESGFGroupRoleAttributeValue()
        groupName = childElem.attrib.get(cls.GROUP_ATTRIB_NAME)
        if groupName is None:
            raise XMLTypeParseError('No "%s" attribute found in Group/Role '
                                    'attribute element' % 
                                    cls.GROUP_ATTRIB_NAME)
        attributeValue.group = groupName
        
        roleName = childElem.attrib.get(cls.ROLE_ATTRIB_NAME)
        if roleName is None:
            roleName = cls.DEFAULT_ROLE_NAME
            
        attributeValue.role = roleName

        return attributeValue
    
    @classmethod
    def factoryMatchFunc(cls, elem):
        """Match function used by AttributeValueElementTreeFactory to
        determine whether the given attribute is ESGFGroupRoleAttributeValue
        type
        
        @type elem: ElementTree.Element
        @param elem: Attribute value as ElementTree XML element
        @rtype: ndg.security.common.saml_utils.etree.ESGFGroupRoleAttributeValue
        or None
        @return: SAML ESGF Group/Role Attribute Value class if elem is an
        Group/role type element or None if if doesn't match this type 
        """
        
        # Group/role element is a child of the AttributeValue element
        if len(elem) == 0:
            return None
        
        childLocalName = QName.getLocalPart(elem[0].tag)
        if childLocalName != cls.TYPE_LOCAL_NAME:
            raise XMLTypeParseError('No "%s" child element found in '
                                    'AttributeValue' % cls.TYPE_LOCAL_NAME)
               
        if cls.GROUP_ATTRIB_NAME in elem[0].attrib and \
           cls.ROLE_ATTRIB_NAME in elem[0].attrib:
            return cls

        return None


class ESGFResponseElementTree(ResponseElementTree):
    """Extend ResponseElementTree type for Attribute Query Response to include 
    ESG custom Group/Role Attribute support"""
    
    @classmethod
    def toXML(cls, response, **kw):
        """Extend base method adding mapping for ESG Group/Role Attribute Value 
        to enable ElementTree Attribute Value factory to render the XML output
        
        @type response: ndg.security.common.saml_utils.etree.ESGFGroupRoleAttributeValue
        @param response: ESGF Group/Role attribute value 
        @rtype: ElementTree.Element
        @return: ESGF Group/Role attribute value as ElementTree.Element
        """
        toXMLTypeMap = kw.get('customToXMLTypeMap', {})
        toXMLTypeMap[ESGFGroupRoleAttributeValue
                     ] = ESGFGroupRoleAttributeValueElementTree
        
        kw['customToXMLTypeMap'] = toXMLTypeMap
        
        # Convert to ElementTree representation to enable attachment to SOAP
        # response body
        return ResponseElementTree.toXML(response, **kw)
    
    @classmethod
    def fromXML(cls, elem, **kw):
        """Extend base method adding mapping for ESG Group/Role Attribute Value
         
        @type elem: ElementTree.Element
        @param elem: ESGF Group/Role attribute value as ElementTree.Element
        @rtype: ndg.security.common.saml_utils.etree.ESGFGroupRoleAttributeValue
        @return: ESGF Group/Role attribute value 
        """
        toSAMLTypeMap = kw.get('customToSAMLTypeMap', [])
        toSAMLTypeMap.append(
                        ESGFGroupRoleAttributeValueElementTree.factoryMatchFunc)
        kw['customToSAMLTypeMap'] = toSAMLTypeMap
        
        return ResponseElementTree.fromXML(elem, **kw)
