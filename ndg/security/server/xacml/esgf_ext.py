"""NDG Security

Extensions for Earth System Grid Federation Group/Role Attribute Value type
"""
__author__ = "P J Kershaw"
__date__ = "01/11/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

from ndg.xacml.core.functions import functionMap
from ndg.xacml.core.functions.v1.bag import BagBase
from ndg.xacml.core.functions.v1.at_least_one_member_of import \
    AtLeastOneMemberOfBase 
from ndg.xacml.core.attributevalue import (AttributeValue,
                                           AttributeValueClassFactory)
from ndg.xacml.parsers import XMLParseError
from ndg.xacml.parsers.etree.attributevaluereader import (
                                                DataTypeReaderClassFactory)
from ndg.xacml.parsers.etree import QName
from ndg.xacml.parsers.etree.attributevaluereader import (
                                                DataTypeReaderClassFactory,
                                                ETreeDataTypeReaderBase)


class ESGFGroupRoleAttributeValue(AttributeValue):
    """Earth System Grid Federation Group/Role Attribute Value type
    
    Attributes have the concept of a different groups and within those groups
    roles indicating a function or privilege
    
    @cvar IDENTIFIER: DataType for this attribute value type
    @type IDENTIFIER: string
    @cvar TYPE: Realisation as a Python type
    @type TYPE: string
    @cvar GROUPROLE_ELEMENT_LOCAL_NAME: XML element name for this type
    @type GROUPROLE_ELEMENT_LOCAL_NAME: string
    @cvar GROUP_ELEMENT_LOCAL_NAME: name of group XML sub-element
    @type GROUP_ELEMENT_LOCAL_NAME: string
    @cvar ROLE_ELEMENT_LOCAL_NAME: name of role XML sub-element
    @type ROLE_ELEMENT_LOCAL_NAME: string
    @cvar ROLE_DEFAULT_VALUE: default value for role name
    @type ROLE_DEFAULT_VALUE: string
    """
    
    IDENTIFIER = 'groupRole'
    TYPE = tuple    
    GROUPROLE_ELEMENT_LOCAL_NAME = 'groupRole'
    GROUP_ELEMENT_LOCAL_NAME = 'group'
    ROLE_ELEMENT_LOCAL_NAME = 'role'
    ROLE_DEFAULT_VALUE = 'default'
    
    __slots__ = ('__group', '__role')
    
    def __init__(self, value=None):
        """Add additional attributes to AttributeValue base type"""
        super(ESGFGroupRoleAttributeValue, self).__init__()
        self.__group = None
        self.__role = self.__class__.ROLE_DEFAULT_VALUE
        
        if value is not None:
            self.value = value
       
    @property
    def group(self):
        """@return: group name
        @rtype: basestring / NoneType
        """ 
        return self.__group
    
    @group.setter
    def group(self, value):
        """@param value: new group value to set
        @type value: basestring
        """
        if not isinstance(value, str):
            raise TypeError('Expecting string type for "group" attribute; got '
                            '%r' % type(value))
            
        self.__group = value
         
    @property
    def role(self):
        """@return: role name
        @rtype: basestring
        """ 
        return self.__role
    
    @role.setter
    def role(self, value):
        """@param value: new role value to set
        @type value: basestring
        """
        if not isinstance(value, str):
            raise TypeError('Expecting string type for "role" attribute; got '
                            '%r' % type(value))
        
        return self.__role
    
    @property
    def value(self):
        """Override default value property to give custom result.  Also,
        'value' becomes a read-only property.  Making this change is critical
        to the function of the GroupRoleAtLeastOneMemberOf class below - it
        relies on being able to make comparison of the value attribute of 
        different GroupRoleAttributeValue instances.  Defined this way, 
        comparison is by group,role to group,role tuple
        """
        return self.group, self.role

    @value.setter
    def value(self, value):
        if not isinstance(value, (tuple, list)) and len(value) != 2:
            raise TypeError('Expecting a two element tuple or list for group/'
                            'role value; got %r' % type(value))
            
        self.group, self.role = value    

class ESGFGroupRoleBag(BagBase):
    """Bag function for Earth System Grid Federation Group/Role custom attribute
    value type"""
    TYPE = ESGFGroupRoleAttributeValue
    FUNCTION_NS = 'urn:esg:security:xacml:2.0:function:grouprole-bag'

  
class ESGFGroupRoleAtLeastOneMemberOf(AtLeastOneMemberOfBase):
    """At least one member of function for Earth System Grid Federation 
    Group/Role custom attribute value type"""
    TYPE = ESGFGroupRoleAttributeValue
    FUNCTION_NS = ('urn:esg:security:xacml:2.0:function:'
                   'grouprole-at-least-one-member-of')

    
class ETreeESGFGroupRoleDataTypeReader(ETreeDataTypeReaderBase):
    """ElementTree based parser for Earth System Grid Federation Group/Role
    attribute value data type"""
    GROUP_XML_ATTRNAME = 'group'
    ROLE_XML_ATTRNAME = 'role'
    
    @classmethod
    def parse(cls, elem, attributeValue):
        """Parse ESGF Group/Role type object using ElementTree

        @param obj: input object to parse
        @type obj: ElementTree Element, or stream object
        @return: ElementTree element
        @rtype: xml.etree.Element
        """
        if len(elem) != 1:
            raise XMLParseError("Expecting single groupRole child element but " 
                                "found only %d element(s)" % len(elem))
                     
        groupRoleElem = elem[0]
        
        if (QName.getLocalPart(groupRoleElem.tag) != 
            attributeValue.__class__.GROUPROLE_ELEMENT_LOCAL_NAME):
            raise XMLParseError("%r element found, expecting \"%s\" element "  
                        "instead" % 
                        attributeValue.__class__.GROUPROLE_ELEMENT_LOCAL_NAME)
        
        groupXmlAttrValue = groupRoleElem.attrib.get(cls.GROUP_XML_ATTRNAME)
        if groupXmlAttrValue is None:
            raise XMLParseError('No "%s" attribute found in "%s" element' %
                (cls.GROUP_XML_ATTRNAME,
                 attributeValue.__class__.GROUPROLE_ELEMENT_LOCAL_NAME))
                
        attributeValue.group = groupXmlAttrValue.strip()


        roleXmlAttrValue = groupRoleElem.attrib.get(cls.ROLE_XML_ATTRNAME)
        if roleXmlAttrValue is None:
            attributeValue.role = attributeValue.__class__.ROLE_DEFAULT_VALUE
        else:
            attributeValue.role = roleXmlAttrValue.strip()
            

def addEsgfXacmlSupport():
    """Add custom Earth System Grid types to XACML Classes.  This includes
    the Group/Role Attribute type, and associated ElementTree based parser,
    and XACML bag and at least one member functions
    """
    
    # Add Group/Role type
    AttributeValueClassFactory.addClass(ESGFGroupRoleAttributeValue.IDENTIFIER, 
                                        ESGFGroupRoleAttributeValue)
    
    # Add new parser for this type
    DataTypeReaderClassFactory.addReader(ESGFGroupRoleAttributeValue.IDENTIFIER,
                                         ETreeESGFGroupRoleDataTypeReader)
    
    # Add extra matching and bag functions
    functionMap[ESGFGroupRoleBag.FUNCTION_NS] = ESGFGroupRoleBag
    functionMap[ESGFGroupRoleAtLeastOneMemberOf.FUNCTION_NS
                ] = ESGFGroupRoleAtLeastOneMemberOf