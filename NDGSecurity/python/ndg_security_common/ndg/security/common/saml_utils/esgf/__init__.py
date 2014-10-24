"""SAML 2.0 Earth System Grid specific functionality

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "09/11/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from ndg.saml.saml2.core import (XSStringAttributeValue, AttributeValue, 
                                 Attribute)
from ndg.saml.common.xml import QName, SAMLConstants

from ndg.security.common.utils import TypedList


class  _MetaESGFSamlNamespaces(type):
    """Meta class enables read-only constants"""
    @property
    def FIRSTNAME_ATTRNAME(self):
        return "urn:esg:first:name"
    
    @property
    def FIRSTNAME_FRIENDLYNAME(self):
        return "FirstName"
   
    @property
    def LASTNAME_ATTRNAME(self):
        return "urn:esg:last:name"
    
    @property
    def LASTNAME_FRIENDLYNAME(self):
        return "LastName"
    
    @property
    def EMAILADDRESS_ATTRNAME(self):
        return "urn:esg:email:address"
    
    @property
    def EMAILADDRESS_FRIENDLYNAME(self):
        return "EmailAddress"
   
    @property
    def NAMEID_FORMAT(self):
        return "urn:esg:openid"

 
class ESGFSamlNamespaces(object):
    """Earth System Grid specific constants for use with SAML assertions"""
    __metaclass__ = _MetaESGFSamlNamespaces
    
    
class ESGFGroupRoleAttributeValue(AttributeValue): 
    '''ESG Specific Group/Role attribute value.  ESG attribute permissions are
    organised into group/role pairs
    '''
    DEFAULT_NS = "http://www.earthsystemgrid.org"
    DEFAULT_PREFIX = "esg"
    TYPE_LOCAL_NAME = "groupRole"
    
    GROUP_ATTRIB_NAME = "group"
    ROLE_ATTRIB_NAME = "role"
    DEFAULT_ROLE_NAME = "default"
    
    # QName of the XSI type
    TYPE_NAME = QName(DEFAULT_NS, 
                      TYPE_LOCAL_NAME, 
                      DEFAULT_PREFIX)
     
    def __init__(self, 
                 namespaceURI=DEFAULT_NS, 
                 elementLocalName=TYPE_LOCAL_NAME, 
                 namespacePrefix=DEFAULT_PREFIX):
        '''@param namespaceURI: the namespace the element is in
        @param elementLocalName: the local name of the XML element this Object 
        represents
        @param namespacePrefix: the prefix for the given namespace'''
        self.__namespaceURI = namespaceURI
        self.__elementLocalName = elementLocalName
        self.__namespacePrefix = namespacePrefix
        self.__group = None
        self.__role = None        

    def _getNamespaceURI(self):
        return self.__namespaceURI

    def _setNamespaceURI(self, value):
        if not isinstance(value, basestring):
            raise TypeError("Expecting %r type for namespaceURI got %r" %
                            (basestring, value.__class__))
        self.__namespaceURI = value

    def _getElementLocalName(self):
        return self.__elementLocalName

    def _setElementLocalName(self, value):
        if not isinstance(value, basestring):
            raise TypeError("Expecting %r type for elementLocalName got %r" %
                            (basestring, value.__class__))
        self.__elementLocalName = value

    def _getNamespacePrefix(self):
        return self.__namespacePrefix

    def _setNamespacePrefix(self, value):
        if not isinstance(value, basestring):
            raise TypeError("Expecting %r type for namespacePrefix got %r" %
                            (basestring, value.__class__))
        self.__namespacePrefix = value

    namespaceURI = property(fget=_getNamespaceURI, 
                            fset=_setNamespaceURI, 
                            doc="the namespace the element is in")

    elementLocalName = property(fget=_getElementLocalName, 
                                fset=_setElementLocalName, 
                                doc="the local name of the XML element this "
                                    "Object represents")

    namespacePrefix = property(fget=_getNamespacePrefix, 
                               fset=_setNamespacePrefix, 
                               doc="the prefix for the given namespace")

    def _getGroup(self):
        return self.__group
     
    def _setGroup(self, group): 
        if not isinstance(group, basestring):
            raise TypeError('Expecting a string type for "group" attribute; '
                            'got %r' % type(group))
        self.__group = group
     
    group = property(fget=_getGroup, fset=_setGroup, doc="Group value")
     
    def _getRole(self):
        return self.__role
     
    def _setRole(self, role):
        if not isinstance(role, basestring):
            raise TypeError('Expecting a string type for "role" attribute; '
                            'got %r' % type(role))           
        self.__role = role
     
    role = property(fget=_getRole, fset=_setRole, doc="Role value")

    def _setValue(self, value):
        if not isinstance(value, (tuple, list)) and len(value) != 2:
            raise TypeError('Expecting a two element tuple or list for group/'
                            'role value; got %r' % type(value))
            
        self.group, self.role = value
        
    def _getValue(self):
        return self.group, self.role
    
    value = property(_getValue, _setValue, 
                     doc="group/role attribute value tuple")
    
    def getOrderedChildren(self):
        # no children
        return None


class ESGFDefaultQueryAttributes(object):    
    XSSTRING_NS = "%s#%s" % (
        SAMLConstants.XSD_NS,
        XSStringAttributeValue.TYPE_LOCAL_NAME
    )
    
    ATTRIBUTES = TypedList(Attribute)
    N_ATTRIBUTES = 3
    i = 0
    for i in range(N_ATTRIBUTES): 
        ATTRIBUTES.append(Attribute())
    del i
    
    ATTRIBUTES[0].name = ESGFSamlNamespaces.FIRSTNAME_ATTRNAME 
    ATTRIBUTES[0].friendlyName = ESGFSamlNamespaces.FIRSTNAME_FRIENDLYNAME
    ATTRIBUTES[0].nameFormat = XSSTRING_NS

    ATTRIBUTES[1].name = ESGFSamlNamespaces.LASTNAME_ATTRNAME 
    ATTRIBUTES[1].friendlyName = ESGFSamlNamespaces.LASTNAME_FRIENDLYNAME
    ATTRIBUTES[1].nameFormat = XSSTRING_NS
    
    ATTRIBUTES[2].name = ESGFSamlNamespaces.EMAILADDRESS_ATTRNAME
    ATTRIBUTES[2].friendlyName = ESGFSamlNamespaces.EMAILADDRESS_FRIENDLYNAME
    ATTRIBUTES[2].nameFormat =  XSSTRING_NS