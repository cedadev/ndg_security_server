"""SAML 2.0 common package

Implementation of SAML 2.0 for NDG Security

NERC DataGrid Project

This implementation is adapted from the Java OpenSAML implementation.  The 
copyright and licence information are included here:

Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
__author__ = "P J Kershaw"
__date__ = "11/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from ndg.saml.common.xml import SAMLConstants, QName
 

class SAMLObject(object):
    """Base class for all SAML types
    
    @cvar DEFAULT_ELEMENT_LOCAL_NAME: default XML element name - derived classes
    must specify 
    @type DEFAULT_ELEMENT_LOCAL_NAME: None
    @ivar __qname: qualified name for XML element
    @type __qname: ndg.saml.common.xml.QName
    """
    DEFAULT_ELEMENT_LOCAL_NAME = None
    __slots__ = ('__qname',)
    
    def __init__(self,
                 namespaceURI=SAMLConstants.SAML20_NS, 
                 elementLocalName=None, 
                 namespacePrefix=SAMLConstants.SAML20_PREFIX):
        '''
        @param namespaceURI: the namespace the element is in
        @type namespaceURI: basestring
        @param elementLocalName: the local name of the XML element this Object 
        represents, defaults to DEFAULT_ELEMENT_LOCAL_NAME.  Ensure that this
        is set to a valid string in derived classes rather the None base class
        setting
        @type elementLocalName: NoneType/basestring
        @param namespacePrefix: the prefix for the given namespace
        @type namespacePrefix: basestring
        '''
        if elementLocalName is None:
            elementLocalName = self.__class__.DEFAULT_ELEMENT_LOCAL_NAME
            
        self.__qname = QName(namespaceURI, 
                             elementLocalName, 
                             namespacePrefix)
            
    @property
    def qname(self):
        """Qualified Name for this type
        
        @return: qualified name
        @rtype: ndg.saml.common.xml.QName
        """
        return self.__qname
            
    @classmethod
    def fromXML(cls, xmlObject):
        '''Parse from an XML representation into a SAML object.  Abstract method
        - derived types should implement
        
        @type xmlObject: XML class e.g. ElementTree or 4Suite XML type
        @param xmlObject: XML representation of SAML Object
        @rtype: saml.saml2.common.SAMLObject derived type
        @return: SAML object
        '''
        raise NotImplementedError()
    
    @classmethod
    def toXML(cls, samlObject):
        '''Convert the input SAML object into an XML representation.  Abstract 
        method - derived types should implement
        @type samlObject: saml.saml2.common.SAMLObject derived type
        @param samlObject: SAML object
        @rtype: XML class e.g. ElementTree or 4Suite XML
        @return: XML representation of SAML Object
        '''
        raise NotImplementedError()

    def __getstate__(self):
        '''Enable pickling
        
        @return: object's attribute dictionary
        @rtype: dict
        '''
        _dict = {}
        for attrName in SAMLObject.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_SAMLObject" + attrName
                
            try:
                _dict[attrName] = getattr(self, attrName)
            except:
                pass
            
        return _dict
  
    def __setstate__(self, attrDict):
        '''Enable pickling
        
        @param attrDict: object's attribute dictionary
        @type attrDict: dict
        '''
        for attrName, val in attrDict.items():
            setattr(self, attrName, val)
            

class SAMLVersion(object):
    """Version helper class
    
    @cvar VERSION_10: SAML Version 1.0 identifier
    @type VERSION_10: tuple
    @cvar VERSION_11: SAML Version 1.1 identifier
    @type VERSION_11: tuple
    @cvar VERSION_20: SAML Version 2.0 identifier
    @type VERSION_20: tuple
    @cvar KNOWN_VERSIONS: list of known SAML version identifiers
    @type KNOWN_VERSIONS: tuple
    @ivar __version: SAML version for the given class instance
    @type __version: tuple
    """
    
    VERSION_10 = (1, 0)
    VERSION_11 = (1, 1)
    VERSION_20 = (2, 0)
    KNOWN_VERSIONS = (VERSION_10, VERSION_11, VERSION_20)
    
    __slots__ = ('__version', )
    
    def __init__(self, version):
        """Instantiate from a given input version
        @param version: SAML version to set
        @type version: basestring or tuple or list
        @raise TypeError: unexpected type for version input
        """
        if isinstance(version, basestring):
            self.__version = SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            self.__version = tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version initialiser; got %r" % version)
            
    def __getstate__(self):
        '''Enable pickling
        
        @return: object's attribute dictionary
        @rtype: dict
        '''
        _dict = {}
        for attrName in SAMLVersion.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_SAMLVersion" + attrName
                
            _dict[attrName] = getattr(self, attrName)
            
        return _dict
  
    def __setstate__(self, attrDict):
        '''Enable pickling
        
        @param attrDict: object's attribute dictionary
        @type attrDict: dict
        '''
        for attrName, val in attrDict.items():
            setattr(self, attrName, val)
    
    def __str__(self):
        """
        @return: string representation of SAML version
        @rtype: string
        """
        return ".".join([str(i) for i in self.__version])
    
    def __eq__(self, version):
        """Test for equality against an input version string, tuple or list
        
        @param version: SAML version to test
        @type version: SAMLVersion, basestring, tuple or list
        @return: True if input and this object match
        @rtype: bool
        @raise TypeError: unexpected type for version input
        """
        if isinstance(version, SAMLVersion):
            return str(self) == str(version)
          
        elif isinstance(version, basestring):
            return self.__version == SAMLVersion.valueOf(version)
        
        elif isinstance(version, (tuple, list)):
            return self.__version == tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
            
    def __ne__(self, version):
        """Test True for this instance version not equal to input version
        
        @param version: SAML version to test
        @type version: SAMLVersion, basestring, tuple or list
        @return: True if input and this object don't match
        @rtype: bool
        @raise TypeError: unexpected type for version input
        """
        return not self.__eq__(version)
            
    def __gt__(self, version):                
        """Test True for this instance version greater than input version
        
        @param version: SAML version to test
        @type version: SAMLVersion, basestring, tuple or list
        @return: True if this instance version greater than input version
        @rtype: bool
        @raise TypeError: unexpected type for version input
        """
        if isinstance(version, basestring):
            return self.__version > SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version > tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
            
    def __lt__(self, version):
        """Test True for this instance version less than input version
        
        @param version: SAML version to test
        @type version: SAMLVersion, basestring, tuple or list
        @return: True if this instance version less than input version
        @rtype: bool
        @raise TypeError: unexpected type for version input
        """
        if isinstance(version, basestring):
            return self.__version < SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version < tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
            
    def __ge__(self, version):                
        """Test True for this instance version greater or equal to the input 
        version
        
        @param version: SAML version to test
        @type version: SAMLVersion, basestring, tuple or list
        @return: True if this instance version greater than or equal to input 
        version
        @rtype: bool
        @raise TypeError: unexpected type for version input
        """
        if isinstance(version, basestring):
            return self.__version >= SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version >= tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
            
    def __le__(self, version):                
        """Test True for this instance version less than or equal to input 
        version
        
        @param version: SAML version to test
        @type version: SAMLVersion, basestring, tuple or list
        @return: True if this instance version less than or equal to input 
        version
        @rtype: bool
        @raise TypeError: unexpected type for version input
        """
        if isinstance(version, basestring):
            return self.__version <= SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version <= tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
   
    @staticmethod
    def valueOf(version):
        """Parse input string into version tuple
        @type version: basestring
        @param version: SAML version
        @rtype: tuple
        @return: SAML version tuple"""
        return tuple([int(i) for i in version.split(".")])
