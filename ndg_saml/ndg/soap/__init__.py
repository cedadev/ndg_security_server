"""SOAP common package for NDG SAML.  

Initially for use with SAML SOAP Bindings.  This itself
uses ElementTree.  This SOAP interface provides an ElementTree interface to
support it

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: __init__.py 7130 2010-06-30 13:33:07Z pjkersha $'
import logging
log = logging.getLogger(__name__)


class Config(object):
    """Configuration options
    @type use_lxml: bool
    @cvar use_lxml: Controls whether lxml.etree should be imported instead of
    etree. lxml is required for XPath expressions with conditions.
    """
    use_lxml = None

def importElementTree():
    """Imports ElementTree or the lxml ElementTree API depending on the
    Config.use_lxml value and whether the lxml package is found.
    @rtype: module
    @return: the element tree module that has been imported
    """
    if Config.use_lxml is not None:
        if Config.use_lxml:
            from lxml import etree as ElementTree
        else:
            try: # python 2.5
                from xml.etree import ElementTree
            except ImportError:
                # if you've installed it yourself it comes this way
                import ElementTree
    else:
        Config.use_lxml = False
        try:
            from lxml import etree as ElementTree
            Config.use_lxml = True
        except ImportError:
            try: # python 2.5
                from xml.etree import ElementTree
            except ImportError:
                # if you've installed it yourself it comes this way
                import ElementTree
    return ElementTree

class SOAPObject(object):
    """Base class for SOAP envelope, header and body elements"""
    
    ELEMENT_PREFIX = "soap11"
    SOAP11_NS = "http://schemas.xmlsoap.org/soap/envelope/"
    SOAP12_NS = "http://www.w3.org/2003/05/soap-envelope"
    DEFAULT_NS = SOAP11_NS
    
    __slots__ = ()
    
    def create(self):
        raise NotImplementedError()
    
    def parse(self, source):
        raise NotImplementedError()
    
    def serialize(self):
        raise NotImplementedError()
    
    def prettyPrint(self):
        raise NotImplementedError()
      
    
class SOAPEnvelopeBase(SOAPObject):
    """SOAP Envelope"""
    
    DEFAULT_ELEMENT_LOCAL_NAME = "Envelope"
    DEFAULT_ELEMENT_NS = SOAPObject.DEFAULT_NS
    DEFAULT_ELEMENT_NS_PREFIX = SOAPObject.ELEMENT_PREFIX
    
    soapHeader = property()
    soapBody = property()
    
    __slots__ = ()
    
    
class SOAPHeaderBase(SOAPObject):
    """SOAP Header base class"""
    
    DEFAULT_ELEMENT_LOCAL_NAME = "Header"
    DEFAULT_ELEMENT_NS = SOAPObject.DEFAULT_NS
    DEFAULT_ELEMENT_NS_PREFIX = SOAPObject.ELEMENT_PREFIX    
    __slots__ = ()
       
        
class SOAPBodyBase(SOAPObject):
    """SOAP Body base class"""
    
    DEFAULT_ELEMENT_LOCAL_NAME = "Body"
    DEFAULT_ELEMENT_NS = SOAPObject.DEFAULT_NS
    DEFAULT_ELEMENT_NS_PREFIX = SOAPObject.ELEMENT_PREFIX
    fault = property()
    __slots__ = ()
 
        
class SOAPFaultBase(SOAPObject):
    """SOAP Fault"""
    
    DEFAULT_ELEMENT_LOCAL_NAME = "Fault"
    DEFAULT_ELEMENT_NS = SOAPObject.DEFAULT_NS
    DEFAULT_ELEMENT_NS_PREFIX = SOAPObject.ELEMENT_PREFIX
    
    FAULT_CODE_ELEMENT_LOCAL_NAME = "faultcode"
    FAULT_STRING_ELEMENT_LOCAL_NAME = "faultstring"
    FAULT_ACTOR_ELEMENT_LOCAL_NAME = "faultactor"
    DETAIL_ELEMENT_LOCAL_NAME = "detail"
    
    VERSION_MISMATCH_CODE = "VersionMismatch"
    MUST_UNDERSTAND_FAULT_CODE = "MustUnderstand"
    CLIENT_FAULT_CODE = "Client"
    SERVER_FAULT_CODE = "Server"
    
    FAULT_CODES = (
        VERSION_MISMATCH_CODE, 
        MUST_UNDERSTAND_FAULT_CODE, 
        CLIENT_FAULT_CODE, 
        SERVER_FAULT_CODE
    )
    
    __slots__ = ("__faultCode", "__faultString", "__faultActor", "__detail")
    
    def __init__(self, faultString=None, faultCode=None, faultActor=None, 
                 detail=None):
        """Initialise attributes"""
        super(SOAPFaultBase, self).__init__()
        
        if faultCode is None:
            self.__faultCode = None
        else:
            self.faultCode = faultCode
            
        if faultString is None:
            self.__faultString = None
        else:
            self.faultString = faultString
            
        if faultActor is None:
            self.__faultActor = None
        else:
            self.faultActor = faultActor
        
        if detail is None:
            self.__detail = None
        else:
            self.detail = detail

    def _setFaultCode(self, value):
        if not isinstance(value, basestring):
            raise AttributeError('Expecting string type for "faultCode" '
                                 'attribute; got %r' % type(value))
            
        qnameElems = value.split(':')
        if len(qnameElems) == 0:
            raise AttributeError('Expecting Qualified Name for "faultCode" '
                                 'attribute; got %r' % value)
        
        faultCodeFound = [qnameElems[1].startswith(i) 
                          for i in self.__class__.FAULT_CODES]
        if max(faultCodeFound) == False:
            raise AttributeError('Expecting "faultCode" prefixed with one of '
                                 '%r; got %r' % (self.__class__.FAULT_CODES,
                                                 value))
            
        self.__faultCode = value
        
    def _getFaultCode(self):
        return self.__faultCode

    faultCode = property(_getFaultCode, _setFaultCode, 
                         doc="Fault Code")

    def _setFaultString(self, value):
        if not isinstance(value, basestring):
            raise AttributeError('Expecting string type for "faultString" '
                                 'attribute; got %r' % type(value))
        self.__faultString = value
        
    def _getFaultString(self):
        return self.__faultString

    faultString = property(_getFaultString, _setFaultString, 
                           doc="Fault String")

    def _getFaultActor(self):
        return self.__faultActor

    def _setFaultActor(self, value):
        if not isinstance(value, basestring):
            raise AttributeError('Expecting string type for "faultActor" '
                                 'attribute; got %r' % type(value))
        self.__faultActor = value

    faultActor = property(_getFaultActor, _setFaultActor, 
                          doc="Fault Actor")

    def _getDetail(self):
        return self.__detail

    def _setDetail(self, value):
        """No type checking - detail could be an XML element or serialised 
        string content"""
        self.__detail = value

    detail = property(_getDetail, _setDetail, doc="Fault detail")


class SOAPException(Exception):
    """Base SOAP Exception class"""
        
    
class SOAPFaultException(Exception):
    """Raise an exception which also creates a fault object"""
    SOAP_FAULT_CLASS = SOAPFaultBase
    
    def __init__(self, faultString, faultCode, faultActor=None, detail=None):
        super(SOAPFaultException, self).__init__(faultString)
        self.__fault = self.__class__.SOAP_FAULT_CLASS(faultString, faultCode, 
                                                       faultActor=faultActor, 
                                                       detail=detail)
        
    @property    
    def fault(self):
        """Get SOAP fault object"""
        return self.__fault