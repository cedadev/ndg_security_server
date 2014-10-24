"""SOAP client package - XML representation using ElementTree

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "27/07/09"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: etree.py 7131 2010-06-30 13:37:48Z pjkersha $'
import logging
log = logging.getLogger(__name__)

from ndg.saml import Config, importElementTreeAndCElementTree
(ElementTree, cElementTree) = importElementTreeAndCElementTree()

# ElementTree helper functions
import ndg.soap.utils.etree as etree
from ndg.soap.utils.etree import QName

from ndg.soap import (SOAPObject, SOAPEnvelopeBase, SOAPHeaderBase, 
                      SOAPBodyBase, SOAPFaultBase)
from ndg.soap import SOAPFaultException as SOAPFaultExceptionBase


class ETreeSOAPExtensions(object):  
    """Utility to enable addition of core ElementTree specific attributes and
    methods for ElementTree SOAP implementation
    """
    def __init__(self):
        self.__qname = None
        self.__elem = None

    def _getQname(self):
        return self.__qname

    def _setQname(self, value):
        if not isinstance(value, QName):
            raise TypeError('Expecting %r for "qname" attribute; got %r' %
                            (QName, type(value)))
        self.__qname = value

    def _getElem(self):
        return self.__elem

    def _setElem(self, value):
        if not ElementTree.iselement(value):
            raise TypeError('Expecting %r for "elem" attribute; got %r' %
                            (ElementTree.Element, type(value)))
        self.__elem = value
        
    qname = property(_getQname, _setQname, None, "Qualified name object")
    elem = property(_getElem, _setElem, None, "Root element")

    @staticmethod
    def _serialize(elem):
        """Serialise element tree into string"""
        if Config.use_lxml:
            return ElementTree.tostring(elem)
        else:
            return cElementTree.tostring(elem)
       
    @classmethod
    def _prettyPrint(cls, elem):
        """Basic pretty printing separating each element on to a new line"""
        xml = cls._serialize(elem)
        xml = ">\n".join(xml.split(">"))
        xml = "\n<".join(xml.split("<"))
        xml = '\n'.join(xml.split('\n\n'))
        return xml

    @staticmethod
    def _parse(source):
        """Read in the XML from source
        @type source: basestring/file
        @param source: file path to XML file or file object
        """
        tree = ElementTree.parse(source)
        elem = tree.getroot()
        
        return elem        


class SOAPHeader(SOAPHeaderBase, ETreeSOAPExtensions):
    """ElementTree implementation of SOAP Header object"""
    
    DEFAULT_ELEMENT_NAME = QName(SOAPHeaderBase.DEFAULT_ELEMENT_NS,
                               tag=SOAPHeaderBase.DEFAULT_ELEMENT_LOCAL_NAME,
                               prefix=SOAPHeaderBase.DEFAULT_ELEMENT_NS_PREFIX)
    
    def __init__(self):
        SOAPHeaderBase.__init__(self)
        ETreeSOAPExtensions.__init__(self)
        
        self.qname = QName(SOAPHeaderBase.DEFAULT_ELEMENT_NS, 
                           tag=SOAPHeaderBase.DEFAULT_ELEMENT_LOCAL_NAME, 
                           prefix=SOAPHeaderBase.DEFAULT_ELEMENT_NS_PREFIX)

    def create(self):
        """Create header ElementTree element"""
        
        self.elem = etree.makeEtreeElement(str(self.qname),
                                    SOAPHeaderBase.DEFAULT_ELEMENT_NS_PREFIX,
                                    SOAPHeaderBase.DEFAULT_ELEMENT_NS)
    
    def serialize(self):
        """Serialise element tree into string"""
        return ETreeSOAPExtensions._serialize(self.elem)
    
    def prettyPrint(self):
        """Basic pretty printing separating each element on to a new line"""
        return ETreeSOAPExtensions._prettyPrint(self.elem)


class SOAPBody(SOAPBodyBase, ETreeSOAPExtensions):
    """ElementTree based implementation for SOAP Body object"""
    
    DEFAULT_ELEMENT_NAME = QName(SOAPBodyBase.DEFAULT_ELEMENT_NS,
                                 tag=SOAPBodyBase.DEFAULT_ELEMENT_LOCAL_NAME,
                                 prefix=SOAPBodyBase.DEFAULT_ELEMENT_NS_PREFIX)
    
    def __init__(self):
        SOAPBodyBase.__init__(self)
        ETreeSOAPExtensions.__init__(self)
        
        self.qname = QName(SOAPBodyBase.DEFAULT_ELEMENT_NS, 
                           tag=SOAPBodyBase.DEFAULT_ELEMENT_LOCAL_NAME, 
                           prefix=SOAPBodyBase.DEFAULT_ELEMENT_NS_PREFIX)
        self.__fault = None
        
    # Test for SOAPFault present
    @property
    def hasSOAPFault(self):
        """Boolean True if this SOAP BOdy contains a SOAPFault instance"""
        return self.fault is not None
    
    def _getFault(self):
        return self.__fault
    
    def _setFault(self, value):
        if not isinstance(value, SOAPFault):
            raise TypeError('Expecting %r type for "fault" attribute; got %r' %
                            (SOAPFault, type(value)))
        self.__fault = value
       
    fault = property(_getFault, _setFault, doc="SOAP Fault")
        
    def create(self):
        """Create header ElementTree element"""
        self.elem = etree.makeEtreeElement(str(self.qname),
                                        SOAPBodyBase.DEFAULT_ELEMENT_NS_PREFIX,
                                        SOAPBodyBase.DEFAULT_ELEMENT_NS)
        if self.hasSOAPFault:
            self.fault.create()
            self.elem.append(self.fault.elem)
    
    def serialize(self):
        """Serialise element tree into string"""
        return ETreeSOAPExtensions._serialize(self.elem)
 
    def parse(self, source):
        """This method ONLY parses a SOAPFault IF one is found"""
        if ElementTree.iselement(source):
            self.elem = source
        else:
            self.elem = self._parse(source)
                  
        for elem in self.elem:
            localName = QName.getLocalPart(elem.tag)
            if localName == SOAPFault.DEFAULT_ELEMENT_LOCAL_NAME:
                if self.fault is None:
                    self.fault = SOAPFault()
                    
                self.fault.parse(elem)
                
                # Only one SOAPFault element is expected
                break
            
    def prettyPrint(self):
        """Basic pretty printing separating each element on to a new line"""
        return ETreeSOAPExtensions._prettyPrint(self.elem)
    

class SOAPFault(SOAPFaultBase, ETreeSOAPExtensions):
    """Extend SOAP Fault for ElementTree parsing and serialisation"""
    
    DEFAULT_ELEMENT_NAME = QName(SOAPFaultBase.DEFAULT_ELEMENT_NS,
                                 tag=SOAPFaultBase.DEFAULT_ELEMENT_LOCAL_NAME,
                                 prefix=SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX)
    
    FAULT_CODE_ELEMENT_NAME = QName(SOAPFaultBase.DEFAULT_ELEMENT_NS,
                             tag=SOAPFaultBase.FAULT_CODE_ELEMENT_LOCAL_NAME,
                             prefix=SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX)
    
    FAULT_STRING_ELEMENT_NAME = QName(SOAPFaultBase.DEFAULT_ELEMENT_NS,
                             tag=SOAPFaultBase.FAULT_STRING_ELEMENT_LOCAL_NAME,
                             prefix=SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX)
    
    FAULT_ACTOR_ELEMENT_NAME = QName(SOAPFaultBase.DEFAULT_ELEMENT_NS,
                             tag=SOAPFaultBase.FAULT_ACTOR_ELEMENT_LOCAL_NAME,
                             prefix=SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX)
    
    DETAIL_ELEMENT_NAME = QName(SOAPFaultBase.DEFAULT_ELEMENT_NS,
                                tag=SOAPFaultBase.DETAIL_ELEMENT_LOCAL_NAME,
                                prefix=SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX)
    
    def __init__(self, *arg, **kw):
        SOAPFaultBase.__init__(self, *arg, **kw)
        ETreeSOAPExtensions.__init__(self)
        
        self.qname = QName(SOAPFaultBase.DEFAULT_ELEMENT_NS, 
                           tag=SOAPFaultBase.DEFAULT_ELEMENT_LOCAL_NAME, 
                           prefix=SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX)
    
    def _setFaultCode(self, value):
        """Override to enable ns prefix to be inferred if not added in already
        """
        if value.startswith(self.__class__.FAULT_CODE_ELEMENT_NAME.prefix):
            _value = value
        else:
            _value = "%s:%s" % (SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX, value)
        
        SOAPFaultBase._setFaultCode(self, _value)
        
    faultCode = property(SOAPFaultBase._getFaultCode, _setFaultCode,
                         doc="Fault code")
    
    def create(self):
        """Create Fault ElementTree element"""
        self.elem = etree.makeEtreeElement(str(self.qname),
                                        SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX,
                                        SOAPFaultBase.DEFAULT_ELEMENT_NS)
        
        faultStringElem = etree.makeEtreeElement(
                                str(self.__class__.FAULT_STRING_ELEMENT_NAME),
                                SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX,
                                SOAPFaultBase.DEFAULT_ELEMENT_NS)
        faultStringElem.text = self.faultString
        self.elem.append(faultStringElem)
        
        faultCodeElem = etree.makeEtreeElement(
                                str(self.__class__.FAULT_CODE_ELEMENT_NAME),
                                SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX,
                                SOAPFaultBase.DEFAULT_ELEMENT_NS)
        faultCodeElem.text = self.faultCode
        self.elem.append(faultCodeElem)
                         
        if self.faultActor is not None:
            faultActorElem = etree.makeEtreeElement(
                                str(self.__class__.FAULT_ACTOR_ELEMENT_NAME),
                                SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX,
                                SOAPFaultBase.DEFAULT_ELEMENT_NS)
            faultActorElem.text = self.faultActor
            self.elem.append(faultActorElem)
                             
        if self.detail is not None:
            detailElem = etree.makeEtreeElement(
                                str(self.__class__.DETAIL_ELEMENT_NAME),
                                SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX,
                                SOAPFaultBase.DEFAULT_ELEMENT_NS)
            
            if ElementTree.iselement(self.detail):
                detailElem.append(self.detail)
                
            elif isinstance(self.detail, basestring): 
                detailElem.text = self.detail
            else:
                raise TypeError('Expecting ElementTree.Element or string '
                                'type for SOAPFault detail; got %r' %
                                type(self.detail))
                
            self.elem.append(detailElem)
    
    def parse(self, source):
        """Parse SOAPFault element"""
        if ElementTree.iselement(source):
            self.elem = source
        else:
            self.elem = self._parse(source)
                  
        for elem in self.elem:
            localName = QName.getLocalPart(elem.tag)
            if localName == SOAPFault.FAULT_CODE_ELEMENT_LOCAL_NAME:
                self.faultCode = elem.text.strip() 
                
            elif localName == SOAPFault.FAULT_STRING_ELEMENT_LOCAL_NAME:
                self.faultString = elem.text.strip()
            
            elif localName == SOAPFault.FAULT_ACTOR_ELEMENT_LOCAL_NAME:
                self.faultActor = elem.text.strip()    
            
            elif localName == SOAPFault.DETAIL_ELEMENT_LOCAL_NAME:
                # Make no assumptions about the content, simply assing the 
                # element to the detail attribute
                self.detail = elem   
                 
            else:
                faultCode = str(QName(SOAPFault.DEFAULT_ELEMENT_NS, 
                                  tag=SOAPFault.CLIENT_FAULT_CODE, 
                                  prefix=SOAPFault.DEFAULT_ELEMENT_NS_PREFIX))
                
                raise SOAPFaultException('Invalid child element in SOAP '
                                         'Fault "%s" for stream %r' % 
                                         (localName, source),
                                         faultCode)
            
    def serialize(self):
        """Serialise element tree into string"""
        return ETreeSOAPExtensions._serialize(self.elem)
    
    def prettyPrint(self):
        """Basic pretty printing separating each element on to a new line"""
        return ETreeSOAPExtensions._prettyPrint(self.elem)


class SOAPFaultException(SOAPFaultExceptionBase):
    """Extend SOAP Fault Exception base class to use ElementTree based 
    SOAP Fault implementation for parsing and serialisation"""
    SOAP_FAULT_CLASS = SOAPFault
    
    
class SOAPEnvelope(SOAPEnvelopeBase, ETreeSOAPExtensions):
    """ElementTree based SOAP implementation"""
    DEFAULT_ELEMENT_NAME = QName(SOAPEnvelopeBase.DEFAULT_ELEMENT_NS,
                             tag=SOAPEnvelopeBase.DEFAULT_ELEMENT_LOCAL_NAME,
                             prefix=SOAPEnvelopeBase.DEFAULT_ELEMENT_NS_PREFIX)

    def __init__(self):
        SOAPEnvelopeBase.__init__(self)
        ETreeSOAPExtensions.__init__(self)
        
        self.qname = QName(SOAPEnvelopeBase.DEFAULT_ELEMENT_NS, 
                           tag=SOAPEnvelopeBase.DEFAULT_ELEMENT_LOCAL_NAME, 
                           prefix=SOAPEnvelopeBase.DEFAULT_ELEMENT_NS_PREFIX)
        self.__header = SOAPHeader()
        self.__body = SOAPBody()

    def _getHeader(self):
        return self.__header

    def _setHeader(self, value):
        if not isinstance(value, SOAPHeader):
            raise TypeError('Expecting %r for "header" attribute; got %r' %
                            (SOAPHeader, type(value)))
        self.__header = value

    def _getBody(self):
        return self.__body

    def _setBody(self, value):
        if not isinstance(value, SOAPBody):
            raise TypeError('Expecting %r for "header" attribute; got %r' %
                            (SOAPBody, type(value)))
        self.__body = value

    header = property(_getHeader, _setHeader, None, "SOAP header object")
    body = property(_getBody, _setBody, None, "SOAP body object")

    def create(self):
        """Create SOAP Envelope with header and body"""
        
        self.elem = etree.makeEtreeElement(str(self.qname),
                                SOAPEnvelopeBase.DEFAULT_ELEMENT_NS_PREFIX,
                                SOAPEnvelopeBase.DEFAULT_ELEMENT_NS)
            
        self.header.create()
        self.elem.append(self.header.elem)
        
        self.body.create()
        self.elem.append(self.body.elem)
    
    def serialize(self):
        """Serialise element tree into string"""
        return ETreeSOAPExtensions._serialize(self.elem)
    
    def prettyPrint(self):
        """Basic pretty printing separating each element onto a new line"""
        return ETreeSOAPExtensions._prettyPrint(self.elem)
    
    def parse(self, source):
        """Parse SOAP Envelope"""
        self.elem = self._parse(source) 
        
        for elem in self.elem:
            localName = QName.getLocalPart(elem.tag)
            if localName == SOAPHeader.DEFAULT_ELEMENT_LOCAL_NAME:
                self.header.elem = elem
                
            elif localName == SOAPBody.DEFAULT_ELEMENT_LOCAL_NAME:
                self.body.parse(elem)
            else:
                faultCode = str(QName(SOAPEnvelopeBase.DEFAULT_ELEMENT_NS, 
                                  tag=SOAPFault.CLIENT_FAULT_CODE, 
                                  prefix=SOAPFault.DEFAULT_ELEMENT_NS_PREFIX))
                
                raise SOAPFaultException('Invalid child element in SOAP '
                                         'Envelope "%s" for stream %r' % 
                                         (localName, source),
                                         faultCode)
