"""SAML 2.0 bindings module implements SOAP binding for attribute query

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/09/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

from os import path
from ConfigParser import ConfigParser, SafeConfigParser

from ndg.saml.common import SAMLObject

from ndg.saml.utils.factory import importModuleObject
from ndg.soap import SOAPEnvelopeBase
from ndg.soap.etree import SOAPEnvelope
from ndg.soap.client import (UrlLib2SOAPClient, UrlLib2SOAPRequest)

from ndg.saml.saml2.binding.soap import SOAPBindingInvalidResponse
    
    
_isIterable = lambda obj: getattr(obj, '__iter__', False) 
   

class SOAPBinding(object):
    '''Client SAML SOAP Binding'''
    SOAP_ACTION = 'http://www.oasis-open.org/committees/security'
    
    REQUEST_ENVELOPE_CLASS_OPTNAME = 'requestEnvelopeClass'
    RESPONSE_ENVELOPE_CLASS_OPTNAME = 'responseEnvelopeClass'
    SERIALISE_OPTNAME = 'serialise'
    DESERIALISE_OPTNAME = 'deserialise'  
    
    CONFIG_FILE_OPTNAMES = (
        REQUEST_ENVELOPE_CLASS_OPTNAME,
        RESPONSE_ENVELOPE_CLASS_OPTNAME,
        SERIALISE_OPTNAME,
        DESERIALISE_OPTNAME
    )
    
    __PRIVATE_ATTR_PREFIX = "__"
    __slots__ = tuple([__PRIVATE_ATTR_PREFIX + i 
                       for i in CONFIG_FILE_OPTNAMES + ("client",)])
    del i
    
    isIterable = staticmethod(_isIterable)
    
    def __init__(self, 
                 requestEnvelopeClass=SOAPEnvelope,
                 responseEnvelopeClass=SOAPEnvelope,
                 serialise=None,
                 deserialise=None,
                 handlers=()):
        '''Create SAML SOAP Client - Nb. serialisation functions must be set
        before send()ing the request'''
        self.__client = None
        self.__serialise = None
        self.__deserialise = None
        
        if serialise is not None:
            self.serialise = serialise
            
        if deserialise is not None:
            self.deserialise = deserialise
        
        self.client = UrlLib2SOAPClient()
        self.client.httpHeader['SOAPAction'] = SOAPBinding.SOAP_ACTION
        
        # Configurable envelope classes
        self.requestEnvelopeClass = requestEnvelopeClass
        self.client.responseEnvelopeClass = responseEnvelopeClass

        if not SOAPBinding.isIterable(handlers):
            raise TypeError('Expecting iterable for "handlers" keyword; got %r'
                            % type(handlers))
           
        for handler in handlers:
            self.client.openerDirector.add_handler(handler())

    def _getSerialise(self):
        return self.__serialise

    def _setSerialise(self, value):
        if isinstance(value, basestring):
            self.__serialise = importModuleObject(value)
            
        elif callable(value):
            self.__serialise = value
        else:
            raise TypeError('Expecting callable for "serialise"; got %r' % 
                            value)

    serialise = property(_getSerialise, _setSerialise, 
                         doc="callable to serialise request into XML type")

    def _getDeserialise(self):
        return self.__deserialise

    def _setDeserialise(self, value):
        if isinstance(value, basestring):
            self.__deserialise = importModuleObject(value)
            
        elif callable(value):
            self.__deserialise = value
        else:
            raise TypeError('Expecting callable for "deserialise"; got %r' % 
                            value)
        

    deserialise = property(_getDeserialise, 
                           _setDeserialise, 
                           doc="callable to de-serialise response from XML "
                               "type")

    def _getRequestEnvelopeClass(self):
        return self.__requestEnvelopeClass

    def _setRequestEnvelopeClass(self, value):
        if isinstance(value, basestring):
            self.client.responseEnvelopeClass = importModuleObject(value)
            
        elif issubclass(value, SOAPEnvelopeBase):
            self.client.responseEnvelopeClass = value
        else:
            raise TypeError('Expecting %r derived type or string for '
                            '"requestEnvelopeClass" attribute; got %r' % 
                            (SOAPEnvelopeBase, value))
        
        self.__requestEnvelopeClass = value

    requestEnvelopeClass = property(_getRequestEnvelopeClass, 
                                    _setRequestEnvelopeClass, 
                                    doc="SOAP Envelope Request Class")

    def _getClient(self):
        return self.__client

    def _setClient(self, value):     
        if not isinstance(value, UrlLib2SOAPClient):
            raise TypeError('Expecting %r for "client"; got %r' % 
                            (UrlLib2SOAPClient, type(value)))
        self.__client = value

    client = property(_getClient, _setClient, 
                      doc="SOAP Client object")   

    def send(self, samlObj, uri=None, request=None):
        '''Make an request/query to a remote SAML service
        
        @type samlObj: saml.common.SAMLObject
        @param samlObj: SAML query/request object
        @type uri: basestring 
        @param uri: uri of service.  May be omitted if set from request.url
        @type request: ndg.security.common.soap.UrlLib2SOAPRequest
        @param request: SOAP request object to which query will be attached
        defaults to ndg.security.common.soap.client.UrlLib2SOAPRequest
        '''
        if self.serialise is None:
            raise AttributeError('No "serialise" method set to serialise the '
                                 'request')

        if self.deserialise is None:
            raise AttributeError('No "deserialise" method set to deserialise '
                                 'the response')
           
        if not isinstance(samlObj, SAMLObject):
            raise TypeError('Expecting %r for input attribute query; got %r'
                            % (SAMLObject, type(samlObj)))
            
        if request is None:
            request = UrlLib2SOAPRequest()
            request.envelope = self.requestEnvelopeClass()
            request.envelope.create()
            
        if uri is not None:
            request.url = uri
        
        samlElem = self.serialise(samlObj)
            
        # Attach query to SOAP body
        request.envelope.body.elem.append(samlElem)
            
        response = self.client.send(request)
        
        if len(response.envelope.body.elem) != 1:
            raise SOAPBindingInvalidResponse("Expecting single child element "
                                             "is SOAP body")
            
        response = self.deserialise(response.envelope.body.elem[0])
        
        return response

    @classmethod
    def fromConfig(cls, cfg, **kw):
        '''Alternative constructor makes object from config file settings
        @type cfg: basestring / ConfigParser derived type
        @param cfg: configuration file path or ConfigParser type object
        @rtype: ndg.saml.saml2.binding.soap.client.SOAPBinding or derived type
        @return: new instance of this class
        '''
        obj = cls()
        obj.parseConfig(cfg, **kw)
        
        return obj

    def parseConfig(self, cfg, prefix='', section='DEFAULT'):
        '''Read config file settings
        @type cfg: basestring /ConfigParser derived type
        @param cfg: configuration file path or ConfigParser type object
        @type prefix: basestring
        @param prefix: prefix for option names e.g. "attributeQuery."
        @type section: baestring
        @param section: configuration file section from which to extract
        parameters.
        '''  
        if isinstance(cfg, basestring):
            cfgFilePath = path.expandvars(cfg)
            hereDir = path.dirname(cfgFilePath)
            _cfg = SafeConfigParser(defaults=dict(here=hereDir))
            _cfg.optionxform = str

            _cfg.read(cfgFilePath)
            
        elif isinstance(cfg, ConfigParser):
            _cfg = cfg   
        else:
            raise AttributeError('Expecting basestring or ConfigParser type '
                                 'for "cfg" attribute; got %r type' % type(cfg))
        
        # Get items for this section as a dictionary so that parseKeywords can
        # used to update the object
        kw = dict(_cfg.items(section))
        if 'prefix' not in kw and prefix:
            kw['prefix'] = prefix
            
        self.parseKeywords(**kw)
        
    def parseKeywords(self, prefix='', **kw):
        """Update object from input keywords
        
        @type prefix: basestring
        @param prefix: if a prefix is given, only update self from kw items 
        where keyword starts with this prefix
        @type kw: dict
        @param kw: items corresponding to class instance variables to 
        update.  Keyword names must match their equivalent class instance 
        variable names.  However, they may prefixed with <prefix>
        """
        prefixLen = len(prefix)
        for optName, val in kw.items():
            if prefix:
                # Filter attributes based on prefix
                if optName.startswith(prefix):
                    setattr(self, optName[prefixLen:], val)
            else:
                # No prefix set - attempt to set all attributes   
                setattr(self, optName, val)
                
    @classmethod
    def fromKeywords(cls, prefix='', **kw):
        """Create a new instance initialising instance variables from the 
        keyword inputs
        @type prefix: basestring
        @param prefix: if a prefix is given, only update self from kw items 
        where keyword starts with this prefix
        @type kw: dict
        @param kw: items corresponding to class instance variables to 
        update.  Keyword names must match their equivalent class instance 
        variable names.  However, they may prefixed with <prefix>
        @return: new instance of this class
        @rtype: ndg.saml.saml2.binding.soap.client.SOAPBinding or derived type
        """
        obj = cls()
        obj.fromKeywords(prefix=prefix, **kw)
        
        return obj
        
    def __setattr__(self, name, value):
        """Enable setting of SOAPBinding.client.responseEnvelopeClass as if it
        were an attribute of self
        """
        try:
            super(SOAPBinding, self).__setattr__(name, value)
            
        except AttributeError:
            if 'name' == SOAPBinding.RESPONSE_ENVELOPE_CLASS_OPTNAME:
                if isinstance(value, basestring):
                    self.client.responseEnvelopeClass = importModuleObject(value)
                elif issubclass(value, SOAPEnvelopeBase):
                    self.client.responseEnvelopeClass = value
                else:
                    raise TypeError('Expecting string or type instance for %r; '
                                    'got %r instead.' % (name, type(value)))
            else:
                raise
                    
    def __getstate__(self):
        '''Explicit implementation needed with __slots__'''
        _dict = {}
        for attrName in SOAPBinding.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_SOAPBinding" + attrName
                
            _dict[attrName] = getattr(self, attrName)
            
        return _dict
        
    def __setstate__(self, attrDict):
        '''Explicit implementation needed with __slots__'''
        for attr, val in attrDict.items():
            setattr(self, attr, val)
