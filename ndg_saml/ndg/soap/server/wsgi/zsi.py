"""WSGI SOAP Middleware utilising the ZSI Python SOAP Package

NERC DataGrid Project

"""
__author__ = "P J Kershaw"
__date__ = "19/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id: $"
import logging
log = logging.getLogger(__name__)

import sys

from ZSI.parse import ParsedSoap
from ZSI.writer import SoapWriter
from ZSI import fault
from ZSI.ServiceContainer import ServiceSOAPBinding

from ndg.security.server.wsgi.soap import SOAPMiddleware, SOAPMiddlewareError,\
    SOAPMiddlewareConfigError, SOAPMiddlewareReadError
from ndg.security.common.wssecurity.utils import DomletteReader, \
    DomletteElementProxy
from ndg.security.common.utils.classfactory import instantiateClass, \
    importClass
      
class ZSIMiddlewareError(SOAPMiddlewareError):
    """Base class for ZSI Middleware type exceptions"""
    
class ZSIMiddlewareReadError(SOAPMiddlewareReadError):
    """ZSI Middleware read error"""

class ZSIMiddlewareConfigError(SOAPMiddlewareConfigError):
    """ZSI middleware configuration error"""
     
class ZSIMiddleware(SOAPMiddleware):
    '''Middleware configurable to a given ZSI SOAP binding

     @type SOAP_WRITER_KEYNAME: basestring
     @cvar SOAP_WRITER_KEYNAME: environ key for ZSI SoapWriter instance
     @type PARSED_SOAP_KEYNAME: basestring
     @cvar PARSED_SOAP_KEYNAME: environ key for ZSI ParsedSoap instance
     @type CHARSET_OPTNAME: basestring
     @cvar CHARSET_OPTNAME: option name to for character set for output
     @type DEFAULT_CHARSET: basestring
     @cvar DEFAULT_CHARSET: default character setting is utf-8
     @type PATH_OPTNAME: basestring
     @cvar PATH_OPTNAME: option to set path for this endpoint (not including 
     domain name)
     @type WRITE_RESPONSE_OPTNAME: basestring 
     @cvar WRITE_RESPONSE_OPTNAME: option name for flag to middleware to 
     serialise and output the SoapWriter instance
     @type REFERENCED_FILTERS_OPTNAME: basestring
     @cvar REFERENCED_FILTERS_OPTNAME: name for option to enable dereferencing 
     of other middleware via these environ keys
     @type FILTER_ID_OPTNAME: basestring
     @cvar FILTER_ID_OPTNAME: option name for environ key to enable other 
     middleware to reference this Filter
     @type PUBLISHED_URI_OPTNAME: basestring
     @cvar PUBLISHED_URI_OPTNAME: option name to define path for this endpoint
     including domain name
     @type READER_CLASS_OPTNAME: basestring
     @cvar READER_CLASS_OPTNAME: option name for SOAP reader class
     @type WRITERCLASS_OPTNAME: basestring
     @cvar WRITERCLASS_OPTNAME: option name for SOAP writer class
     '''  
    
    SOAP_WRITER_KEYNAME = 'ZSI.writer.SoapWriter'
    PARSED_SOAP_KEYNAME = 'ZSI.parse.ParsedSoap'
    
    CHARSET_OPTNAME = 'charset'
    DEFAULT_CHARSET = '; charset=utf-8'
    PATH_OPTNAME = 'path'
    WRITE_RESPONSE_OPTNAME = 'writeResponse'
    REFERENCED_FILTERS_OPTNAME = 'referencedFilters'
    FILTER_ID_OPTNAME = 'filterID'
    PUBLISHED_URI_OPTNAME = 'publishedURI'
    READER_CLASS_OPTNAME = 'readerclass'
    WRITERCLASS_OPTNAME = 'writerclass'
    
    def __init__(self, app):
        log.debug("ZSIMiddleware.__init__ ...")
        super(ZSIMiddleware, self).__init__()
        
        self._app = app
        self.__charset = ZSIMiddleware.DEFAULT_CHARSET
        self.__path = None
        self.__referencedFilterKeys = None
        self.__publishedURI = None
        self.__readerClass = None
        self.__writerClass = None
        self.__writeResponseSet = None
        self.__filterID = None

    def _getCharset(self):
        return self.__charset

    def _setCharset(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "charset" got %r' %
                            type(value))
        self.__charset = value

    def _getPath(self):
        return self.__path

    def _setPath(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "path" got %r' %
                            type(value))
        self.__path = value

    def _getPublishedURI(self):
        return self.__publishedURI

    def _setPublishedURI(self, value):
        if not isinstance(value, (basestring, type(None))):
            raise TypeError('Expecting string or None type for "publishedURI" '
                            'got %r' % type(value))
        self.__publishedURI = value

    def _getReaderClass(self):
        return self.__readerClass

    def _setReaderClass(self, value):
        self.__readerClass = value

    def _getWriterClass(self):
        return self.__writerClass

    def _setWriterClass(self, value):
        self.__writerClass = value

    def _getWriteResponseSet(self):
        return self.__writeResponseSet

    def _setWriteResponseSet(self, value):
        if not isinstance(value, bool):
            raise TypeError('Expecting %r for "writeResponseSet" type got %r' %
                            (bool, type(value)))
        
        self.__writeResponseSet = value

    def _getFilterID(self):
        return self.__filterID

    def _setFilterID(self, value):
        if not isinstance(value, (basestring, type(None))):
            raise TypeError('Expecting string or None type for "filterID" got '
                            '%r' % type(value))
        self.__filterID = value

    charset = property(_getCharset, _setCharset, 
                       doc="character set for response")

    path = property(_getPath, _setPath, doc="Path for endpoint")

    publishedURI = property(_getPublishedURI, _setPublishedURI, 
                            doc="fully qualified path for endpoint")

    readerClass = property(_getReaderClass, _setReaderClass, 
                           doc="ZSI Reader class")

    writeResponseSet = property(_getWriteResponseSet, _setWriteResponseSet, 
                                doc="boolean set to True to write out a "
                                    "response from this middleware")

    writerClass = property(_getWriterClass, _setWriterClass, 
                           doc="ZSI Writer Class")

    filterID = property(_getFilterID, _setFilterID, 
                        doc="enable the instance of this middleware to be "
                            "referenced in environ by this identifier")

    def initialise(self, global_conf, prefix='', **app_conf):
        """Set-up ZSI middleware interface attributes.  Overloaded base class 
        method to enable custom settings from app_conf
        
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        charsetOptName = prefix + ZSIMiddleware.CHARSET_OPTNAME
        if charsetOptName in app_conf:
            self.charset = '; charset=' + app_conf[charsetOptName]
        else:
            self.charset = '; charset=utf-8'
            
        pathOptName = prefix + ZSIMiddleware.PATH_OPTNAME
        if pathOptName in app_conf:
            if app_conf[pathOptName] != '/':
                self.path = app_conf[pathOptName].rstrip('/')
            else:
                self.path = app_conf[pathOptName]
        else:
            self.path = '/'

        # This flag if set to True causes this handler to call the 
        # start_response method and output the SOAP response
        writeResponseOptName = prefix + ZSIMiddleware.WRITE_RESPONSE_OPTNAME
        self.writeResponseSet = ZSIMiddleware.str2Bool(app_conf.get(
                                                    writeResponseOptName, ''))

        # Check for a list of other filters to be referenced by this one
        referencedFiltersOptName = prefix + \
                                    ZSIMiddleware.REFERENCED_FILTERS_OPTNAME
        if referencedFiltersOptName in app_conf:
            # __call__  may reference any filters in environ keyed by these
            # keywords
            self.referencedFilterKeys = app_conf.pop(
                                            referencedFiltersOptName).split()

        
        filterIdOptName = prefix + ZSIMiddleware.FILTER_ID_OPTNAME
        self.filterID = app_conf.pop(filterIdOptName, None)
        
        # The endpoint that this services will be referenced from externally.
        # e.g. the Session Manager client running locally can check the
        # input URI and compare with this value to see if the request is 
        # actually to the local Session Manager instance
        publishedUriOptName = prefix + ZSIMiddleware.PUBLISHED_URI_OPTNAME
        self.publishedURI = app_conf.pop(publishedUriOptName, None)
        
        readerClassOptName = prefix + ZSIMiddleware.READER_CLASS_OPTNAME
        if readerClassOptName in app_conf:
            readerClassName = app_conf.pop(readerClassOptName)
            self.readerClass = importClass(readerClassName)
        else:
            self.readerClass = DomletteReader
            
        writerClassOptName = prefix + ZSIMiddleware.WRITERCLASS_OPTNAME
        if writerClassOptName in app_conf:
            writerClassName = app_conf.pop(writerClassOptName)
            self.writerClass = importClass(writerClassName)
        else:
            self.writerClass = DomletteElementProxy

    def __call__(self, environ, start_response):
        log.debug("ZSIMiddleware.__call__")
                        
        # Derived class must implement SOAP Response via overloaded version of
        # this method.  ParsedSoap object is available as a key in environ via
        # the parseRequest method
        
        return self.writeResponse(environ, start_response)

    
    def _initCall(self, environ, start_response):
        '''Sub-divided out from __call__ to enable derived classes to easily
        include this functionality:
         - Set a reference to this WSGI filter in environ if filterID was 
        set in the config and 
         - check the request to see if this filter should handle it
        '''
        
        # Add any filter references for this WSGI component regardless of the
        # current request ID.  This ensures that other WSGI components called
        # may reference it if they need to.
        self.addFilter2Environ(environ)
        
        # Apply filter for calls
        if not self.__class__.isSOAPMessage(environ):
            log.debug("ZSIMiddleware.__call__: skipping non-SOAP call")
            return self._app(environ, start_response)
        
        elif not self.pathMatch(environ):
            log.debug("ZSIMiddleware.__call__: path doesn't match SOAP "
                      "service endpoint")
            return self._app(environ, start_response)
        
        elif self.__class__.isSOAPFaultSet(environ):
            # This MUST be checked in a overloaded version especially in 
            # consideration of security: e.g. an upstream signature 
            # verification may have found an error in a signature
            log.debug("ZSIMiddleware.__call__: SOAP fault set by previous "
                      "SOAP middleware filter")
            return self._app(environ, start_response)

        # Parse input into a ZSI ParsedSoap object set as a key in environ
        try:
            self.parseRequest(environ)
        except Exception, e:
            sw = self.exception2SOAPFault(environ, e)
            self.setSOAPWriter(environ, sw)
            return self.writeResponse(environ, start_response)
        
        # Return None to __call__ to indicate that it can proceed with 
        # processing the input
        return None

    def exception2SOAPFault(self, environ, exception):
        '''Convert an exception into a SOAP fault message'''
        soapFault = fault.FaultFromException(exception, 
                                             None,
                                             tb=sys.exc_info()[2])
        sw = SoapWriter(outputclass=self.writerClass)
        soapFault.serialize(sw)
        environ[ZSIMiddleware.SOAP_FAULT_SET_KEYNAME] = True
        return sw
    
    pathMatch = lambda self, environ: environ['PATH_INFO'] == self.path
    
    def parseRequest(self, environ):
        '''Parse SOAP message from environ['wsgi.input']
        
        Reading from environ['wsgi.input'] may be a destructive process so the
        content is saved in a ZSI.parse.ParsedSoap object for use by SOAP
        handlers which follow in the chain
        
        environ['ZSI.parse.ParsedSoap'] may be set to a ParsedSoap object
        parsed by a SOAP handler ahead of the current one in the chain.  In
        this case, don't re-parse.  If NOT parsed, parse and set
        'ZSI.parse.ParsedSoap' environ key'''
        
        # Check for ParsedSoap object set in environment, if not present,
        # make one
        ps = environ.get(ZSIMiddleware.PARSED_SOAP_KEYNAME)
        if ps is None:
            # TODO: allow for chunked data
            contentLength = int(environ['CONTENT_LENGTH'])
            soapIn = environ['wsgi.input'].read(contentLength)
            if len(soapIn) < contentLength:
                raise ZSIMiddlewareReadError("Expecting %d content length; "
                                             "received %d instead." % 
                                             (contentLength, len(soapIn)))
            
            log.debug("SOAP Request for handler %r" % ZSIMiddleware)
            log.debug("_" * 80)
            log.debug(soapIn)
            log.debug("_" * 80)
            
            ps = ParsedSoap(soapIn, readerclass=self.readerClass)
            environ[ZSIMiddleware.PARSED_SOAP_KEYNAME] = ps
            
        return environ[ZSIMiddleware.PARSED_SOAP_KEYNAME]


    def writeResponse(self, environ, start_response, errorCode=None):
        '''This method serializes the SOAP output and sets the response header.
        It's the final step and should be called in the last SOAP handler in 
        a chain of handlers or else specify it in the ini file as the last
        SOAP handler'''
        
        # This flag must be set to True to write out the final response from
        # this handler
        if self.writeResponseSet == False:
            return self._app(environ, start_response)
        
        sw = self.getSOAPWriter(environ)
        soapOut = str(sw)
        
        if errorCode is None:
            if self.__class__.isSOAPFaultSet(environ):
                errorCode = "500 Internal Server Error"
            else:
                errorCode = "200 OK"
                
        log.debug("SOAP Response for handler %r" % self.__class__)
        log.debug("_" * 80)
        log.debug(soapOut)
        log.debug("_" * 80)
        start_response(errorCode,
                       [('content-type', 'text/xml' + self.charset),
                        ('content-length', str(len(soapOut)))])
        return soapOut

    @classmethod
    def getSOAPWriter(cls, environ):
        '''Access SoapWriter object set in environment by this classes' call
        method'''
        
        sw = environ.get(ZSIMiddleware.SOAP_WRITER_KEYNAME)
        if sw is None:
            raise KeyError("Expecting '%s' key in environ: missing call to "
                           "ZSIMiddleware?" % ZSIMiddleware.SOAP_WRITER_KEYNAME)
        return sw
    
    @classmethod
    def setSOAPWriter(cls, environ, sw):
        '''Set SoapWriter object in environment'''   
        environ[ZSIMiddleware.SOAP_WRITER_KEYNAME] = sw

    def addFilter2Environ(self, environ):
        '''Add a key to the current application in the environment so that
        other middleware can reference it.  This is dependent on filterID set
        in app_conf'''
        if self.filterID is not None:           
            if self.filterID in environ:
                raise ZSIMiddlewareConfigError("An filterID key '%s' is "
                                                "already set in environ" % 
                                                self.filterID)
            environ[self.filterID] = self


class SOAPBindingMiddleware(ZSIMiddleware):  
    '''Interface to apply a ZSI ServiceSOAPBinding type SOAP service'''
    
    SERVICE_SOAP_BINDING_CLASSNAME_OPTNAME = 'serviceSOAPBindingClass'
    SERVICE_SOAP_BINDING_PROPPREFIX_OPTNAME = 'serviceSOAPBindingPropPrefix'
    DEFAULT_SERVICE_SOAP_BINDING_PROPPREFIX_OPTNAME = \
                            'ndg.security.server.wsgi.zsi.serviceSOAPBinding.'
                            
    SERVICE_SOAP_BINDING_ENVIRON_KEYNAME_OPTNAME = \
                            'serviceSOAPBindingEnvironKeyName' 
    DEFAULT_SERVICE_SOAP_BINDING_ENVIRON_KEYNAME = \
                            'ndg.security.servier.wsgi.zsi.serviceSOAPBinding'
    ENABLE_WSDL_QUERY_OPTNAME = 'enableWSDLQuery' 
    DEFAULT_ENABLE_WSDL_QUERY_VALUE = False
    SOAP_METHOD_STRING = 'soap_%s'
    
    def __init__(self, app):
        super(SOAPBindingMiddleware, self).__init__(app)
        self.__serviceSOAPBindingKeyName = None
        self.__serviceSOAPBinding = None
        self.__enableWSDLQuery = False
        
    def _getServiceSOAPBinding(self):
        return self.__serviceSOAPBinding

    def _setServiceSOAPBinding(self, value):
        """Instance must be ZSI ServiceSOAPBinding derived type"""
        if not isinstance(value, ServiceSOAPBinding):
            raise TypeError('Expecting %r type for "serviceSOAPBinding"; got '
                            '%r' % (ServiceSOAPBinding, type(value)))
        self.__serviceSOAPBinding = value

    serviceSOAPBinding = property(fget=_getServiceSOAPBinding, 
                                  fset=_setServiceSOAPBinding, 
                                  doc="Instance of ZSI ServiceSOAPBinding "
                                      "derived type determines the behaviour "
                                      "of the SOAP callbacks")

    def _getServiceSOAPBindingKeyName(self):
        return self.__serviceSOAPBindingKeyName

    def _setServiceSOAPBindingKeyName(self, value):
        """Instance must be ZSI ServiceSOAPBindingKeyName derived type"""
        if not isinstance(value, basestring):
            raise TypeError('Expecting bool type for "enableWSDLQuery"; got '
                            '%r' % type(value))
        self.__serviceSOAPBindingKeyName = value

    serviceSOAPBindingKeyName = property(fget=_getServiceSOAPBindingKeyName, 
                                         fset=_setServiceSOAPBindingKeyName, 
                                         doc="Keyword to key WSGI environ for "
                                             "SOAP Binding middleware instance")

    def _getEnableWSDLQuery(self):
        return self.__enableWSDLQuery

    def _setEnableWSDLQuery(self, value):
        if not isinstance(value, bool):
            raise TypeError('Expecting bool type for "enableWSDLQuery"; got '
                            '%r' % type(value))
        self.__enableWSDLQuery = value
        
    enableWSDLQuery = property(fget=_getEnableWSDLQuery, 
                               fset=_setEnableWSDLQuery, 
                               doc="Enable service to publish the WSDL via "
                                   "the ?wsdl query argument appended to the "
                                   "endpoint")

    def initialise(self, global_conf, prefix='', **app_conf):
        """Set-up ZSI SOAP Binding middleware interface attributes.
         Overloaded base class method to enable custom settings from app_conf
        
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        super(SOAPBindingMiddleware, self).initialise(global_conf, 
                                                      prefix=prefix,
                                                      **app_conf)
        
        serviceSOAPBindingEnvironKeyNameOptName = prefix + \
            SOAPBindingMiddleware.SERVICE_SOAP_BINDING_ENVIRON_KEYNAME_OPTNAME
        serviceSOAPBindingClassNameOptName = prefix + \
            SOAPBindingMiddleware.SERVICE_SOAP_BINDING_CLASSNAME_OPTNAME
                            
        if serviceSOAPBindingEnvironKeyNameOptName in app_conf and \
           serviceSOAPBindingClassNameOptName in app_conf:
            raise ZSIMiddlewareConfigError('Only "%s" or "%s" may be set; not '
                                           ' both' % 
            (SOAPBindingMiddleware.SERVICE_SOAP_BINDING_ENVIRON_KEYNAME_OPTNAME,
             SOAPBindingMiddleware.SERVICE_SOAP_BINDING_CLASSNAME_OPTNAME))
            
        if serviceSOAPBindingClassNameOptName in app_conf:
            # Instantiate the binding from the config settings
            modName, className = app_conf[
                            serviceSOAPBindingClassNameOptName].rsplit('.', 1)
                
            # Filter
            prefixOptName = prefix + \
                SOAPBindingMiddleware.SERVICE_SOAP_BINDING_PROPPREFIX_OPTNAME
            prefix = app_conf.get(prefixOptName,
                            SOAPBindingMiddleware.
                            DEFAULT_SERVICE_SOAP_BINDING_PROPPREFIX_OPTNAME)
            
            serviceSOAPBindingKw = dict([(k.replace(prefix, ''), v)
                                         for k, v in app_conf.items()
                                         if k.startswith(prefix)])
    
            self.serviceSOAPBinding = instantiateClass(modName,
                                       className,
                                       objectType=ServiceSOAPBinding,
                                       classProperties=serviceSOAPBindingKw)           
        else: 
            # Alternatively, reference another binding instance made available
            # by upstream middleware via environ
            self.serviceSOAPBindingKeyName = app_conf.get(
                            serviceSOAPBindingEnvironKeyNameOptName,
                            SOAPBindingMiddleware.
                            DEFAULT_SERVICE_SOAP_BINDING_ENVIRON_KEYNAME)
        
        
        # Flag to enable display of WSDL via wsdl query arg in a GET request
        enableWSDLQueryOptName = prefix + \
                                SOAPBindingMiddleware.ENABLE_WSDL_QUERY_OPTNAME
        self.enableWSDLQuery = SOAPBindingMiddleware.str2Bool(
                                    app_conf.get(enableWSDLQueryOptName, ''))   
    
    def __call__(self, environ, start_response):
        log.debug("SOAPBindingMiddleware.__call__ ...")
             
        # Get a reference to the service SOAP binding from environ or if not,
        # from the binding instantiated at initialisation
        serviceSOAPBinding = environ.get(self.serviceSOAPBindingKeyName,
                                         self.serviceSOAPBinding)
        if serviceSOAPBinding is None:
            raise ZSIMiddlewareConfigError('No SOAP service binding set in '
                                           'environ or configured from start'
                                           '-up')
             
        if self.pathMatch(environ) and self.enableWSDLQuery and \
           environ.get('REQUEST_METHOD', '') == 'GET' and \
           environ.get('QUERY_STRING', '') == 'wsdl':
            wsdl = serviceSOAPBinding._wsdl
            start_response("200 OK", [('Content-type', 'text/xml'),
                                      ('Content-length', str(len(wsdl)))])
            return wsdl 
                
        # Apply filter for calls
        response = self._initCall(environ, start_response)
        if response is not None:
            return response
          
        try:
            # Other filters in the middleware chain may be passed by setting
            # a reference to them in the config.  This is useful if the SOAP
            # binding code needs to access results from upstream middleware 
            # e.g. check output from signature verification filter
            if hasattr(self, 'referencedFilterKeys'):
                try:
                    serviceSOAPBinding.referencedWSGIFilters = \
                                    dict([(i, environ[i]) 
                                          for i in self.referencedFilterKeys])
                except KeyError:
                    raise ZSIMiddlewareConfigError('No filter ID "%s" found '
                                                   'in environ' % i)    
            ps = self.parseRequest(environ)
               
            # Map SOAP Action to method in binding class
            soapActionName = environ[
                            SOAPBindingMiddleware.SOAP_ACTION_ENVIRON_KEYNAME
                            ].strip('"')
            soapMethodName = SOAPBindingMiddleware.SOAP_METHOD_STRING % \
                            soapActionName
                    
            
            method = getattr(serviceSOAPBinding, soapMethodName)            
            resp = method(ps)
        except Exception, e:
            sw = self.exception2SOAPFault(environ, e)
        else: 
            # Serialize output using SOAP writer class
            sw = SoapWriter(outputclass=self.writerClass)
            sw.serialize(resp)
        
        # Make SoapWriter object available to any SOAP filters that follow
        self.setSOAPWriter(environ, sw)
        soapOut = str(sw)

        return self.writeResponse(environ, start_response)
