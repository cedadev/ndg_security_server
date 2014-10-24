"""NDG Security SOAP Service Middleware

NERC DataGrid Project

"""
__author__ = "P J Kershaw"
__date__ = "27/05/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id: $"
import logging
log = logging.getLogger(__name__)

     
class SOAPMiddlewareError(Exception):
    """Base error handling exception class for the SOAP WSGI middleware module
    """
    _log = log
    def __init__(self, *arg, **kw):
        '''Extend to enable logging of errors'''
        if len(arg) > 0:
            self.__class__._log.error(arg[0])
        Exception.__init__(self, *arg, **kw)


class SOAPMiddlewareReadError(SOAPMiddlewareError):
    """SOAP Middleware read error"""


class SOAPMiddlewareConfigError(SOAPMiddlewareError):
    """SOAP Middleware configuration error"""


class SOAPMiddleware(object):
    """SOAP WSGI base class"""
    SOAP_FAULT_SET_KEYNAME = 'ndg.security.server.wsgi.soap.soapFault'
    SOAP_ACTION_ENVIRON_KEYNAME = 'HTTP_SOAPACTION'
    
    _str2Bool = lambda str: str.lower() in ["yes", "true", "t", "1"]
    str2Bool = staticmethod(_str2Bool)
        
    @classmethod
    def isSOAPMessage(cls, environ):
        '''Generic method to filter out non-soap messages
        
        TODO: is HTTP_SOAPACTION only set for WSDL doc-literal wrapped style
        generated content? - If so this test should be moved'''
        return environ.get('REQUEST_METHOD', '') == 'POST' and \
               environ.get(cls.SOAP_ACTION_ENVIRON_KEYNAME) is not None

    @classmethod
    def isSOAPFaultSet(cls, environ):
        '''Check environment for SOAP fault flag set.  This variable is set
        from exception2SOAPFault'''
        return environ.get(cls.SOAP_FAULT_SET_KEYNAME, False) == True
        
    @classmethod
    def filter_app_factory(cls, app, global_conf, **app_conf):
        """Set-up using a Paste app factory pattern.  
        
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        app = cls(app)
        app.initialise(global_conf, **app_conf)
        
        return app
    
    def initialise(self, global_conf, **app_conf):
        """Set attributes from keyword dictionaries global and or app_conf
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        """
        raise NotImplementedError()
