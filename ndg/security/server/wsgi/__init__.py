"""WSGI Middleware components

NERC Data Grid Project"""
__author__ = "P J Kershaw"
__date__ = "27/05/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)
import http.client
import re # for NDGSecurityPathFilter

class NDGSecurityMiddlewareError(Exception):
    '''Base exception class for NDG Security middleware'''
    
class NDGSecurityMiddlewareConfigError(NDGSecurityMiddlewareError):
    '''NDG Security Middleware Configuration error'''
    
class NDGSecurityMiddlewareBase(object):
    """Base class for NDG Security Middleware classes
    @cvar USERNAME_ENVIRON_KEYNAME: environ key name for user id as used by
    AuthKit
    @type USERNAME_ENVIRON_KEYNAME: string
    """
    USERNAME_ENVIRON_KEYNAME = 'REMOTE_USER'
    USERDATA_ENVIRON_KEYNAME = 'REMOTE_USER_DATA'
    USERNAME_SESSION_KEYNAME = 'username'
    
    propertyDefaults = {
        'mountPath': '/',
    }
    __slots__ = ('_app', '_environ', '_start_response', '_pathInfo', '_path',
                 '_mountPath')
    
    def __init__(self, app, app_conf, prefix='', **local_conf):
        '''
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type app_conf: dict        
        @param app_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for app_conf parameters e.g. 'ndgsecurity.' -
        enables other global configuration parameters to be filtered out
        @type local_conf: dict        
        @param local_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        self._app = app
        self._environ = {}
        self._start_response = None
        self._pathInfo = None
        self._path = None
        self._mountPath = '/'
                
        # Convenient utility for tracing start_response call
        self.debug_start_response = False
             
        opt = self.__class__.propertyDefaults.copy()
        
        # If no prefix is set, there is no way to distinguish options set for 
        # this app and those applying to other applications
        if app_conf is not None and prefix:
            # Update from application config dictionary - filter using prefix
            self.__class__._filterOpts(opt, app_conf, prefix=prefix)
                        
        # Similarly, filter keyword input                 
        self.__class__._filterOpts(opt, local_conf, prefix=prefix)
        
        # Set options as object attributes
        for name, val in list(opt.items()):
            if not name.startswith('_'):
                setattr(self, name, val)


    def _initCall(self, environ, start_response):
        """Call from derived class' __call__() to set environ and path
        attributes
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        """
        self.environ = environ
        
        if self.debug_start_response:
            def start_response_(status, response_headers, exc_info=None):
                log.debug('Calling start response with '
                          'environ["PATH_INFO"]=%r, '
                          'status=%r, headers=%r, exc_info=%r', 
                          environ['PATH_INFO'], status, response_headers, 
                          exc_info)

                return start_response(status, response_headers, 
                                      exc_info=exc_info)
            
            self.start_response = start_response_
            
        else:
            self.start_response = start_response
            
        self.setPathInfo()
        self.setPath()

    @staticmethod
    def initCall(__call__):
        '''Decorator to __call__ to enable convenient attribute initialisation
        '''
        def __call__wrapper(self, environ, start_response):
            self._initCall(environ, start_response)
            return __call__(self, environ, start_response)

        return __call__wrapper


    def __call__(self, environ, start_response):
        """
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        """
        self._initCall(environ, start_response)
        return self._setResponse(environ, start_response)
    
    def _setResponse(self, 
                     environ=None, 
                     start_response=None, 
                     notFoundMsg=None,
                     notFoundMsgContentType=None):
        """Convenience method to wrap call to next WSGI app in stack or set an
        error if none is set
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary defaults to 
        environ object attribute.  For the latter to be available, the initCall
        decorator method must have been invoked.
        @type start_response: function
        @param start_response: standard WSGI start response function defaults 
        to start_response object attribute.  For the latter to be available, 
        the initCall decorator method must have been invoked.
        """
        if environ is None:
            environ = self.environ
        
        if start_response is None:
            start_response = self.start_response

        if self._app:
            return self._app(environ, start_response)
        else:
            return self._setErrorResponse(start_response=start_response, 
                                          msg=notFoundMsg,
                                          code=404,
                                          contentType=notFoundMsgContentType)
            
    def _setErrorResponse(self, start_response=None, msg=None, 
                          code=500, contentType=None):
        '''Convenience method to set a simple error response
        
        @type start_response: function
        @param start_response: standard WSGI callable to set the HTTP header
        defaults to start_response object attribute.  For the latter to be 
        available, the initCall decorator method must have been invoked.   
        @type msg: basestring
        @param msg: optional error message
        @type code: int
        @param code: standard HTTP error response code
        @type contentType: basestring
        @param contentType: set 'Content-type' HTTP header field - defaults to
        'text/plain'
        '''            
        if start_response is None:
            start_response = self.start_response
            
        status = '%d %s' % (code, http.client.responses[code])
        if msg is None:
            response = status
        else:
            response = msg
        
        if contentType is None:
            contentType = 'text/plain'
                
        start_response(status,
                       [('Content-type', contentType),
                        ('Content-Length', str(len(response)))])
        return [response]
        
    @staticmethod
    def getStatusMessage(statusCode):
        '''Make a standard status message for use with start_response
        @type statusCode: int
        @param statusCode: HTTP status code
        @rtype: str
        @return: status code with standard message
        @raise KeyError: for invalid status code
        '''
        return '%d %s' % (statusCode, http.client.responses[statusCode])
    
    # Utility functions to support Paste Deploy application and filter function
    # signatures
    @classmethod        
    def filter_app_factory(cls, app, app_conf, **local_conf):
        '''Function signature for Paste Deploy filter
        
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type app_conf: dict        
        @param app_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for app_conf parameters e.g. 'ndgsecurity.' -
        enables other global configuration parameters to be filtered out
        @type local_conf: dict        
        @param local_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        return cls(app, app_conf, **local_conf)
       
    @classmethod
    def app_factory(cls, app_conf, **local_conf):
        '''Function Signature for Paste Deploy app'''
        return cls(None, app_conf, **local_conf)
    
    @classmethod
    def _filterOpts(cls, opt, newOpt, prefix='', propertyDefaults=None):
        '''Convenience utility to filter input options set in __init__ via
        app_conf or keywords
        
        @type opt: dict
        @param opt: existing options set.  These will be updated by this
        method based on the content of newOpt
        @type newOpt: dict
        @param newOpt: new options to update opt with
        @type prefix: basestring 
        @param prefix: if set, remove the given prefix from the input options
        @type propertyDefaults: iterable/None
        @param propertyDefaults: property names restricted to this dictionary
        of names.  If None, default to propertyDefaults class variable setting
        @raise KeyError: if an option is set that is not in the classes
        defOpt class variable
        '''
        if propertyDefaults is None:
            propertyDefaults = cls.propertyDefaults
            
        badOpt = []
        for k,v in list(newOpt.items()):
            if prefix and k.startswith(prefix):
                subK = k.replace(prefix, '')                    
                filtK = '_'.join(subK.split('.'))  
            else:
                # Ignore items that are not prefixed
                continue
                    
            if propertyDefaults is not None and filtK not in propertyDefaults:
                badOpt += [k]
            else:
                opt[filtK] = v
                
        if len(badOpt) > 0:
            raise TypeError("Invalid input option(s) set: %s" % 
                            (", ".join(badOpt)))

    def setMountPath(self, mountPath=None, environ=None):
        if mountPath:
            self._mountPath = mountPath
        else:
            if environ is None:
                environ = self._environ
            
            self._mountPath = environ.get('SCRIPT_URL')
            if self._mountPath is None:
                raise AttributeError("SCRIPT_URL key not set in environ: "
                                     "'mountPath' is set to None")
        
        # Comment out as it breaks standard for URL trailing slash 
#        if self._mountPath != '/':
#            self._mountPath = self._mountPath.rstrip('/')
        
    def _getMountPath(self):
        return self._mountPath
    
    mountPath = property(fget=_getMountPath,
                        fset=setMountPath,
                        doc="URL path as assigned to SCRIPT_URL environ key")

    def setPathInfo(self, pathInfo=None, environ=None):
        if pathInfo:
            self._pathInfo = pathInfo
        else:
            if environ is None:
                environ = self._environ
            
            self._pathInfo = environ['PATH_INFO']
            
        if self._pathInfo != '/':
            self._pathInfo = self._pathInfo.rstrip('/')
        
    def _getPathInfo(self):
        return self._pathInfo
    
    pathInfo = property(fget=_getPathInfo,
                        fset=setPathInfo,
                        doc="URL path as assigned to PATH_INFO environ key")


    def setPath(self, path=None):
        if path:
            self._path = path
        else:
            self._path = self.mountPath.rstrip('/') + self._pathInfo
            
        if self._path != '/':
            self._path = self._path.rstrip('/')
        
    def _getPath(self):
        return self._path
    
    path = property(fget=_getPath,
                        fset=setPath,
                        doc="Full URL path minus domain name - equivalent to "
                            "self.mountPath PATH_INFO environ setting")

    def _setEnviron(self, environ):
        self._environ = environ
        
    def _getEnviron(self):
        return self._environ
    
    environ = property(fget=_getEnviron,
                       fset=_setEnviron,
                       doc="Reference to WSGI environ dict")
    
    def _setStart_response(self, start_response):
        self._start_response = start_response
        
    def _getStart_response(self):
        return self._start_response
    
    start_response = property(fget=_getStart_response,
                              fset=_setStart_response,
                              doc="Reference to WSGI start_response function")
        
        
    def redirect(self, url, start_response=None):
        """Do a HTTP 302 redirect
        
        @type start_response: callable following WSGI start_response convention
        @param start_response: WSGI start response callable
        @type url: basestring
        @param url: URL to redirect to
        @rtype: list
        @return: empty HTML body
        """
        if start_response is None:
            # self.start_response will be None if initCall decorator wasn't 
            # applied to __call__
            if self.start_response is None:
                raise NDGSecurityMiddlewareConfigError("No start_response "
                                                       "function set.")
            start_response = self.start_response
            
        start_response(NDGSecurityMiddlewareBase.getStatusMessage(302), 
                       [('Content-type', 'text/html'),
                        ('Content-length', '0'),
                        ('Location', url)])
        return []

    @staticmethod
    def parseListItem(item):
        """Utility method for parsing a space separate list of items in a 
        string.  Items may be quoted.  This method is useful for parsing items
        assigned to a parameter in a config file e.g.
        fileList: "a.txt" b.csv 'My File'
        @type item: basestring
        @param item: list of space separated items in a string.  These may be 
        quoted
        """
        return [i.strip("\"'") for i in item.split()]  

   
class NDGSecurityPathFilter(NDGSecurityMiddlewareBase):
    """Specialisation of NDG Security Middleware to enable filtering based on
    PATH_INFO
    """
    propertyDefaults = {
        'errorResponseCode': 401,
        'serverName': None,
        'pathMatchList': ['/']
    }
    propertyDefaults.update(NDGSecurityMiddlewareBase.propertyDefaults)
    
    CSV_PAT = re.compile(',\s*')
    
    # TODO: refactor to:
    # * enable reading of path list from a database or some other 
    # configuration source.
    # * enable some kind of pattern matching for paths    
    _pathMatch = lambda self: self._pathInfo in self.pathMatchList
    pathMatch = property(fget=_pathMatch,
                         doc="Check for input path match to list of paths"
                             "to which this middleware is to be applied")

    def __init__(self, *arg, **kw):
        '''See NDGSecurityMiddlewareBase for explanation of args
        @type arg: tuple
        @param arg: single element contains next middleware application in the 
        chain and app_conf dict      
        @type kw: dict        
        @param kw: prefix for app_conf parameters and local_conf dict        
        '''
        super(NDGSecurityPathFilter, self).__init__(*arg, **kw)
        
    def _getPathMatchList(self):
        return self.__pathMatchList
    
    def _setPathMatchList(self, pathList):
        '''
        @type pathList: list or tuple
        @param pathList: list of URL paths to apply this middleware 
        to. Paths are relative to the point at which this middleware is mounted
        as set in environ['PATH_INFO']
        '''
        
        if isinstance(pathList, str):
            # Try parsing a space separated list of file paths
             self.__pathMatchList=NDGSecurityPathFilter.CSV_PAT.split(pathList)
            
        elif not isinstance(pathList, (list, tuple)):
            raise TypeError('Expecting a list or tuple for "pathMatchList"')
        else:
            self.__pathMatchList = list(pathList)
            
    pathMatchList = property(fget=_getPathMatchList,
                             fset=_setPathMatchList,
                             doc='List of URL paths to which to apply SSL '
                                 'client authentication')
        
    def _getErrorResponseCode(self):
        """Error response code getter
        @rtype: int
        @return: HTTP error code set by this middleware on client cert.
        verification error
        """
        return self._errorResponseCode
            
    def _setErrorResponseCode(self, code):
        """Error response code setter
        @type code: int or basestring
        @param code: error response code set if client cert. verification
        fails"""
        if isinstance(code, int):
            self._errorResponseCode = code
        elif isinstance(code, str):
            self._errorResponseCode = int(code)
        else:
            raise TypeError('Expecting int or string type for '
                            '"errorResponseCode" attribute')
            
        if self._errorResponseCode not in http.client.responses: 
            raise ValueError("Error response code [%d] is not recognised "
                             "standard HTTP response code" % 
                             self._errorResponseCode)  
            
    errorResponseCode = property(fget=_getErrorResponseCode,
                                 fset=_setErrorResponseCode,
                                 doc="Response code raised if client "
                                     "certificate verification fails")
