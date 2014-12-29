"""WSGI middleware implementing HTTP Basic Auth to support Online CA service

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "21/05/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)
import re
import httplib
import base64
    
from paste.httpexceptions import HTTPException, HTTPUnauthorized


class HttpBasicAuthMiddlewareError(Exception):
    """Base exception type for HttpBasicAuthMiddleware"""
    
    
class HttpBasicAuthMiddlewareConfigError(HttpBasicAuthMiddlewareError):
    """Configuration error with HTTP Basic Auth middleware"""


class HttpBasicAuthResponseException(HttpBasicAuthMiddlewareError):
    """Exception class for use by the authentication function callback to
    signal HTTP codes and messages back to HttpBasicAuthMiddleware.  The code 
    can conceivably a non-error HTTP code such as 200
    """
    def __init__(self, *arg, **kw):
        """Extend Exception type to accommodate an extra HTTP response code
        argument
        """
        self.response = arg[0]
        if len(arg) == 2:
            argList = list(arg)
            self.code = argList.pop()
            arg = tuple(argList)
        else:
            self.code = httplib.UNAUTHORIZED
                
        HttpBasicAuthMiddlewareError.__init__(self, *arg, **kw)
    
    
class HttpBasicAuthMiddleware(object):
    '''HTTP Basic Authentication Middleware 

    @cvar AUTHN_FUNC_ENV_KEYNAME: key name for referencing Authentication
    callback function in environ.  Upstream middleware must set this.
    @type AUTHN_FUNC_ENV_KEYNAME: string
    @cvar AUTHN_FUNC_ENV_KEYNAME_OPTNAME: in file option name for setting the
    Authentication callback environ key
    @type AUTHN_FUNC_ENV_KEYNAME_OPTNAME: string
    @cvar REALM_OPTNAME: ini file option name for setting the HTTP Basic Auth
    authentication realm
    @type REALM_OPTNAME: string
    @cvar PARAM_PREFIX: prefix for ini file options
    @type PARAM_PREFIX: string
    @cvar AUTHENTICATE_HDR_FIELDNAME: HTTP header field name 'WWW-Authenticate'
    @type AUTHENTICATE_HDR_FIELDNAME: string
    @cvar AUTHENTICATE_HDR_FIELDNAME_LOWER: lowercase version of 
    AUTHENTICATE_HDR_FIELDNAME class variable included for convenience with
    string matching 
    @type AUTHENTICATE_HDR_FIELDNAME_LOWER: string
    @cvar AUTHN_SCHEME_HDR_FIELDNAME: HTTP Authentication scheme identifier
    @type AUTHN_SCHEME_HDR_FIELDNAME: string
    @cvar FIELD_SEP: field separator for username/password header string
    @type FIELD_SEP: string
    @cvar AUTHZ_ENV_KEYNAME: WSGI environ key name for HTTP Basic Auth header
    content
    @type AUTHZ_ENV_KEYNAME: string
    @cvar AUTHN_HDR_FORMAT: HTTP Basic Auth format string following RFC2617
    @type AUTHN_HDR_FORMAT: string
    
    @ivar __re_path_match_list: list of regular expression patterns used to match
    incoming requests and enforce HTTP Basic Auth against
    @type __re_path_match_list: list
    @ivar __authn_func_environ_keyname: __authn_func_environ_keyname
    @type __authn_func_environ_keyname: string
    @ivar __realm: HTTP Basic Auth authentication realm
    @type __realm: string
    @ivar __app: next WSGI app/middleware in call chain
    @type __app: function
    '''
    AUTHN_FUNC_ENV_KEYNAME = (
    'myproxy.server.wsgi.httpbasicauth.HttpBasicAuthMiddleware.authenticate')
    
    # Config file option names
    AUTHN_FUNC_ENV_KEYNAME_OPTNAME = 'authnFuncEnvKeyName'       
    RE_PATH_MATCH_LIST_OPTNAME = 're_path_match_list'
    REALM_OPTNAME = 'realm'
    
    PARAM_PREFIX = 'http.auth.basic.'
    
    # HTTP header request and response field parameters
    AUTHENTICATE_HDR_FIELDNAME = 'WWW-Authenticate'
    
    # For testing header content in start_response_wrapper
    AUTHENTICATE_HDR_FIELDNAME_LOWER = AUTHENTICATE_HDR_FIELDNAME.lower()
    
    AUTHN_SCHEME_HDR_FIELDNAME = 'Basic'
    AUTHN_SCHEME_HDR_FIELDNAME_LOWER = AUTHN_SCHEME_HDR_FIELDNAME.lower()
    
    FIELD_SEP = ':'
    AUTHZ_ENV_KEYNAME = 'HTTP_AUTHORIZATION'
    
    AUTHN_HDR_FORMAT = '%s ' + REALM_OPTNAME + '="%s"'
    
    __slots__ = (
        '__re_path_match_list', 
        '__authn_func_environ_keyname', 
        'authentication_callback',
        '__realm',
        '__app'
    )
    
    def __init__(self, app):
        """Create instance variables
        @param app: next middleware/app in WSGI stack
        @type app: function
        """
        self.__re_path_match_list = None
        self.__authn_func_environ_keyname = None

        # There are two options: pass an authentication function via upstream 
        # middleware and set in environ keyed with authn_func_environ_keyname
        # or simply set a function via against this variable.  If this is 
        # variable is None, __call__ method will check for
        # environ[<authn_func_environ_keyname>] instead
        self.authentication_callback = None
        
        self.__realm = None
        self.__app = app

    @classmethod
    def filter_app_factory(cls, app, global_conf, prefix=PARAM_PREFIX, 
                           **local_conf):
        """Function following Paste filter app factory signature
        
        @type app: callable following WSGI interface
        @param app: next middleware/application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type local_conf: dict        
        @param local_conf: PasteDeploy application specific configuration 
        dictionary
        @rtype: myproxy.server.wsgi.httpbasicauth.HttpBasicAuthMiddleware
        @return: an instance of this middleware
        """
        httpBasicAuthFilter = cls(app)
        httpBasicAuthFilter.parse_config(prefix=prefix, **local_conf)
        
        return httpBasicAuthFilter
        
    def parse_config(self, prefix='', **app_conf):
        """Parse dictionary of configuration items updating the relevant 
        attributes of this instance
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        re_path_match_listOptName = prefix + \
                            HttpBasicAuthMiddleware.RE_PATH_MATCH_LIST_OPTNAME
        re_path_match_listVal = app_conf.pop(re_path_match_listOptName, '')
        
        self.re_path_match_list = re_path_match_listVal.split()

        paramName = prefix + \
                    HttpBasicAuthMiddleware.AUTHN_FUNC_ENV_KEYNAME_OPTNAME
                    
        self.authn_func_environ_keyname = app_conf.get(paramName,
                                HttpBasicAuthMiddleware.AUTHN_FUNC_ENV_KEYNAME)

    @property
    def authn_func_environ_keyname(self):
        return self.__authn_func_environ_keyname

    @authn_func_environ_keyname.setter
    def authn_func_environ_keyname(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for '
                            '"authn_func_environ_keyname"; got %r type' % 
                            type(value))
            
        self.__authn_func_environ_keyname = value

    @property
    def re_path_match_list(self):
        return self.__re_path_match_list[:]

    @re_path_match_list.setter
    def re_path_match_list(self, value):
        self.__re_path_match_list = []
        for re_path in value:
            self.__re_path_match_list.append(re.compile(re_path))

    @property
    def realm(self):
        """Get realm
        
        @rtype: basestring
        @return: HTTP Authentication realm to set in responses
        """
        return self.__realm

    @realm.setter
    def realm(self, value):
        """Set realm
        
        @type value: basestring
        @param value: HTTP Authentication realm to set in responses
        """
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for '
                            '"realm"; got %r' % type(value))
        
        self.__realm = value

    def _path_match(self, environ):
        """Apply a list of regular expression matching patterns to the contents
        of environ['PATH_INFO'], if any match, return True.  This method is
        used to determine whether to apply SSL client authentication
        
        @param environ: WSGI environment variables dictionary
        @type environ: dict
        @return: True if request path matches the regular expression list set,
        False otherwise
        @rtype: bool 
        """
        path = environ['PATH_INFO']
        for reg_ex in self.re_path_match_list:
            if reg_ex.match(path):
                return True
            
        return False   

    @classmethod
    def parse_credentials(cls, environ):
        """Extract username and password from HTTP_AUTHORIZATION environ key
        
        @param environ: WSGI environ dict
        @type environ: dict
        
        @rtype: tuple
        @return: username and password.  If the key is not set or the auth
        method is not basic return a two element tuple with elements both set
        to None
        """
        basic_auth_hdr = environ.get(cls.AUTHZ_ENV_KEYNAME)
        if basic_auth_hdr is None:
            log.debug("No %r setting in environ: skipping HTTP Basic Auth",
                      HttpBasicAuthMiddleware.AUTHZ_ENV_KEYNAME)
            return None, None
                       
        method, encoded_creds = basic_auth_hdr.split(None, 1)
        if (method.lower() != cls.AUTHN_SCHEME_HDR_FIELDNAME_LOWER):
            log.debug("Auth method is %r not %r: skipping request",
                      method, 
                      cls.AUTHN_SCHEME_HDR_FIELDNAME)
            return None, None
            
        creds = base64.decodestring(encoded_creds)
        username, password = creds.rsplit(cls.FIELD_SEP, 1)
        return username, password

    def __call__(self, environ, start_response):
        """Authenticate based HTTP header elements as specified by the HTTP
        Basic Authentication spec.
        
        @param environ: WSGI environ 
        @type environ: dict-like type
        @param start_response: WSGI start response function
        @type start_response: function
        @return: response
        @rtype: iterable
        @raise HttpBasicAuthMiddlewareConfigError: no authentication callback
        found in environ
        """
        log.debug("HttpBasicAuthNMiddleware.__call__ ...")
        
        if not self._path_match(environ):
            return self.__app(environ, start_response)
        
        # Pick up authentication callback from local variable or special key
        # in environ set by upstream middleware
        if self.authentication_callback is None:
            authenticate_func = environ.get(self.authn_func_environ_keyname)
        else:
            authenticate_func = self.authentication_callback
             
        if authenticate_func is None:
            # HTTP 500 default is right for this error
            raise HttpBasicAuthMiddlewareConfigError("No authentication "
                                                     "function set in environ")
                    
        def start_response_wrapper(status, headers, exec_info=None): 
            """Ensure Authentication realm is included with 401 responses"""
            status_code = int(status.split()[0])
            if status_code == httplib.UNAUTHORIZED:
                authn_realm_hdrFound = False
                for name, val in headers:
                    if (name.lower() == 
                            self.__class__.AUTHENTICATE_HDR_FIELDNAME_LOWER):
                        authn_realm_hdrFound = True
                        break
                     
                if not authn_realm_hdrFound:
                    # Nb. realm requires double quotes according to RFC
                    authn_realm_hdr = (
                        self.__class__.AUTHENTICATE_HDR_FIELDNAME,
                        self.__class__.AUTHN_HDR_FORMAT % (
                        self.__class__.AUTHN_SCHEME_HDR_FIELDNAME,
                        self.realm)
                    )
                    headers.append(authn_realm_hdr)
                
            return start_response(status, headers)
        
        username, password = self.parse_credentials(environ)
        
        # Call authentication middleware/application.  
        try:
            response = authenticate_func(environ, start_response_wrapper, 
                                         username, password)
        except HTTPUnauthorized:
            if username is None:
                # If no username is set, set the HTTP Basic Auth challenge 
                # returning an auth realm
                log.error('No username set in HTTP Authorization header')
                http_unauthorized = HTTPUnauthorized("No username set")
                
                return http_unauthorized(environ, start_response_wrapper)
            else:
                # Credentials were set it's just they were invalid
                raise

        except HTTPException, e:
            return e(environ, start_response)
        
        # If no response is set, the next middleware is called in the chain
        if response is not None:
            return response
        else:
            return self.__app(environ, start_response_wrapper)

