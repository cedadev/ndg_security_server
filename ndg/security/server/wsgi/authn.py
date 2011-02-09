"""Module containing:
 * HTTP Basic Authentication Middleware
 * middleware to enable redirection to OpenID Relying Party for login
 * logout middleware for deleting AuthKit cookie and redirecting back to 
   referrer
 
NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "13/01/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

import re
import base64
import httplib
import urllib
from paste.request import construct_url, parse_querystring
import authkit.authenticate
from authkit.authenticate.multi import MultiHandler

from ndg.security.server.wsgi import (NDGSecurityMiddlewareBase, 
                                      NDGSecurityMiddlewareError, 
                                      NDGSecurityMiddlewareConfigError) 
from ndg.security.server.wsgi.session import (SessionMiddlewareBase,
                                              SessionHandlerMiddleware)  

from ndg.security.server.wsgi.ssl import AuthKitSSLAuthnMiddleware

class AuthnException(NDGSecurityMiddlewareError):
    """Base exception for this module"""
    
    
class HTTPBasicAuthMiddlewareError(AuthnException):
    """Base exception type for HTTPBasicAuthMiddleware"""
    
    
class HTTPBasicAuthMiddlewareConfigError(NDGSecurityMiddlewareConfigError):
    """Configuration error with HTTP Basic Auth middleware"""


class HTTPBasicAuthUnauthorized(HTTPBasicAuthMiddlewareError):  
    """Raise from custom authentication interface in order to set HTTP 
    401 Unuathorized response"""
    
    
class HTTPBasicAuthMiddleware(NDGSecurityMiddlewareBase):
    '''HTTP Basic Authentication Middleware 
    '''
    AUTHN_FUNC_ENV_KEYNAME = ('ndg.security.server.wsgi.authn.'
                              'HTTPBasicAuthMiddleware.authenticate')
    AUTHN_FUNC_ENV_KEYNAME_OPTNAME = 'authnFuncEnvKeyName'       
    PARAM_PREFIX = 'http.auth.basic.'
    HTTP_HDR_FIELDNAME = 'basic'
    FIELD_SEP = ':'
    AUTHZ_ENV_KEYNAME = 'HTTP_AUTHORIZATION'
    
    RE_PATH_MATCH_LIST_OPTNAME = 'rePathMatchList'
    
    def __init__(self, app, app_conf, prefix=PARAM_PREFIX, **local_conf):
        self.__rePathMatchList = None
        self.__authnFuncEnvironKeyName = None
        
        super(HTTPBasicAuthMiddleware, self).__init__(app, app_conf, 
                                                      **local_conf)

        rePathMatchListOptName = prefix + \
                            HTTPBasicAuthMiddleware.RE_PATH_MATCH_LIST_OPTNAME
        rePathMatchListVal = app_conf.pop(rePathMatchListOptName, '')
        
        self.rePathMatchList = [re.compile(i) 
                                for i in rePathMatchListVal.split()]

        paramName = prefix + \
                    HTTPBasicAuthMiddleware.AUTHN_FUNC_ENV_KEYNAME_OPTNAME
                    
        self.authnFuncEnvironKeyName = local_conf.get(paramName,
                                HTTPBasicAuthMiddleware.AUTHN_FUNC_ENV_KEYNAME)

    def _getAuthnFuncEnvironKeyName(self):
        return self.__authnFuncEnvironKeyName

    def _setAuthnFuncEnvironKeyName(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for '
                            '"authnFuncEnvironKeyName"; got %r type' % 
                            type(value))
        self.__authnFuncEnvironKeyName = value

    authnFuncEnvironKeyName = property(fget=_getAuthnFuncEnvironKeyName, 
                                       fset=_setAuthnFuncEnvironKeyName, 
                                       doc="key name in environ for the "
                                           "custom authentication function "
                                           "used by this class")

    def _getRePathMatchList(self):
        return self.__rePathMatchList

    def _setRePathMatchList(self, value):
        if not isinstance(value, (list, tuple)):
            raise TypeError('Expecting list or tuple type for '
                            '"rePathMatchList"; got %r' % type(value))
        
        self.__rePathMatchList = value

    rePathMatchList = property(fget=_getRePathMatchList, 
                               fset=_setRePathMatchList, 
                               doc="List of regular expressions determine the "
                                   "URI paths intercepted by this middleware")

    def _pathMatch(self):
        """Apply a list of regular expression matching patterns to the contents
        of environ['PATH_INFO'], if any match, return True.  This method is
        used to determine whether to apply SSL client authentication
        """
        path = self.pathInfo
        for regEx in self.rePathMatchList:
            if regEx.match(path):
                return True
            
        return False   

    def _parseCredentials(self):
        """Extract username and password from HTTP_AUTHORIZATION environ key
        
        @rtype: tuple
        @return: username and password.  If the key is not set or the auth
        method is not basic return a two element tuple with elements both set
        to None
        """
        basicAuthHdr = self.environ.get(
                                    HTTPBasicAuthMiddleware.AUTHZ_ENV_KEYNAME)
        if basicAuthHdr is None:
            log.debug("No %r setting in environ: skipping HTTP Basic Auth",
                      HTTPBasicAuthMiddleware.AUTHZ_ENV_KEYNAME)
            return None, None
                       
        method, encodedCreds = basicAuthHdr.split(None, 1)
        if method.lower() != HTTPBasicAuthMiddleware.HTTP_HDR_FIELDNAME:
            log.debug("Auth method is %r not %r: skipping request",
                      method, HTTPBasicAuthMiddleware.HTTP_HDR_FIELDNAME)
            return None, None
            
        creds = base64.decodestring(encodedCreds)
        username, password = creds.split(HTTPBasicAuthMiddleware.FIELD_SEP, 1)
        return username, password

    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        """Authenticate based HTTP header elements as specified by the HTTP
        Basic Authentication spec."""
        log.debug("HTTPBasicAuthNMiddleware.__call__ ...")
        
        if not self._pathMatch():
            return self._app(environ, start_response)
        
        authenticate = environ.get(self.authnFuncEnvironKeyName)
        if authenticate is None:
            # HTTP 500 default is right for this error
            raise HTTPBasicAuthMiddlewareConfigError("No authentication "
                                                     "function set in environ")
            
        username, password = self._parseCredentials()
        if username is None:
            return self._setErrorResponse(code=httplib.UNAUTHORIZED)
        
        # Call authentication application
        try:
            return authenticate(environ, start_response, username, password)
        
        except HTTPBasicAuthUnauthorized, e:
            log.error(e)
            return self._setErrorResponse(code=httplib.UNAUTHORIZED)
        else:
            return self._app(environ, start_response)


# AuthKit based HTTP basic authentication plugin not currently needed but may 
# need resurrecting
from authkit.permissions import UserIn
            
class HTTPBasicAuthentication(object):
    '''Authkit based HTTP Basic Authentication.   __call__ defines a 
    validation function to fit with the pattern for the AuthKit interface
    '''
    
    def __init__(self):
        self._userIn = UserIn([])
        
    def __call__(self, environ, username, password):
        """AuthKit HTTP Basic Auth validation function - return True/False"""
        raise NotImplementedError()

import webob

class AuthenticationEnforcementFilter(object):
    """Simple filter raises HTTP 401 response code if the requested URI matches
    a fixed regular expression set in the start-up configuration.  If however,
    REMOTE_USER is set in environ, the request is passed through to the next
    middleware or terminating app
    """
    REMOTE_USER_ENVVAR_NAME = 'REMOTE_USER'
    INTERCEPT_URI_PAT_OPTNAME = 'interceptUriPat'
    DEFAULT_INTERCEPT_URI_PAT = re.compile(".*")
    RE_PAT_TYPE = type(DEFAULT_INTERCEPT_URI_PAT)
    
    __slots__ = ('_app', '__interceptUriPat')
    
    def __init__(self, app):
        """Create attributes, initialising intercept URI to match all incoming
        requests
        """
        self.__interceptUriPat = self.__class__.DEFAULT_INTERCEPT_URI_PAT
        self._app = app
        
    @property
    def interceptUriPat(self):
        return self.__interceptUriPat
    
    @interceptUriPat.setter
    def interceptUriPat(self, value):
        if isinstance(value, basestring):
            self.__interceptUriPat = re.compile(value)
            
        elif isinstance(value, self.__class__.RE_PAT_TYPE):
            self.__interceptUriPat = value
            
        else:
            raise TypeError('Expecting string or RE pattern type for "'
                            'RE_PAT_TYPE" attribute')
    
    @classmethod
    def filter_app_factory(cls, app, global_conf, **app_conf):
        filter = cls(app)
        if cls.INTERCEPT_URI_PAT_OPTNAME in app_conf:
            filter.interceptUriPat = app_conf[cls.INTERCEPT_URI_PAT_OPTNAME]
            
        return filter
    
    def __call__(self, environ, start_response):
        request = webob.Request(environ)
        if not self.interceptUriPat.match(request.url):
            return self._app(environ, start_response)
        
        if self.__class__.REMOTE_USER_ENVVAR_NAME in environ:
            return self._app(environ, start_response)
        else:
            response = webob.Response(body="401 Unauthorized", status=401)
            return response(environ, start_response)
        
                
class AuthnRedirectMiddleware(SessionMiddlewareBase):
    """Base class for Authentication HTTP redirect initiator and redirect
    response WSGI middleware

    @type RETURN2URI_ARGNAME: basestring
    @cvar RETURN2URI_ARGNAME: name of URI query argument used to pass the 
    return to URI between initiator and consumer classes"""
    RETURN2URI_ARGNAME = 'ndg.security.r'


class AuthnRedirectInitiatorMiddleware(AuthnRedirectMiddleware):
    '''Middleware to initiate a redirect to another URI if a user is not 
    authenticated i.e. security cookie is not set
    
    AuthKit.authenticate.middleware must be in place upstream of this 
    middleware.  AuthenticationMiddleware wrapper handles this.
    
    @type propertyDefaults: dict
    @cvar propertyDefaults: valid configuration property keywords    
    '''
    propertyDefaults = {
        'redirectURI': None,
    }
    propertyDefaults.update(AuthnRedirectMiddleware.propertyDefaults)
    
    TRIGGER_HTTP_STATUS_CODE = '401'
    MIDDLEWARE_ID = 'AuthnRedirectInitiatorMiddleware'

    def __init__(self, app, global_conf, **app_conf):
        '''
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        self.__redirectURI = None
        super(AuthnRedirectInitiatorMiddleware, self).__init__(app, 
                                                               global_conf, 
                                                               **app_conf)

    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        '''Invoke redirect if user is not authenticated'''
        
        log.debug("AuthnRedirectInitiatorMiddleware.__call__ ...")
        
        if self.isAuthenticated:
            # Call next app in stack
            return self._app(environ, start_response)        
        else:
            # User is not authenticated - Redirect to OpenID Relying Party URI
            # for user OpenID entry
            return self._setRedirectResponse()
   
    def _setRedirectURI(self, uri):
        if not isinstance(uri, basestring):
            raise TypeError("Redirect URI must be set to string type")   
         
        self.__redirectURI = uri
        
    def _getRedirectURI(self):
        return self.__redirectURI
    
    redirectURI = property(fget=_getRedirectURI,
                           fset=_setRedirectURI,
                           doc="URI to redirect to if user is not "
                               "authenticated")

    def _setRedirectResponse(self):
        """Construct a redirect response adding in a return to address in a
        URI query argument
        
        @rtype: basestring
        @return: redirect response
        """       
        return2URI = construct_url(self.environ)
        quotedReturn2URI = urllib.quote(return2URI, safe='')
        return2URIQueryArg = urllib.urlencode(
            {AuthnRedirectInitiatorMiddleware.RETURN2URI_ARGNAME: 
             quotedReturn2URI})

        redirectURI = self.redirectURI
        
        if '?' in redirectURI:
            if redirectURI.endswith('&'):
                redirectURI += return2URIQueryArg
            else:
                redirectURI += '&' + return2URIQueryArg
        else:
            if redirectURI.endswith('?'):
                redirectURI += return2URIQueryArg
            else:
                redirectURI += '?' + return2URIQueryArg
          
        # Call NDGSecurityMiddlewareBase.redirect utility method      
        return self.redirect(redirectURI)
        
    @classmethod
    def checker(cls, environ, status, headers):
        """Set the MultiHandler checker function for triggering this 
        middleware.  In this case, it's a HTTP 401 Unauthorized response 
        detected in the middleware chain
        """
        if status.startswith(cls.TRIGGER_HTTP_STATUS_CODE):
            log.debug("%s.checker caught status [%s]: invoking authentication "
                      "handler", cls.__name__, cls.TRIGGER_HTTP_STATUS_CODE)
            return True
        else:
            log.debug("%s.checker skipping status [%s]", cls.__name__, status)
            return False


class AuthnRedirectResponseMiddleware(AuthnRedirectMiddleware):
    """Compliment to AuthnRedirectInitiatorMiddleware 
    functioning as the opposite end of the HTTP redirect interface.  It 
    performs the following tasks:
    - Detect a redirect URI set in a URI query argument and copy it into
    a user session object. 
    - Redirect back to the redirect URI once a user is authenticated
    
    Also see,
    ndg.security.server.wsgi.openid.relyingparty.OpenIDRelyingPartyMiddleware 
    which performs a similar function.
    """    
    _sslAuthnSucceeded = lambda self: self.environ.get(
                    AuthKitSSLAuthnMiddleware.AUTHN_SUCCEEDED_ENVIRON_KEYNAME,
                    False)
        
    sslAuthnSucceeded = property(fget=_sslAuthnSucceeded,
                                 doc="Boolean indicating SSL authentication "
                                     "has succeeded in "
                                     "AuthKitSSLAuthnMiddleware upstream of "
                                     "this middleware")   
    _sslAuthnSucceeded = lambda self: self.environ.get(
                    AuthKitSSLAuthnMiddleware.AUTHN_SUCCEEDED_ENVIRON_KEYNAME,
                    False)
        
    sslAuthnSucceeded = property(fget=_sslAuthnSucceeded,
                                 doc="Boolean indicating SSL authentication "
                                     "has succeeded in "
                                     "AuthKitSSLAuthnMiddleware upstream of "
                                     "this middleware")
        
    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        session = environ[self.sessionKey]
        
        # Check for return to address in URI query args set by 
        # AuthnRedirectInitiatorMiddleware in application code stack
        if environ['REQUEST_METHOD'] == "GET":
            params = dict(parse_querystring(environ))
        else:
            params = {}
        
        # Store the return URI query argument in a beaker session
        quotedReferrer = params.get(self.__class__.RETURN2URI_ARGNAME, '')
        referrerURI = urllib.unquote(quotedReferrer)
        if referrerURI:
            session[self.__class__.RETURN2URI_ARGNAME] = referrerURI
            session.save()
            
        # Check for a return URI setting in the beaker session and if the user
        # has just been authenticated by the AuthKit SSL Client authentication
        # middleware.  If so, redirect to this URL deleting the beaker session
        # URL setting
        return2URI = session.get(self.__class__.RETURN2URI_ARGNAME)    
        if self.sslAuthnSucceeded and return2URI:
            del session[self.__class__.RETURN2URI_ARGNAME]
            session.save()
            return self.redirect(return2URI)

        return self._app(environ, start_response)


class AuthKitRedirectResponseMiddleware(AuthnRedirectResponseMiddleware):
    """Overload isAuthenticated method in parent class to set Authenticated 
    state based on presence of AuthKit 'REMOTE_USER' environ variable
    """
    _isAuthenticated = lambda self: \
        AuthnRedirectResponseMiddleware.USERNAME_ENVIRON_KEYNAME in self.environ
        
    isAuthenticated = property(fget=_isAuthenticated,
                               doc="Boolean indicating if AuthKit "
                                   "'REMOTE_USER' environment variable is set")
    
    def __init__(self, app, app_conf, **local_conf):
        super(AuthKitRedirectResponseMiddleware, self).__init__(app, app_conf,
                                                                **local_conf)
    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        return super(AuthKitRedirectResponseMiddleware, self).__call__(environ,
                                                                start_response)


class AuthenticationMiddlewareConfigError(NDGSecurityMiddlewareConfigError):
    '''Authentication Middleware Configuration error'''


class AuthenticationMiddleware(MultiHandler, NDGSecurityMiddlewareBase):
    '''Top-level class encapsulates session and authentication handlers
    in this module
    
    Handler to intercept 401 Unauthorized HTTP responses and redirect to an
    authentication URI.  This class also implements a redirect handler to
    redirect back to the referrer if logout is invoked.
    '''

    def __init__(self, app, global_conf, prefix='', **app_conf):
        '''
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        
        # Set logout URI parameter from AuthKit settings if not otherwise set
        sessionHandlerPrefix = prefix + SessionHandlerMiddleware.PARAM_PREFIX        
        app = SessionHandlerMiddleware(app, 
                                       global_conf, 
                                       prefix=sessionHandlerPrefix,
                                       **app_conf)
        
        # Remove session handler middleware specific parameters
        for k in app_conf.keys():
            if k.startswith(sessionHandlerPrefix):
                del app_conf[k]
        
        app = authkit.authenticate.middleware(app, app_conf)        
        
        MultiHandler.__init__(self, app)

        # Redirection middleware is invoked based on a check method which 
        # catches HTTP 401 responses.
        self.add_method(AuthnRedirectInitiatorMiddleware.MIDDLEWARE_ID, 
                        AuthnRedirectInitiatorMiddleware.filter_app_factory, 
                        global_conf,
                        prefix=prefix,
                        **app_conf)
        
        self.add_checker(AuthnRedirectInitiatorMiddleware.MIDDLEWARE_ID, 
                         AuthnRedirectInitiatorMiddleware.checker)
