"""NDG Security OpenID Relying Party Middleware

Wrapper to AuthKit OpenID Middleware

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/01/2009"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

import httplib # to get official status code messages
import urllib # decode quoted URI in query arg
import urllib2 # SSL based whitelisting 
from urlparse import urlsplit, urlunsplit

from paste.request import parse_querystring, parse_formvars
import authkit.authenticate
from authkit.authenticate.open_id import AuthOpenIDHandler
from beaker.middleware import SessionMiddleware

# SSL based whitelisting 
from M2Crypto import SSL
from M2Crypto.m2urllib2 import build_opener, HTTPSHandler
from openid.fetchers import setDefaultFetcher, Urllib2Fetcher

from ndg.security.common.utils.classfactory import instantiateClass
from ndg.security.server.wsgi import NDGSecurityMiddlewareBase
from ndg.security.server.wsgi.authn import AuthnRedirectMiddleware
from ndg.security.server.wsgi.openid.relyingparty.validation import (
                                                        SSLIdPValidationDriver)


class OpenIDRelyingPartyMiddlewareError(Exception):
    """OpenID Relying Party WSGI Middleware Error"""


class OpenIDRelyingPartyConfigError(OpenIDRelyingPartyMiddlewareError):
    """OpenID Relying Party Configuration Error"""
  

class OpenIDRelyingPartyMiddleware(NDGSecurityMiddlewareBase):
    '''OpenID Relying Party middleware which wraps the AuthKit implementation.
    This middleware is to be hosted in it's own security middleware stack.
    WSGI middleware applications to be protected can be hosted in a separate
    stack.  The AuthnRedirectMiddleware filter can respond to a HTTP 
    401 response from this stack and redirect to this middleware to initiate
    OpenID based sign in.  AuthnRedirectMiddleware passes a query
    argument in its request containing the URI return address for this 
    middleware to return to following OpenID sign in.
    '''
    OPENID_RP_PREFIX = 'openid.relyingparty.'
    IDP_WHITELIST_CONFIG_FILEPATH_OPTNAME = 'idpWhitelistConfigFilePath'
    SIGNIN_INTERFACE_MIDDLEWARE_CLASS_OPTNAME = 'signinInterfaceMiddlewareClass'
    SIGNIN_INTERFACE_PREFIX = 'signinInterface.'
    
    AUTHKIT_COOKIE_SIGNOUTPATH_OPTNAME = 'authkit.cookie.signoutpath'
    AUTHKIT_OPENID_TMPL_OPTNAME_PREFIX = 'authkit.openid.template.'
    AUTHKIT_OPENID_TMPL_OBJ_OPTNAME = AUTHKIT_OPENID_TMPL_OPTNAME_PREFIX + 'obj'
    AUTHKIT_OPENID_TMPL_STRING_OPTNAME = AUTHKIT_OPENID_TMPL_OPTNAME_PREFIX + \
        'string'
    AUTHKIT_OPENID_TMPL_FILE_OPTNAME = AUTHKIT_OPENID_TMPL_OPTNAME_PREFIX + \
        'file'
    
    sslPropertyDefaults = {
        IDP_WHITELIST_CONFIG_FILEPATH_OPTNAME: None
    }
    propertyDefaults = {
        SIGNIN_INTERFACE_MIDDLEWARE_CLASS_OPTNAME: None,
        'baseURL': ''
    }
    propertyDefaults.update(sslPropertyDefaults)
    propertyDefaults.update(NDGSecurityMiddlewareBase.propertyDefaults)
    
    def __init__(self, app, global_conf, prefix=OPENID_RP_PREFIX, 
                 **app_conf):
        """Add AuthKit and Beaker middleware dependencies to WSGI stack and 
        set-up SSL Peer Certificate Authentication of OpenID Provider set by
        the user
        
        @type app: callable following WSGI interface signature
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy application global configuration - 
        must follow format of propertyDefaults class variable
        @type prefix: basestring
        @param prefix: prefix for OpenID Relying Party configuration items
        @type app_conf: dict
        @param app_conf: application specific configuration - must follow 
        format of propertyDefaults class variable"""    

        # Whitelisting of IDPs.  If no config file is set, no validation is
        # executed
        cls = OpenIDRelyingPartyMiddleware
        
        idpWhitelistConfigFilePath = app_conf.get(
                            prefix + cls.IDP_WHITELIST_CONFIG_FILEPATH_OPTNAME)
        if idpWhitelistConfigFilePath is not None:
            self._initIdPValidation(idpWhitelistConfigFilePath)
        
        # Check for sign in template settings
        if prefix+cls.SIGNIN_INTERFACE_MIDDLEWARE_CLASS_OPTNAME in app_conf:
            if (cls.AUTHKIT_OPENID_TMPL_OBJ_OPTNAME in app_conf or 
                cls.AUTHKIT_OPENID_TMPL_STRING_OPTNAME in app_conf or 
                cls.AUTHKIT_OPENID_TMPL_FILE_OPTNAME in app_conf):
                
                log.warning("OpenID Relying Party %r setting overrides "
                            "'%s*' AuthKit settings",
                            cls.AUTHKIT_OPENID_TMPL_OPTNAME_PREFIX,
                            cls.SIGNIN_INTERFACE_MIDDLEWARE_CLASS_OPTNAME)
                
            signinInterfacePrefix = prefix+cls.SIGNIN_INTERFACE_PREFIX
            
            className = app_conf[
                        prefix + cls.SIGNIN_INTERFACE_MIDDLEWARE_CLASS_OPTNAME]
            classProperties = {'prefix': signinInterfacePrefix}
            classProperties.update(app_conf)
            
            app = instantiateClass(className, 
                                   None,  
                                   objectType=SigninInterface, 
                                   classArgs=(app, global_conf),
                                   classProperties=classProperties)
            
            # Delete sign in interface middleware settings
            for conf in app_conf, global_conf or {}:
                for k in conf.keys():
                    if k.startswith(signinInterfacePrefix):
                        del conf[k]
        
            app_conf[
                    cls.AUTHKIT_OPENID_TMPL_STRING_OPTNAME] = app.makeTemplate()
                
        self.signoutPath = app_conf.get(cls.AUTHKIT_COOKIE_SIGNOUTPATH_OPTNAME)

        # Set AuthKit customisations
        app_conf['authkit.openid.force_redirect'] = True
        app_conf['authkit.openid.openid_form_fieldname'] = 'openid-identifier'
         
        app = authkit.authenticate.middleware(app, app_conf)
        _app = app
        while True:
            if isinstance(_app, AuthOpenIDHandler):
                authOpenIDHandler = _app
                self._authKitVerifyPath = authOpenIDHandler.path_verify
                self._authKitProcessPath = authOpenIDHandler.path_process
                break
            
            elif hasattr(_app, 'app'):
                _app = _app.app
            else:
                break
         
        if not hasattr(self, '_authKitVerifyPath'):
            raise OpenIDRelyingPartyConfigError("Error locating the AuthKit "
                                                "AuthOpenIDHandler in the "
                                                "WSGI stack")
        
        # Put this check in here after sessionKey has been set by the 
        # super class __init__ above
        self.sessionKey = authOpenIDHandler.session_middleware
            
        
        # Check for return to argument in query key value pairs
        self._return2URIKey = AuthnRedirectMiddleware.RETURN2URI_ARGNAME + '='
    
        super(OpenIDRelyingPartyMiddleware, self).__init__(app, 
                                                           global_conf, 
                                                           prefix=prefix, 
                                                           **app_conf)
    
    @NDGSecurityMiddlewareBase.initCall     
    def __call__(self, environ, start_response):
        '''
        - Alter start_response to override the status code and force to 401.
        This will enable non-browser based client code to bypass the OpenID 
        interface
        - Manage AuthKit verify and process actions setting the referrer URI
        to manage redirects correctly
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        '''
        # Skip Relying Party interface set-up if user has been authenticated
        # by other middleware
        if 'REMOTE_USER' in environ:
            log.debug("Found REMOTE_USER=%s in environ, AuthKit "
                      "based authentication has taken place in other "
                      "middleware, skipping OpenID Relying Party interface" %
                      environ['REMOTE_USER'])
            return self._app(environ, start_response)

        session = environ.get(self.sessionKey)
        if session is None:
            raise OpenIDRelyingPartyConfigError('No beaker session key "%s" '
                                                'found in environ' % 
                                                self.sessionKey)
        
        # Check for return to address in URI query args set by 
        # AuthnRedirectMiddleware in application code stack
        params = dict(parse_querystring(environ))
        quotedReferrer = params.get(AuthnRedirectMiddleware.RETURN2URI_ARGNAME,
                                    '')
        
        referrer = urllib.unquote(quotedReferrer)
        referrerPathInfo = urlsplit(referrer)[2]

        if (referrer and 
            not referrerPathInfo.endswith(self._authKitVerifyPath) and 
            not referrerPathInfo.endswith(self._authKitProcessPath)):
            
            # An app has redirected to the Relying Party interface setting the
            # special ndg.security.r query argument.  Subvert 
            # authkit.authenticate.open_id.AuthOpenIDHandler.process
            # reassigning it's session 'referer' key to the URI specified in
            # ndg.security.r in the request URI
            session['referer'] = referrer
            session.save()
            
        if self._return2URIKey in environ.get('HTTP_REFERER', ''):
            # Remove return to arg to avoid interfering with AuthKit OpenID
            # processing
            splitURI = urlsplit(environ['HTTP_REFERER'])
            query = splitURI[3]
            
            filteredQuery = '&'.join([arg for arg in query.split('&')
                                if not arg.startswith(self._return2URIKey)])
            
            environ['HTTP_REFERER'] = urlunsplit(splitURI[:3] + \
                                                 (filteredQuery,) + \
                                                 splitURI[4:])
                            
        # See _start_response doc for an explanation...
        if environ['PATH_INFO'] == self._authKitVerifyPath: 
            def _start_response(status, header, exc_info=None):
                '''Make OpenID Relying Party OpenID prompt page return a 401
                status to signal to non-browser based clients that 
                authentication is required.  Requests are filtered on content 
                type so that static content such as graphics and style sheets 
                associated with the page are let through unaltered
                
                @type status: str
                @param status: HTTP status code and status message
                @type header: list
                @param header: list of field, value tuple HTTP header content
                @type exc_info: Exception
                @param exc_info: exception info
                '''
                _status = status
                
                # Ignore redirect requests - this is set following a form POST
                # of the OpenID URL to initiate sign-in
                if not _status.startswith('30'):
                    for name, val in header:
                        if (name.lower() == 'content-type' and 
                            val.startswith('text/html')):
                            _status = self.getStatusMessage(401)
                            break
                    
                return start_response(_status, header, exc_info)
        else:
            _start_response = start_response

        return self._app(environ, _start_response)

    def _initIdPValidation(self, idpWhitelistConfigFilePath):
        """Initialise M2Crypto based urllib2 HTTPS handler to enable SSL 
        authentication of OpenID Providers"""
        log.info("Setting parameters for SSL Authentication of OpenID "
                 "Provider ...")
        
        idPValidationDriver = SSLIdPValidationDriver(
                                idpConfigFilePath=idpWhitelistConfigFilePath)
            
        # Force Python OpenID library to use Urllib2 fetcher instead of the 
        # Curl based one otherwise the M2Crypto SSL handler will be ignored.
        setDefaultFetcher(Urllib2Fetcher())
        
        log.debug("Setting the M2Crypto SSL handler ...")
        
        opener = urllib2.OpenerDirector()            
        opener.add_handler(FlagHttpsOnlyHandler())
        opener.add_handler(HTTPSHandler(idPValidationDriver.ctx))
        
        urllib2.install_opener(opener)

    
class FlagHttpsOnlyHandler(urllib2.AbstractHTTPHandler):
    '''Raise an exception for any other protocol than https'''
    def unknown_open(self, req):
        """Signal to caller that default handler is not supported"""
        raise urllib2.URLError("Only HTTPS based OpenID Providers "
                               "are supported")


class SigninInterfaceError(Exception):
    """Base class for SigninInterface exceptions
    
    A standard message is raised set by the msg class variable but the actual
    exception details are logged to the error log.  The use of a standard 
    message enables callers to use its content for user error messages.
    
    @type msg: basestring
    @cvar msg: standard message to be raised for this exception"""
    userMsg = ("An internal error occurred with the page layout,  Please "
               "contact your system administrator")
    errorMsg = "SigninInterface error"
    
    def __init__(self, *arg, **kw):
        if len(arg) > 0:
            msg = arg[0]
        else:
            msg = self.__class__.errorMsg
            
        log.error(msg)
        Exception.__init__(self, msg, **kw)
        
        
class SigninInterfaceInitError(SigninInterfaceError):
    """Error with initialisation of SigninInterface.  Raise from __init__"""
    errorMsg = "SigninInterface initialisation error"
    
    
class SigninInterfaceConfigError(SigninInterfaceError):
    """Error with configuration settings.  Raise from __init__"""
    errorMsg = "SigninInterface configuration error"    


class SigninInterface(NDGSecurityMiddlewareBase):
    """Base class for sign in rendering.  This is implemented as WSGI 
    middleware to enable additional middleware to be added into the call
    stack e.g. StaticFileParser to enable rendering of graphics and other
    static content in the Sign In page"""
    
    def getTemplateFunc(self):
        """Return template function for AuthKit to render OpenID Relying
        Party Sign in page"""
        raise NotImplementedError()
    
    def __call__(self, environ, start_response):
        return self._app(self, environ, start_response)

