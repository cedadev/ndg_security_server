"""WSGI Policy Enforcement Point basic result handler - returns a HTML access
denied message to the client if the client is not authorized.

Functionality in this module moved from original authz package location

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "05/01/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
__license__ = "BSD - see LICENSE file in top-level directory"
import logging
log = logging.getLogger(__name__)

from httplib import UNAUTHORIZED

from ndg.security.server.wsgi.authz.result_handler import (
    PEPResultHandlerMiddlewareBase, PEPResultHandlerMiddlewareConfigError)


class HTTPRedirectPEPResultHandlerMiddleware(PEPResultHandlerMiddlewareBase):
    """This middleware is invoked if access is denied to a given resource.  It
    sets a redirect response to redirect the user's browser to a configured
    URL.  This could be to provide a custom access denied message or interface.
    
    This middleware is incorporated into the call stack by passing it in to a 
    MultiHandler instance.  The MultiHandler is configured in the 
    AuthorizationMiddlewareBase class - see ndg.security.server.wsgi.authz.  The
    MultiHandler is passed a checker method which determines whether to allow 
    access, or call this interface.   The checker is implemented in the 
    PEPFilter.  See ndg.security.server.wsgi.authz
    """
    REDIRECT_URI_PARAMNAME = 'redirectURI'
    
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
        super(PEPResultHandlerMiddlewareBase, self).__init__(app, {})
        
        redirectURI = app_conf.get(prefix + \
                HTTPRedirectPEPResultHandlerMiddleware.REDIRECT_URI_PARAMNAME)
        if redirectURI is None:
            raise PEPResultHandlerMiddlewareConfigError("Missing required "
                "parameter %r" % prefix + \
                HTTPRedirectPEPResultHandlerMiddleware.REDIRECT_URI_PARAMNAME)
    
        self.redirectURI = redirectURI
                  
    @PEPResultHandlerMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        
        log.debug("PEPResultHandlerMiddleware.__call__ ...")
        cls = HTTPRedirectPEPResultHandlerMiddleware
        
        session = self.environ.get(self.sessionKey)
        if not self.isAuthenticated:
            # This check is included as a precaution: this condition should be
            # caught be the AuthNRedirectHandlerMiddleware or PEPFilter
            log.warning("PEPResultHandlerMiddleware: user is not "
                        "authenticated - setting HTTP 401 response")
            return self._setErrorResponse(code=UNAUTHORIZED)
        else:
            # Get response message from PDP recorded by PEP
            pepCtx = session.get(cls.PEPCTX_SESSION_KEYNAME, {})
            pdpResponse = pepCtx.get(cls.PEPCTX_RESPONSE_SESSION_KEYNAME)
            msg = getattr(pdpResponse, 'message', '') or ''
            log.info("PEP returned access denied message: %r; redirecting to "
                     "configured redirectURI=%r", msg, self.redirectURI)

            return self.redirect()
        
    def redirect(self):
        """Override NDGSecurityMiddlewareBase.redirect to pass uri attribute
        explicitly
        
        @param uri: custom access denied response URI to redirect to
        @type uri: basestring
        @return: empty response - redirect is set in header
        @rtype: list
        """
        return super(HTTPRedirectPEPResultHandlerMiddleware, self).redirect(
                                                            self.redirectURI)
        
    def _setRedirectURI(self, uri):
        if not isinstance(uri, basestring):
            raise TypeError("Redirect URI must be set to string type")   
         
        self.__redirectURI = uri
        
    def _getRedirectURI(self):
        return self.__redirectURI
    
    redirectURI = property(fget=_getRedirectURI,
                           fset=_setRedirectURI,
                           doc="URI to redirect to if access is denied")