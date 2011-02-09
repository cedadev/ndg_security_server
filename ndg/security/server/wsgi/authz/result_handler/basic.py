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

from httplib import UNAUTHORIZED, FORBIDDEN

from ndg.security.server.wsgi import NDGSecurityMiddlewareBase
from ndg.security.server.wsgi.authz.result_handler import (
                                                PEPResultHandlerMiddlewareBase)


class PEPResultHandlerMiddleware(PEPResultHandlerMiddlewareBase):
    """This middleware is invoked if access is denied to a given resource.  It
    is incorporated into the call stack by passing it in to a MultiHandler 
    instance.  The MultiHandler is configured in the AuthorizationMiddlewareBase 
    class - see ndg.security.server.wsgi.authz.  The MultiHandler is passed a 
    checker method which determines whether to allow access, or call this 
    interface.   The checker is implemented in the PEPFilter.  See 
    ndg.security.server.wsgi.authz
    
    PEPResultHandlerMiddlewareBase (SessionMiddlewareBase) base class defines 
    user session key and isAuthenticated property
    """
    
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
        super(PEPResultHandlerMiddleware, self).__init__(app,
                                                         global_conf,
                                                         prefix=prefix,
                                                         **app_conf)
               
    @PEPResultHandlerMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        
        log.debug("PEPResultHandlerMiddleware.__call__ ...")
        
        session = self.environ.get(self.sessionKey)
        if not self.isAuthenticated:
            # This check is included as a precaution: this condition should be
            # caught be the AuthNRedirectHandlerMiddleware or PEPFilter
            log.warning("PEPResultHandlerMiddleware: user is not "
                        "authenticated - setting HTTP 401 response")
            return self._setErrorResponse(code=UNAUTHORIZED)
        else:
            # Get response message from PDP recorded by PEP
            pepCtx = session.get(
                    PEPResultHandlerMiddleware.PEPCTX_SESSION_KEYNAME, {})
            pdpResponse = pepCtx.get(
                    PEPResultHandlerMiddleware.PEPCTX_RESPONSE_SESSION_KEYNAME)
            msg = getattr(pdpResponse, 'message', '') or ''
                
            response = ("Access is forbidden for this resource:%s"
                        "Please check with your site administrator that you "
                        "have the required access privileges." % 
                        msg.join(('\n\n',)*2))

            return self._setErrorResponse(code=FORBIDDEN, msg=response)