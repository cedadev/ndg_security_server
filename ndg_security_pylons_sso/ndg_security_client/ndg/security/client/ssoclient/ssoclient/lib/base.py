"""The base Controller API

Provides the BaseController class for subclassing, and other objects
utilized by Controllers.
"""
from pylons import c, cache, config, g, request, response, session
from pylons.controllers import WSGIController
from pylons.controllers.util import abort, etag_cache, redirect_to
from pylons.decorators import jsonify, validate
from pylons.i18n import _, ungettext, N_
from pylons.templating import render

import ndg.security.client.ssoclient.ssoclient.lib.helpers as h
import ndg.security.client.ssoclient.ssoclient.model as model

import urllib
from urlparse import urlsplit, urlunsplit
from base64 import urlsafe_b64encode

from ndg.security.common.pylons.security_util import setSecuritySession, \
    SSOServiceQuery, SecuritySession

import logging
log = logging.getLogger(__name__)

class BaseControllerError(Exception):
    "Error handling for BaseController"
    
class BaseController(WSGIController):

    def __before__(self):
        '''Strip query arguments from a Login Service request and redirect from
        https -> http
        
        Moved this code from __call__ because redirect_to doesn't work from
        BaaseController.__call__.  I suspect this is a problem introduced
        with change from Pylons 0.9.5 -> 0.9.6.  See:
        
        http://pylonshq.com/irclogs/%23pylons/%23pylons.2007-08-30.log.html'''
        
        log.debug("BaseController.__before__ ...")
        if 'h' in request.params:
            # 'h' corresponds to the setting of a session manager host i.e.
            # the request has come from a completed login from the login 
            # service
            log.debug("Setting security session from URL query args ...")
            
            # Copy the query arguments into security session keys
            setSecuritySession()            
            session.save()
            
            log.debug(\
                'Switch from https to http and remove security query args ...')
            returnToURL = g.ndg.security.common.sso.cfg.server + self.pathInfo

            # Reconstruct the URL removing the security related arguments
            qs = SSOServiceQuery.stripFromURI()
            if qs:
                returnToURL += "?" + qs
               
            log.debug('URL transport switched to http: "%s"' % returnToURL)
            h.redirect_to(returnToURL)
            
        elif 'logout' in request.params:
            # Request comes from a successful logout call.  Clean up any
            # security cookies in this domain
            log.debug("Removing security details following logout ...")

            returnToURL = g.ndg.security.common.sso.cfg.server + self.pathInfo
                
            # Reconstruct the URL removing the logout flag argument
            qs = SSOServiceQuery.stripFromURI('logout')
            if qs:
                returnToURL += "?" + qs
            
            # Delete security session cookie details
            SecuritySession.delete()
            
            # Redirect to cleaned up URL
            h.redirect_to(returnToURL)

        self._OpenIDHandler()
                         
                         
    def __call__(self, environ, start_response):        
        # Insert any code to be run per request here. The Routes match
        # is under environ['pylons.routes_dict'] should you want to check
        # the action or route vars here
        log.debug("BaseController.__call__: %s ..." % \
                                                environ['pylons.routes_dict'])

        self.pathInfo = urllib.quote(environ.get('PATH_INFO', '')) 

        # construct URL picking up setting of server name from config to 
        # avoid exposing absolute URL hidden behind mod_proxy see #857 
        c.requestURL = g.ndg.security.common.sso.cfg.server + \
            self.pathInfo
        qs = '&'.join(["%s=%s" % item for item in request.params.items()])
        if qs:
            c.requestURL += '?' + qs

        self._environ = environ
        
        return WSGIController.__call__(self, environ, start_response)

        
    def _OpenIDHandler(self):
        '''OpenID handling - check for user set and if so that an existing
        session doesn't already exist'''

        if 'REMOTE_USER' in request.environ and \
           SecuritySession()['u'] != request.environ['REMOTE_USER']:
        
            username = request.environ['REMOTE_USER']
                            
            # No session exists - set one.
            # TODO: OpenID integration with Session Manager WS?
            # TODO: OpenID user attribute allocation
            setSecuritySession(h=None,
                               u=username,
                               org=username,
                               roles=['OpenIDUser'],
                               sid=None)
            SecuritySession.save()

        # Switch from https to http 
        # TODO: https transport for OpenID IdP redirect back to SP
#        log.debug("Ensure switch back to http following OpenID login...")
#        returnToURL = g.ndg.security.common.sso.cfg.server + self.pathInfo
#        log.debug("returnToURL=%s" % returnToURL)
#        h.redirect_to(returnToURL)

# Include the '_' function in the public names
__all__ = [__name for __name in locals().keys() if not __name.startswith('_') \
           or __name == '_']
