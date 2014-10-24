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

import ndg.security.server.sso.sso.lib.helpers as h
import ndg.security.server.sso.sso.model as model
from ndg.security.common.pylons.security_util import setSecuritySession, \
    session

import urllib
import logging
log = logging.getLogger(__name__)

class BaseControllerError(Exception):
    "Error handling for BaseController"
    
class BaseController(WSGIController):
    def __call__(self, environ, start_response):        
        # Insert any code to be run per request here. The Routes match
        # is under environ['pylons.routes_dict'] should you want to check
        # the action or route vars here
        #log.debug("BaseController.__call__ ...")

        # construct URL picking up setting of server name from config to 
        # avoid exposing absolute URL hidden behind mod_proxy see #857 
        # Also, avoid returning to getCredentials and potentially exposing
        # username/pass-phrase on URL.
        pathInfo = urllib.quote(environ.get('PATH_INFO', '')) 
        if 'getCredentials' in pathInfo:
            log.debug("Reverting request URL from getCredentials to login...")
            c.requestURL = g.ndg.security.server.sso.cfg.server+'/login'       
        else:
            c.requestURL = g.ndg.security.server.sso.cfg.server+pathInfo
            query='&'.join(["%s=%s" % item for item in request.params.items()])
            if query:
                c.requestURL += '?' + query

        self._openidHandler(environ)
        
        return WSGIController.__call__(self, environ, start_response)
    
    def _openidHandler(self, environ):
        if 'REMOTE_USER' not in environ:
            return
        
        if 'ndgSec' in session and \
           environ['REMOTE_USER'] == session['ndgSec']['u']:
            return
        
        setSecuritySession(h=None,
                           u=environ['REMOTE_USER'],
                           org=environ['REMOTE_USER'],
                           roles=['OpenIDUser'],
                           sid=None)
        session.save()
      
# Include the '_' function in the public names
__all__ = [__name for __name in locals().keys() if not __name.startswith('_') \
           or __name == '_']
