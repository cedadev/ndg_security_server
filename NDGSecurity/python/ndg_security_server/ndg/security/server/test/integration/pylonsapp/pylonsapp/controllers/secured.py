import logging

from pylons import request, response, session, tmpl_context as c, url
from pylons.controllers.util import abort, redirect

from pylonsapp.lib.base import BaseController, render
from ndg.security.server.utils.pylons_ext import AuthenticationDecorators

log = logging.getLogger(__name__)
    
    
class SecuredController(BaseController):

    def index(self):
        # Return a rendered template
        return render('/secured.mako')
    
    @AuthenticationDecorators.login        
    def login(self):
        redirect('/secured/index')
      
    @AuthenticationDecorators.logout      
    def logout(self):
        log.warning('Got to logout action')
