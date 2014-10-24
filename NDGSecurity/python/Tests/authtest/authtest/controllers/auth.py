import logging

from authtest.lib.base import *
from pylons import Response

from authkit.authorize.pylons_adaptors import authorize
from authkit.permissions import RemoteUser, ValidAuthKitUser

log = logging.getLogger(__name__)

class AuthController(BaseController):

    def index(self):
        # Return a rendered template
        #   return render('/some/template.mako')
        # or, Return a response
        return 'Hello World'

#    def private(self):
#        if request.environ.get("REMOTE_USER"):
#            return Response("You are authenticated!")
#        else:
#            response = Response("You are not authenticated!")
#            
#            # This doesn't work - use status_code attribute instead
#            #response.status = "401 Not authenticated"
#            response.status_code = 401
#
#            return response
        
#    @authorize(UserIn(["visitor"]))
    @authorize(RemoteUser())
    def private(self):
        return Response("You are authenticated!")
            
    def signout(self):
        return Response("Successfully signed out!")
    
    def testkid(self):
        return render('signin')
