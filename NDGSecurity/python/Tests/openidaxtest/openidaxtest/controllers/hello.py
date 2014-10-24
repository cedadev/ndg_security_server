import logging

from pylons import request, response, session, tmpl_context as c
from pylons.controllers.util import abort, redirect_to

from openidaxtest.lib.base import BaseController, render

log = logging.getLogger(__name__)

from authkit.authorize import NotAuthorizedError
from authkit.permissions import RequestPermission
from authkit.authorize.pylons_adaptors import authorize

class OpenIdAxPermission(RequestPermission):
    def __init__(self):
        # custom settings here...
        self.authzEmail = 'somebody@somewhere'
        
    def check(self, app, environ, start_response): 
        remoteUserData = environ.get('REMOTE_USER_DATA')
        #remoteUserData = "{'ax':{'value.email.1':'somebody@somewhere'}}"
        if remoteUserData:
            # Cookie *MUST* be signed otherwise this is unsafe
            remoteUserDataDict = eval(remoteUserData)
            if (isinstance(remoteUserDataDict, dict) and 
                'ax' in remoteUserDataDict):
                axDict = remoteUserDataDict['ax']
                
                if axDict.get('value.email.1') != self.authzEmail:
                    raise NotAuthorizedError("Access denied ...")
            
        return app(environ, start_response)
    

class HelloController(BaseController):

    @authorize(OpenIdAxPermission())
    def index(self):
        # Return a rendered template
        #return render('/hello.mako')
        # or, return a response
        return 'Hello World'

    def signin(self):
        if not request.environ.get('REMOTE_USER'):
            # This triggers the AuthKit middleware into displaying the sign-in form
            abort(401)
        else:
            return render('signedin.html')

    def signout(self):
        # The actual removal of the AuthKit cookie occurs when the response passes
        # through the AuthKit middleware, we simply need to display a page
        # confirming the user is signed out
        return render('signedout.html')
