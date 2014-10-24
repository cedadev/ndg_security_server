import logging

from ndgsecuredpylons.lib.base import *

log = logging.getLogger(__name__)

class Invoke401Controller(BaseController):

    def index(self):
        # Return a rendered template
        #   return render('/some/template.mako')
        # or, Return a response
        if 'REMOTE_USER' not in request.environ:
            abort(401)
        else:
            return 'Hello World'
