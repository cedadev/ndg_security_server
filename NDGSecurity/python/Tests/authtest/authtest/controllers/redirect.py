import logging

from authtest.lib.base import *

log = logging.getLogger(__name__)

class RedirectController(BaseController):

    def index(self):
        # Return a rendered template
        #   return render('/some/template.mako')
        # or, Return a response
        h.redirect_to('http://localhost:5100/handle_redirect')
        return 'Hello World'
