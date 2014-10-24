import logging

from authtest.lib.base import *

log = logging.getLogger(__name__)

class HandleRedirectController(BaseController):

    def index(self):
        # Return a rendered template
        #   return render('/some/template.mako')
        # or, Return a response
        return 'Hello World'
