import logging

from ssoclient.lib.base import *

log = logging.getLogger(__name__)

class Test1Controller(BaseController):

    def index(self):
        # Return a rendered template
        #   return render('/some/template.mako')
        # or, Return a response
        log.debug("Test1Controller.index...")
        c.xml = "Test page"
        return render('ndg.security.error')
