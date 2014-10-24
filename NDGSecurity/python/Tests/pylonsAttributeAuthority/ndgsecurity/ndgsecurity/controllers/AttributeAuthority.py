import logging

from ndgsecurity.lib.base import *

log = logging.getLogger(__name__)

class AttributeauthorityController(BaseController):

    def index(self):
        # Return a rendered template
        #   return render('/some/template.mako')
        # or, Return a response
        return 'Hello World'
