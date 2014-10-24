import logging

from authtest.lib.base import *
from pylons import Response

log = logging.getLogger(__name__)

class MytestController(BaseController):

    def hello(self):
        # Return a rendered template
        #   return render('/some/template.mako')
        # or, Return a response
        return self._result()

    def _result(self):
        return Response('Hello World')
