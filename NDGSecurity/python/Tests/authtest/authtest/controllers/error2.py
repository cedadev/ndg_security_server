import logging

from authtest.lib.base import *

log = logging.getLogger(__name__)
from ows_common import exceptions as OWS_E

class Error2Controller(BaseController):

    def index(self):
        # Return a rendered template
        #   return render('/some/template.mako')
        # or, Return a response
        log.debug("Calling Error2Controller.index...")
        try:
            raise OWS_E.MissingParameterValue("Error here")
        except Exception, e:
            response.headers['content-type'] = 'text/html'
            return render('exception_report', report=e.report, format='xml')
