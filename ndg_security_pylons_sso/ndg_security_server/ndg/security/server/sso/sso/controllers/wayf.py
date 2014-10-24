import logging

from ndg.security.server.sso.sso.lib.base import *
from ndg.security.common.attributeauthority import AttributeAuthorityClient
from base64 import urlsafe_b64decode

log = logging.getLogger(__name__)


class WayfController(BaseController):
    """Where Are You From Controller - display a list of trusted sites for 
    login"""

    def index(self):
        ''' NDG equivalent to Shibboleth WAYF '''
        log.debug("WayfController.index ...")

        # Check for return to arg in query.  This is necessary only if the 
        # WAYF query originates from a different service to this one
        if 'r' in request.params:
            # Convenience alias
            state = g.ndg.security.common.sso.state
        
            state.b64encReturnToURL = str(request.params.get('r', ''))
            state.returnToURL = urlsafe_b64decode(str(state.b64encReturnToURL)) 
            log.debug("Set return to URL from 'r' query arg: r = %s"% \
                                                        state.returnToURL)

        # Trigger AuthKit handler:
        abort(401)