from ndg.security.client.ssoclient.ssoclient.lib.base import *

log = logging.getLogger(__name__)

from ndg.security.common.pylons.security_util import SecuritySession
import logging
log = logging.getLogger(__name__)

import sys # include in case tracefile is set to sys.stderr 
import base64 # decode the return to address

from ndg.security.common.sessionmanager import SessionManagerClient


class LogoutController(BaseController):
    '''Provides the pylons controller for logging out and removing security
    session cookie content
    '''
  
    def index(self):
        '''Logout - remove session from Session Manager tidy up cookie'''

        log.debug("LogoutController.index ...")
        

        if 'ndgSec' not in session:
            # There's no handle to a security session
            log.error("logout called but no 'ndgSec' key in session object")
            return self._redirect()
        
        try:
            smClnt = SessionManagerClient(uri=session['ndgSec']['h'],
                    tracefile=g.ndg.security.common.sso.cfg.tracefile,
                    **g.ndg.security.common.sso.cfg.wss)       
        except Exception, e:
            log.error("logout - creating Session Manager client: %s" % e)
            return self._cleanupAndRedirect()  
        
        # Disconnect from Session Manager
        log.info('Calling Session Manager "%s" disconnect for logout...' % \
                 session['ndgSec']['h'])
        try:
            smClnt.disconnect(sessID=session['ndgSec']['sid'])
        except Exception, e:
            log.error("Error with Session Manager logout: %s" % e)
            # don't exit here - instead proceed to delete session and 
            # redirect ...

        return self._cleanupAndRedirect()


    def _cleanupAndRedirect(self):
        """Remove security session and call _redirect"""
        log.debug("LogoutController._cleanupAndRedirect...")
        
        try:
            # easy to kill our cookie
            SecuritySession.delete()
            if 'ndgCleared' in session: del session['ndgCleared']
            session.save()
            
        except Exception, e:   
            log.error("logout - clearing security session: %s" % e)

        return self._redirect()
    
    
    def _redirect(self):
        """Handle redirect back to previous page"""
        
        # Redirect URL is held in 'r' URL arg of this request
        b64encReturnTo = str(request.params.get('r', ''))

        if b64encReturnTo:
            # Decode the return to address
            try:
                b64decReturnTo = base64.urlsafe_b64decode(b64encReturnTo)
            except Exception, e:
                log.error("logout - decoding return URL: %s" % e) 
                c.xml = "Error carrying out browser redirect following logout"
                return render('ndg.security.error')
            
            # Check for 'getCredentials' - avoid in case username/password
            # contained in the URL!
            getCredentialsIdx = b64decReturnTo.rfind('/getCredentials')
            if getCredentialsIdx != -1:
                log.debug(\
                    "Reverting request URL from getCredentials to login...")
                b64decReturnTo = b64decReturnTo[:getCredentialsIdx] + '/login'
            
            # and now go back to whence we had come
            log.debug("LogoutController._redirect: redirect to %s" % \
                                                              b64decReturnTo)
            h.redirect_to(b64decReturnTo)
        else:
            log.debug("LogoutController._redirect: no redirect URL set.")
            return render('ndg.security.error')