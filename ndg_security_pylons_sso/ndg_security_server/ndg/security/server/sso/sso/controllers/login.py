"""Single Sign On Service Login Controller

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "10/12/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import logging
log = logging.getLogger(__name__)

# _redirect requires this to parse the server name
from urlparse import urlsplit


from ndg.security.server.sso.sso.lib.base import *
from ndg.security.common.pylons.security_util import setSecuritySession, \
    SecuritySession, SSOServiceQuery
from ndg.security.server.wsgi.utils.attributeauthorityclient import \
    WSGIAttributeAuthorityClient
from ndg.security.server.wsgi.utils.sessionmanagerclient import \
    WSGISessionManagerClient, SessionExpired, AttributeRequestDenied
from ndg.security.common.m2CryptoSSLUtility import HTTPSConnection, \
    HostCheck, InvalidCertSignature, InvalidCertDN

from base64 import urlsafe_b64decode, urlsafe_b64decode

class LoginController(BaseController):  
    '''Handle NDG Login and redirect backing to requesting URL if set'''
          
    def __before__(self):
        '''Set-up alias to SSO settings global'''
        self.cfg = g.ndg.security.server.sso.cfg
        self.state = g.ndg.security.common.sso.state
        
    def index(self):
        '''Initialise Session Manager client context, check for an existing
        user session.  If found, redirect back to SSO Client, if not found
        present login'''
        log.debug("LoginController.index ...")   

        # Check the return to URL from the 'r' argument in the request
        self.state.b64encReturnToURL = str(request.params.get('r', ''))
        
        if 'ndgSec' not in session: 
            log.debug('No security session details found - offering login...')
            return render('ndg.security.kid', 'ndg.security.login')
        
        # Session is set in this domain - check it 
        try:    
            smClnt = WSGISessionManagerClient(
                    environ=request.environ,
                    uri=session['ndgSec']['h'],
                    environKeyName=self.cfg.smEnvironKeyName,
                    attributeAuthorityEnvironKeyName=self.cfg.aaEnvironKeyName,
                    tracefile=self.cfg.tracefile,
                    httpProxyHost=self.cfg.httpProxyHost,
                    noHttpProxyList=self.cfg.noHttpProxyList,
                    sslCACertFilePathList=self.cfg.sslCACertFilePathList,
                    **self.cfg.wss)                                
        except Exception, e:
            c.xml = ('Error establishing security context.  Please report '
                     'the error to your site administrator')
            log.error("Initialising SessionManagerClient for getSessionStatus "
                      "call: %s" % e)
            SecuritySession.delete()
            response.status_code = 400
            return render('ndg.security.kid', 'ndg.security.login')
        
        # Check session status
        log.debug('Calling Session Manager "%s" getSessionStatus for user '
                  '"%s" with sid="%s" ...' %
                  (session['ndgSec']['h'], 
                   session['ndgSec']['u'], 
                   session['ndgSec']['sid']))

        try:
            c.loggedIn=smClnt.getSessionStatus(sessID=session['ndgSec']['sid'])
        except Exception, e:
            c.xml = "Error checking your session details.  Please re-login"
            log.error("Session Manager getSessionStatus: %s" % e)
            SecuritySession.delete()
            response.status_code = 400
            return render('ndg.security.kid', 'ndg.security.login')
   
        if c.loggedIn:
            log.debug("Session found - redirect back to site requesting "
                      "credentials ...")
            # ... Return across http GET passing security parameters...
            return self._redirect()
        else:
            log.debug("Session wasn't found - removing security details "
                      "from cookie and re-displaying login...")
            SecuritySession.delete()
            return render('ndg.security.kid', 'ndg.security.login')


    def getCredentials(self):
        """Authenticate user and cache user credentials in Session Manager 
        following user login"""
        log.debug("LoginController.getCredentials ...")   

        if 'username' not in request.params:
            log.debug("No username set - rendering login...")
            return render('ndg.security.kid', 'ndg.security.login')
        
        try:    
            smClnt = WSGISessionManagerClient(
                    environ=request.environ,
                    uri=self.cfg.smURI,
                    environKeyName=self.cfg.smEnvironKeyName,
                    attributeAuthorityEnvironKeyName=self.cfg.aaEnvironKeyName,
                    tracefile=self.cfg.tracefile,
                    httpProxyHost=self.cfg.httpProxyHost,
                    noHttpProxyList=self.cfg.noHttpProxyList,
                    **self.cfg.wss)
                                
            username = request.params['username']
            passphrase = request.params['passphrase']                     
                                
        except Exception, e:
            c.xml = ('Error establishing security context.  Please report '
                     'the error to your site administrator')
            log.error("Login: initialising WSGISessionManagerClient: %s" % e)
            response.status_code = 400
            return render('ndg.security.kid', 'ndg.security.login')
        
        # Connect to Session Manager
        log.debug('Calling Session Manager "%s" connect for user "%s" ...' %
                  (self.cfg.smURI, username))
        try:
            sessID = smClnt.connect(username, passphrase=passphrase)[-1]
        except Exception, e:
            c.xml = ("Error logging in.  Please check your username/"
                     "pass-phrase and try again.  If the problem persists "
                     "please contact your site administrator.")
            log.error("Session Manager connect returned: %s" % e)
            response.status_code = 400
            return render('ndg.security.kid', 'ndg.security.login')
        
        # Cache user attributes in Session Manager
        log.debug("Calling Session Manager getAttCert for Attribute Authority "
                  "[%s]" % self.cfg.aaURI)
        try:
            # Make request for attribute certificate
            attCert = smClnt.getAttCert(sessID=sessID, 
                                        attributeAuthorityURI=self.cfg.aaURI)
        except SessionExpired, e:
            log.info("Session expired getting Attribute Certificate: %s" % e)
            c.xml = "Session has expired, please re-login"
            response.status_code = 400
            return render('ndg.security.kid', 'ndg.security.login')
            
        except AttributeRequestDenied, e:
            log.error("Login: attribute Certificate request denied: %s" % e)
            c.xml = ("No authorisation roles are available for your "
                    "account.  Please check with your site administrator.")
            response.status_code = 400
            return render('ndg.security.kid', 'ndg.security.login')
            
        except Exception, e:
            log.error("Login: attribute Certificate request: %s" % e)
            c.xml = ("An internal error occurred.  Please report this to "
                    "your site administrator.")
            response.status_code = 400
            return render('ndg.security.kid', 'ndg.security.login')

        log.debug('Completing login...')
        
        c.loggedIn = True
        
        # Make security session details
        setSecuritySession(h=self.cfg.smURI,
                           u=username,
                           org=attCert.issuerName,
                           roles=attCert.roles,
                           sid=sessID)
        session.save()

        log.debug("session = %s" % session)
        log.info("user %s logged in with roles %s" % (session['ndgSec']['u'],
                                                  session['ndgSec']['roles']))
        return self._redirect()
        
        
    def _redirect(self):
        """Pass security creds back to requestor so that they can make
        a cookie.  If the requestor is in the same domain as the login then
        this is not necessary."""
        log.debug("LoginController._redirect...")
        
        # This is set in index and getCredentials
        if self.state.b64encReturnToURL:
        
            # Only add token if return URI is in a different domain
            thisHostname = request.host.split(':')[0]
            
            # Decode return to address
            returnToURL = urlsafe_b64decode(self.state.b64encReturnToURL)
            log.debug('Login redirect to [%s]' % returnToURL)

            hostnameWithPortNum = urlsplit(returnToURL)[1]
            
            # Require hostname with port number striped to test SSL connection
            # (will default to 443)
            returnToURLHostname = hostnameWithPortNum.split(':')[0]
            
#            if thisHostname not in returnToURLHostname:
            if True: # Ensure return args in URL regardless
                # Returning to a different domain - copy the security session
                # details into the URL query string
                if '?' in returnToURL:
                    returnToURL += '&%s' % SSOServiceQuery()
                else:
                    returnToURL += '?%s' % SSOServiceQuery()
            
            # Check return-to address by examining peer cert
            log.debug("Checking return-to URL for valid SSL peer cert. ...")

            
            # Look-up list of Cert DNs for trusted requestors
            aaClnt = WSGIAttributeAuthorityClient(
                                    environ=request.environ,
                                    uri=self.cfg.aaURI,
                                    environKeyName=self.cfg.aaEnvironKeyName,
                                    tracefile=self.cfg.tracefile,
                                    httpProxyHost=self.cfg.httpProxyHost,
                                    noHttpProxyList=self.cfg.noHttpProxyList,
                                    **self.cfg.wss)
            
            HostInfo = aaClnt.getAllHostsInfo()
            requestServerDN = [val['loginRequestServerDN']
                               for val in HostInfo.values()]
            log.debug("Attribute Authority [%s] expecting DN for SSL peer "
                      "one of: %s" % (self.cfg.aaURI, requestServerDN))
            
            hostCheck = HostCheck(acceptedDNs=requestServerDN,
                            caCertFilePathList=self.cfg.sslCACertFilePathList)
            
            testConnection = HTTPSConnection(returnToURLHostname, 
                                             None, 
                                             postConnectionCheck=hostCheck)

            log.debug('Testing connection to "%s"' % returnToURLHostname)
            try:
                try:
                    testConnection.connect()
                except (InvalidCertSignature, InvalidCertDN), e:
                    log.error("Login: requestor SSL certificate: %s" % e)
                    c.xml = ("Request to redirect back to %s with your "
                             "credentials refused: there is a problem with "
                             "the SSL certificate of this site.  Please "
                             "report this to your site administrator." % 
                             returnToURLHostname)
                    response.status_code = 400
                    return render('ndg.security.kid', 'ndg.security.login')
            finally:    
                testConnection.close()

            log.debug("SSL peer cert. is OK - redirecting to [%s] ..." %
                                                                returnToURL)
            # redirect_to doesn't like unicode
            h.redirect_to(str(returnToURL))
        else:
            log.debug("LoginController._redirect: no redirect URL set - "
                      "render login page")
            c.xml='Logged in'
            return render('ndg.security.kid', 'ndg.security.login')