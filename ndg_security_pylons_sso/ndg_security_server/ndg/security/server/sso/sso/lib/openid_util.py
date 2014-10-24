import pylons
from pylons.templating import Buffet
from pylons import config, request, session
import ndg.security.server.sso.sso.lib.helpers as h
from ndg.security.server.sso.sso.lib.app_globals import Globals

import logging
log = logging.getLogger(__name__)

log.debug("Defining MyBuffet for OpenID template ...")

class MyBuffet(Buffet):
    def _update_names(self, ns):
        return ns

def_eng = config['buffet.template_engines'][0]
log.info("def_eng = %s" % def_eng)
buffet = MyBuffet(
    def_eng['engine'],
    template_root=def_eng['template_root'],
    **def_eng['template_options']
)

for e in config['buffet.template_engines'][1:]:
    buffet.prepare(
        e['engine'],
        template_root=e['template_root'],
        alias=e['alias'],
        **e['template_options']
    )

class State:
    '''Collection of variables to set in templates'''
    def __init__(self):
        self.openid = 'None'
        self.title = "Login"
        self.xml = ''
        self.doc = 'logged in'
        self.providers = {}
        self.loggedIn = False
        self.errorPageHeading = ''


# State variable for WAYF kid file set-up
c = State()

import base64

def make_template():
    '''Make kid template for OpenID login - the NDG WAYF piggy backs this.
    
    It's triggered by a HTTP 401 authorisation error and called explicitly
    via the WAYF controller'''
    
    g = config['pylons.g']
    
    # Check for return from OpenID login
    try:
        userSet = 'REMOTE_USER' in request.environ
    except TypeError, e:
        # Request object may not be registered - crude fix here wrapping it a
        # catch
        # TODO: referencing environ outside a controller
        log.info("Keying 'REMOTE_USER' in request.environ: %s" % e)
        userSet = False
        
    if userSet:
        if not g.ndg.security.common.sso.state.returnToURL:
            log.error("No returnToURL set for redirect following OpenID "
                      "login")
        else:
            log.info("Redirecting to [%s] following OpenID login ..." %
                     g.ndg.security.common.sso.state.returnToURL)
            h.redirect_to(g.ndg.security.common.sso.state.returnToURL)

    state = g.ndg.security.common.sso.state
    cfg =  g.ndg.security.common.sso.cfg
    
    # Set encoded return to address - ensure login can return to an address 
    # over https to preserve confidentiality of credentials
    # TODO: revisit - at the moment a redirect back from https -> http at the
    # client to the IdP is rejected
#    if state.returnToURL and cfg.server in state.returnToURL:
#        state.returnToURL = state.returnToURL.replace(cfg.server, 
#                                                      cfg.sslServer)
#        log.debug("make_template: switched return to address to https = %s" % 
#                                                            state.returnToURL)

    state.b64encReturnToURL = base64.urlsafe_b64encode(str(state.returnToURL))        
    
    # Retrieve IdP details 
    _getTrustedIdPs(g)
    
    return _render("ndg.security.wayf", h=h, g=g, c=c)


def _render(templateName, **kw):
    '''TODO: Wrapper to enable substitution of $message and $css_class used by
    AuthKit open_id module'''
    rendering = buffet.render('ndg.security.kid', 
                              template_name=templateName,
                              namespace=kw)
    # Add $message and $css_class here somehow
    return rendering


from ndg.security.server.wsgi.utils.attributeauthorityclient import \
    WSGIAttributeAuthorityClient

def _getTrustedIdPs(g):
    '''Retrieve list of trusted login sites for user to select - calls
    Attribute Authority WS'''

    # Get references to globals
    state = g.ndg.security.common.sso.state
    cfg =  g.ndg.security.server.sso.cfg
                                
    # Check for cached copy and return if set to avoid recalling
    # Attribute Authority - This has the consequence that if the list
    # of trusted hosts in the Map Configuration changes, the Attribute
    # Authority and THIS service must be restarted.
    if len(g.ndg.security.server.sso.state.trustedIdPs) > 0:
        return
    
    log.debug("Initialising connection to Attribute Authority [%s]"%cfg.aaURI)
    
    try:
        aaClnt = WSGIAttributeAuthorityClient(environ=pylons.request.environ,
                                        uri=cfg.aaURI,
                                        environKeyName=cfg.aaEnvironKeyName,
                                        tracefile=cfg.tracefile,
                                        httpProxyHost=cfg.httpProxyHost,
                                        noHttpProxyList=cfg.noHttpProxyList,
                                        **cfg.wss)
    except Exception, e:
        log.error("Initialising AttributeAuthorityClient for "
                  "getAllHostsInfo call: %s" % e)
        return

    # Get list of login uris for trusted sites including THIS one
    log.debug("Calling Attribute Authority getAllHostsInfo for wayf ...")

    try:
        hosts = aaClnt.getTrustedHostInfo() 
    except Exception, e:
        log.error("AttributeAuthorityClient getAllHostsInfo call: %s" % e)  
        return
        
    # Pick out siteName for as it should be set to a more user friendly 
    # description of the site.  Site name may not be set so if unavailable,
    # default to host name identifier.
    g.ndg.security.server.sso.state.trustedIdPs = \
                        dict([(v['siteName'] or k, v['loginURI']) 
                                 for k, v in hosts.items()])


from ndg.security.common.pylons.security_util import setSecuritySession
from urlparse import urlsplit

def url2user(environ, url):
    '''Function picked up by authkit.openid.urltouser config setting.  It
    sets a username from the users OpenID URL following login'''
    log.info("OpenID sign in with [%s]" % url)
    
    # Remove protocol prefix and strip /'s
    username = ''.join(urlsplit(url)[1:]).strip('/').replace('/', '-')
    return username
