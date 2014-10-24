import pylons
from pylons.templating import Buffet
from pylons import config
import ndg.security.server.sso.sso.lib.helpers as h
import logging
log = logging.getLogger(__name__)

class MyBuffet(Buffet):
    def _update_names(self, ns):
        return ns

def_eng = config['buffet.template_engines'][0]
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
    def __init__(self, urls={}, session={}):
        self.title = ''
        self.xml = ''
        self.headExtras = ''
        self.session = session
        self.loginStatus = True
        self.urls = urls

def _render(templateName, **kw):
    ''''''
    rendering = buffet.render(template_name=templateName, namespace=kw)
    return rendering

config['pylons.g'].server = "http://localhost:8700"
config['pylons.g'].LeftLogo = config['pylons.g'].server+'/layout/NERC_Logo.gif'
config['pylons.g'].LeftAlt = 'Natural Environment Research Council'
config['pylons.g'].ndgLink = 'http://ndg.nerc.ac.uk/'
config['pylons.g'].ndgImage = config['pylons.g'].server+'/layout/ndg_logo_circle.gif'
config['pylons.g'].disclaimer = ''
config['pylons.g'].stfcLink = 'http://ceda.stfc.ac.uk/'
config['pylons.g'].stfcImage = config['pylons.g'].server+'/layout/stfc-circle-sm.gif'
config['pylons.g'].helpIcon = config['pylons.g'].server+'/layout/icons/help.png'

from ndg.security.server.wsgi.openid.provider import RenderingInterface

class OpenIDProviderKidRendering(RenderingInterface):
    """Provide Kid Templating for OpenID Provider Middleware"""
    
    def login(self, environ, success_to=None, fail_to=None):
        """Set-up Kid template for OpenID Provider Login"""
        c = State(urls=self.urls, session=self.session)
        c.title = "OpenID Login"
        c.success_to = success_to or self.urls['url_mainpage']
        c.fail_to = fail_to or self.urls['url_mainpage'] 
    
        return _render('ndg.security.login', c=c, g=config['pylons.g'], h=h)
        
        
    def mainPage(self, environ):
        """Set-up Kid template for OpenID Provider Login"""
        c = State(urls=self.urls, session=self.session)
        c.title = "OpenID Provider"
        c.headExtras = '<meta http-equiv="x-xrds-location" content="%s"/>' % \
                        self.urls['url_serveryadis']
    
        return _render('ndg.security.mainPage', c=c, g=config['pylons.g'], h=h)


    def identityPage(self, environ):
        """Identity page"""
        path = environ['PATH_INFO']
        username = path[4:]
        if not username:
            h.redirect_to(self.urls['url_mainpage'])
            
        c = State(urls=self.urls, session=self.session)
        c.title = "OpenID Identity Page"
                        
        link_tag = '<link rel="openid.server" href="%s"/>' % \
              self.urls['url_openidserver']
              
        yadis_loc_tag = '<meta http-equiv="x-xrds-location" content="%s"/>' % \
            (self.urls['url_yadis']+'/'+username)
            
        c.headExtras = link_tag + yadis_loc_tag
        identityURL = self.base_url + path
        c.xml = "<b><pre>%s</pre></b>" % identityURL
        
        return _render('ndg.security.identityPage',
                       c=c, g=config['pylons.g'], h=h)    
    
    def decidePage(self, environ, oidRequest):
        """Handle user interaction required before final submit back to Relying
        Party"""
        c = State(urls=self.urls, session=self.session)
        c.title = 'Approve OpenID Request?'
        c.trust_root = oidRequest.trust_root
        c.oidRequest = oidRequest
        
        return _render('ndg.security.decidePage', c=c,g=config['pylons.g'],h=h)

        
    def errorPage(self, environ, msg):
        c = State(urls=self.urls, session=self.session)
        c.title = 'Error with OpenID Provider'
        c.xml = msg
        return _render('ndg.security.error', c=c, g=config['pylons.g'], h=h)