"""NDG Security OpenID Relying Party Buffet based Sign in template

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/01/2009"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

from paste.cascade import Cascade
from paste.registry import RegistryManager
from paste.urlparser import StaticURLParser

from pylons.templating import Buffet

from ndg.security.server.wsgi.openid.relyingparty import SigninInterface, \
    SigninInterfaceConfigError

# Boiler plate to create renderer
class OpenIDRelyingPartyRenderingBuffet(Buffet):
    def _update_names(self, ns):
        return ns

class BuffetSigninTemplate(SigninInterface):
    """Provide Templating for OpenID Relying Party Middleware Sign in interface
    via Buffet class"""

    propertyDefaults = {
        'templateType': 'kid', 
        'templatePackage': None,
        'staticContentRootDir': './',
        'baseURL': 'http://localhost',
        'initialOpenID': '',
        'logoutURI': '',
        'leftLogo': None,
        'leftAlt': None,
        'ndgLink': 'http://ndg.nerc.ac.uk',
        'ndgImage': None,
        'disclaimer': 'Test deployment only',
        'stfcLink': 'http://www.stfc.ac.uk/',
        'stfcImage': None,
        'helpIcon': None
    }
        
    def __init__(self, app, global_conf, **local_conf):
        '''Extend SignInterface to include config and set-up for Buffet
        object
        
        @type *arg: tuple
        @param *arg: RenderingInterface parent class arguments
        @type **opt: dict
        @param **opt: additional keywords to set-up Buffet rendering'''
        super(BuffetSigninTemplate, self).__init__(app, 
                                                   global_conf, 
                                                   **local_conf)
        
        self._buffet = OpenIDRelyingPartyRenderingBuffet(self.templateType, 
                                            template_root=self.templatePackage)
        
        self.title = "Enter your OpenID to Sign in"
        self.xml = ''
        self.headExtras = ''
        self.loginStatus = True
        self.loggedIn = False
        
        # TODO: handle session object scope
        self.session = {'username': ''}
        
        staticApp = StaticURLParser(self.staticContentRootDir)
        self._app = Cascade([staticApp, self._app], catch=(404, 401))
        
    def _render(self, templateName, c=None, **kw):
        '''Wrapper for Buffet.render'''
        if c is None:
            c = self
            
        kw['c'] = c
        
        rendering = self._buffet.render(template_name=templateName, 
                                        namespace=kw)
        return rendering
   
    def makeTemplate(self):
        return self._render('signin', c=self)
    
    def getTemplateFunc(self):
        """Set-up template for OpenID Provider Login"""
        def _makeTemplate():
            return self.makeTemplate()
            
        return _makeTemplate
    
    def __call__(self, environ, start_response):
        return self._app(environ, start_response)
