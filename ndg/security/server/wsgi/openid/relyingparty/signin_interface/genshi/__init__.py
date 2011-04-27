"""NDG Security OpenID Relying Party Genshi based Sign in template

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

from os import path

from paste.cascade import Cascade
from paste.urlparser import StaticURLParser     
from genshi.template import TemplateLoader

from ndg.security.server.wsgi.openid.relyingparty import (SigninInterface, 
    SigninInterfaceConfigError)


class GenshiSigninTemplate(SigninInterface):
    """Provide Templating for OpenID Relying Party Middleware Sign in interface
    via Buffet class"""
    DEFAULT_TEMPLATES_DIR = path.join(path.dirname(__file__), 'templates')
    DEFAULT_STATIC_CONTENT_DIR = path.join(path.dirname(__file__), 'public')
    
    SIGNIN_TEMPLATE_NAME = 'signin.html'
    
    propertyDefaults = {
        'templateRootDir': DEFAULT_TEMPLATES_DIR,
        'staticContentRootDir': None,
        'baseURL': 'http://localhost',
        'initialOpenID': '',
        'heading': '',
        'leftLogo': None,
        'leftAlt': '',
        'leftLink': None,
        'leftImage': None,
        'footerText': 'Test deployment only',
        'rightLink': None,
        'rightImage': None,
        'rightAlt': '',
        'helpIcon': None
    }
    
    def __init__(self, app, global_conf, **local_conf):
        '''Extend SignInterface to include config and set-up for Genshi
        object
        
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        enables other global configuration parameters to be filtered out
        @type local_conf: dict        
        @param local_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        super(GenshiSigninTemplate, self).__init__(app, 
                                                   global_conf, 
                                                   **local_conf)
            
        self.__loader = TemplateLoader(self.templateRootDir, auto_reload=True)
        
        self.title = "Enter your OpenID to Sign in"
        self.xml = ''
        self.headExtras = ''
        self.loginStatus = True
        self.loggedIn = False
        
        # TODO: handle session object scope
        self.session = {'username': ''}
        
        if self.staticContentRootDir is not None:
            staticApp = StaticURLParser(self.staticContentRootDir)
            appList = [staticApp]
            
            # Check next app is set - if it is, add to the Cascade - Nb.
            # THIS middleware may behave as an app in which case there is no
            # next app in the chain      
            if self._app is not None:
                appList += [self._app]
                
            self._app = Cascade(appList, catch=(404, 401))

    def _getStaticContentRootDir(self):
        return self.__staticContentRootDir

    def _setStaticContentRootDir(self, value):
        if not isinstance(value, (basestring, type(None))):
            raise TypeError('Expecting string or None type for '
                            "'staticContentRootDir'; got %r" % type(value))
        
        if value is not None and not path.isdir(value):
            raise AttributeError("'staticContentRootDir' setting %r is not a "
                                 "valid directory" % value)
            
        self.__staticContentRootDir = value

    staticContentRootDir = property(_getStaticContentRootDir, 
                                    _setStaticContentRootDir, 
                                    doc="StaticContentRootDir's Docstring")

    def _getLoader(self):
        return self.__loader

    def _setLoader(self, value):
        if not isinstance(value, TemplateLoader):
            raise TypeError('Expecting %r type for "loader"; got %r' % 
                            type(value))
        self.__loader = value

    loader = property(_getLoader, _setLoader, 
                      doc="Genshi TemplateLoader instance")

    def _render(self, templateName, c=None, **kw):
        '''Wrapper for Genshi template rendering
        @type templateName: basestring
        @param templateName: name of template file to load
        @type c: None/object
        @param c: reference to object to pass into template - defaults to self
        @type kw: dict
        @param kw: keywords to pass to template
        @rtype: string
        @return: rendered template
        '''
        if c is None:
            c = self
            
        kw['c'] = c
        
        tmpl = self.loader.load(templateName)
        rendering = tmpl.generate(**kw).render('html', doctype='html')

        return rendering
   
    def makeTemplate(self):
        '''
        @rtype: string
        @return: rendered template
        '''
        return self._render(GenshiSigninTemplate.SIGNIN_TEMPLATE_NAME, c=self)
    
    def getTemplateFunc(self):
        """Set-up template for OpenID Provider Login
        @rtype: callable
        @return: rendering function
        """
        def _makeTemplate():
            return self.makeTemplate()
            
        return _makeTemplate
    
    def __call__(self, environ, start_response):
        return self._app(environ, start_response)
