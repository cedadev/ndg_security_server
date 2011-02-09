"""NDG Security Genshi based Rendering Interface for 
OpenIDProviderMiddleware

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "14/08/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
__license__ = "BSD - see LICENSE file in top-level directory"
import logging
log = logging.getLogger(__name__)

import httplib
from os import path

from genshi.template import TemplateLoader
from openid.consumer import discover
from openid.server.server import CheckIDRequest, OpenIDResponse
from openid.extensions import ax

# Rendering classes for OpenID Provider must derive from generic render 
# interface
from ndg.security.server.wsgi.openid.provider import (RenderingInterface, 
    RenderingInterfaceConfigError)
    
from ndg.security.server.wsgi.openid.provider import OpenIDProviderMiddleware


class GenshiRendering(RenderingInterface):
    """Provide Templating for OpenID Provider Middleware using Genshi templating
    """
    PROPERTY_NAMES = (
        'templateRootDir',
        'baseURL',
        'leftLogo',
        'leftAlt',
        'leftLink',
        'leftImage',
        'rightLink',
        'rightImage',
        'rightAlt',
        'footerText',
        'helpIcon',
        'tmplServerYadis',
        'tmplYadis'
    )
    
    # Make a set of defaults with specific settings for the Yadis templates 
    # based on parent class class variables
    PROPERTY_DEFAULTS = {}.fromkeys(PROPERTY_NAMES, '')
    PROPERTY_DEFAULTS['tmplServerYadis'] = RenderingInterface.tmplServerYadis
    PROPERTY_DEFAULTS['tmplYadis'] = RenderingInterface.tmplYadis
    
    ATTR_NAMES = (
        'title', 
        'heading',
        'xml', 
        'headExtras', 
        'loginStatus',
        'loader',
        'session',
        'success_to',
        'fail_to',
        'trust_root',
        'environ',
        'identityURI',
        'oidRequest',
        'oidResponse'
    )
    __slots__ = tuple(["__%s" % name for name in ATTR_NAMES])
    del name
    __slots__ += PROPERTY_NAMES
        
    LOGIN_TMPL_NAME = 'login.html'
    DECIDE_PAGE_TMPL_NAME = 'decide.html'
    MAIN_PAGE_TMPL_NAME = 'main.html'
    ERROR_PAGE_TMPL_NAME = 'error.html'
    SERVER_YADIS_TMPL_NAME = 'serveryadis.xml'
    YADIS_TMPL_NAME = 'yadis.xml'
    
    # Approve and reject submit HTML input types for the Relying Party Approval 
    # page
    APPROVE_RP_SUBMIT = OpenIDProviderMiddleware.APPROVE_RP_SUBMIT
    REJECT_RP_SUBMIT = OpenIDProviderMiddleware.REJECT_RP_SUBMIT

    DEFAULT_TEMPLATES_DIR = path.join(path.dirname(__file__), 'templates')

   
    def __init__(self, *arg, **opt):
        '''Extend RenderingInterface to include config and set-up for Genshi
        templating
        
        @type *arg: tuple
        @param *arg: RenderingInterface parent class arguments
        @type **opt: dict
        @param **opt: additional keywords to set-up Genshi rendering'''
        super(GenshiRendering, self).__init__(*arg, **opt)
        
        # Initialise attributes
        for i in self.__class__.PROPERTY_NAMES:
            setattr(self, i, self.__class__.PROPERTY_DEFAULTS[i])
         
        # Update from keywords   
        for i in opt:
            setattr(self, i, opt[i])

        if not self.templateRootDir:
            self.templateRootDir = GenshiRendering.DEFAULT_TEMPLATES_DIR
         
        self.__loader = TemplateLoader(self.templateRootDir, auto_reload=True)
        
        self.title = ''
        self.heading = ''
        self.xml = ''
        self.headExtras = ''
        self.loginStatus = True
        self.session = ''
        self.success_to = ''
        self.fail_to = ''
        
        self.__oidRequest = None
        self.__oidResponse = None
        self.__identityURI = None
        self.__environ = None
        self.__trust_root = None

    def getEnviron(self):
        return self.__environ

    def getIdentityURI(self):
        return self.__identityURI

    def setEnviron(self, value):
        self.__environ = value

    def setIdentityURI(self, value):
        self.__identityURI = value

    def getTrust_root(self):
        return self.__trust_root

    def getOidRequest(self):
        return self.__oidRequest

    def getOidResponse(self):
        return self.__oidResponse

    def setTrust_root(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for trust_root attribute; '
                            'got %r' % type(value))
        self.__trust_root = value

    def setOidRequest(self, value):
        if not isinstance(value, CheckIDRequest):
            raise TypeError('Expecting %r type for oidRequest attribute; '
                            'got %r' % (CheckIDRequest, type(value)))
        self.__oidRequest = value

    def setOidResponse(self, value):
        if not isinstance(value, OpenIDResponse):
            raise TypeError('Expecting %r type for oidResponse attribute; '
                            'got %r' % (OpenIDResponse, type(value)))
        self.__oidResponse = value

    def getSuccess_to(self):
        return self.__success_to

    def getFail_to(self):
        return self.__fail_to

    def setSuccess_to(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for success_to attribute; '
                            'got %r' % type(value))
        self.__success_to = value

    def setFail_to(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for fail_to attribute; '
                            'got %r' % type(value))
        self.__fail_to = value

    def getTitle(self):
        return self.__title

    def getHeading(self):
        return self.__heading

    def getXml(self):
        return self.__xml

    def getHeadExtras(self):
        return self.__headExtras

    def getLoginStatus(self):
        return self.__loginStatus

    def getSession(self):
        return self.__session
    
    def setTitle(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for title attribute; '
                            'got %r' % type(value))
        self.__title = value
    
    def setHeading(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for heading attribute; '
                            'got %r' % type(value))
        self.__heading = value

    def setXml(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for xml attribute; '
                            'got %r' % type(value))
        self.__xml = value

    def setHeadExtras(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for headExtras attribute; '
                            'got %r' % type(value))
        self.__headExtras = value

    def setLoginStatus(self, value):
        if not isinstance(value, bool):
            raise TypeError('Expecting bool type for loginStatus attribute; '
                            'got %r' % type(value))
        self.__loginStatus = value

    def setSession(self, value):
        self.__session = value

    title = property(getTitle, setTitle, None, "Template title")

    heading = property(getHeading, setHeading, None, "Template heading")

    xml = property(getXml, setXml, None, "Additional XML for template")

    headExtras = property(getHeadExtras, setHeadExtras, None, 
                          "additional head info for template")

    loginStatus = property(getLoginStatus, setLoginStatus, None, 
                           "Login Status boolean")

    session = property(getSession, setSession, None, 
                       "Beaker session")

    success_to = property(getSuccess_to, setSuccess_to, None, 
                          "URL following successful login")

    fail_to = property(getFail_to, setFail_to, None, 
                       "URL following an error with login")

    def __setattr__(self, name, value):
        """Apply some generic type checking"""
        if name in GenshiRendering.PROPERTY_NAMES:
            if not isinstance(value, basestring):
                raise TypeError('Expecting string type for %r attribute; got '
                                '%r' % (name, type(value)))
            
        super(GenshiRendering, self).__setattr__(name, value)
        
    def _getLoader(self):
        return self.__loader

    def _setLoader(self, value):
        if not isinstance(value, TemplateLoader):
            raise TypeError('Expecting %r type for "loader"; got %r' % 
                            (TemplateLoader, type(value)))
        self.__loader = value

    loader = property(_getLoader, _setLoader, 
                      doc="Genshi TemplateLoader instance")  
          
    def _render(self, templateName, method='html', doctype='html', c=None, **kw):
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
        rendering = tmpl.generate(**kw).render(method=method, doctype=doctype)
        
        return rendering

    def yadis(self, environ, start_response):
        """Render Yadis document containing user URL - override base 
        implementation to specify Yadis based discovery for user URL
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @rtype: basestring
        @return: WSGI response
        """
        userIdentifier = OpenIDProviderMiddleware.parseIdentityURI(
                                                    environ['PATH_INFO'])[-1]
        
        # This is where this implementation differs from the base class one
        user_url = OpenIDProviderMiddleware.createIdentityURI(
                                                        self.urls['url_yadis'],
                                                        userIdentifier)
        
        yadisDict = dict(openid20type=discover.OPENID_2_0_TYPE, 
                         openid10type=discover.OPENID_1_0_TYPE,
                         endpoint_url=self.urls['url_openidserver'], 
                         user_url=user_url)
        
        response = self._render(self.__class__.YADIS_TMPL_NAME, 
                                method='xml',
                                doctype=None,
                                **yadisDict)
     
        start_response('200 OK',
                       [('Content-type', 'application/xrds+xml'+self.charset),
                        ('Content-length', str(len(response)))])
        return response
    
    def serverYadis(self, environ, start_response):
        '''Render Yadis info for ID Select mode request - Override base 
        implementation to enable custom XRDS document setting
        
        @type environ: dict
        @param environ: dictionary of environment variables
        @type start_response: callable
        @param start_response: WSGI start response function.  Should be called
        from this method to set the response code and HTTP header content
        @rtype: basestring
        @return: WSGI response
        '''
        endpoint_url = self.urls['url_openidserver']
        _dict = {
            'openid20type': discover.OPENID_IDP_2_0_TYPE,
            'endpoint_url': endpoint_url
        }
        
        response = self._render(self.__class__.SERVER_YADIS_TMPL_NAME, 
                                method='xml',
                                doctype=None,
                                **_dict)
             
        start_response("200 OK",
                       [('Content-type', 'application/xrds+xml'),
                        ('Content-length', str(len(response)))])
        return response 
    
    def login(self, environ, start_response, success_to=None, fail_to=None, 
              msg=''):
        """Set-up template for OpenID Provider Login"""
        self.title = "OpenID Login"
        self.heading = "Login"
        self.success_to = success_to or self.urls['url_mainpage']
        self.fail_to = fail_to or self.urls['url_mainpage'] 
        self.xml = msg
        
        response = self._render(GenshiRendering.LOGIN_TMPL_NAME)
        start_response('200 OK', 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        self.xml = ''
        return response
               
    def mainPage(self, environ, start_response):
        """Set-up template for OpenID Provider Login"""
        self.title = "OpenID Provider"
        self.heading = "OpenID Provider"
        self.headExtras = '<meta http-equiv="x-xrds-location" content="%s"/>'%\
                        self.urls['url_serveryadis']
    
        response = self._render(GenshiRendering.MAIN_PAGE_TMPL_NAME)
        start_response('200 OK', 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response

    def identityPage(self, environ, start_response):
        """This page would normally render the user's Identity page but it's
        not needed for Yadis only based discovery"""
        self.title = 'OpenID Provider - Error'
        self.heading = 'OpenID Provider - Invalid Page Requested'
        self.xml = 'Invalid page requested for OpenID Provider'
        response = self._render(GenshiRendering.ERROR_PAGE_TMPL_NAME) 
        self.xml = ''   
        start_response("404 Not Found", 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response
  
    def decidePage(self, environ, start_response, oidRequest, oidResponse):
        """Handle user interaction required before final submit back to Relying
        Party"""
        self.title = 'Approve OpenID Request?'
        self.heading = 'Approve OpenID Request?'
        self.trust_root = oidRequest.trust_root
        self.oidRequest = oidRequest
        
        # Get all the content namespaced as AX type
        axArgs = oidResponse.fields.getArgs(ax.AXMessage.ns_uri)
        
        # Add to access object for convenient access based on type URI
        axFetchResponse = ax.FetchResponse()
        axFetchResponse.parseExtensionArgs(axArgs)  
        
        ax_req = ax.FetchRequest.fromOpenIDRequest(oidRequest)
        axRequestedAttr = ax_req.requested_attributes
        self.environ = environ
        
        if oidRequest.idSelect():
            if 'username' not in self.session:
                log.error("No 'username' key set in session object for "
                          "idselect mode do decide page")
                msg = ('An internal error has occurred.  Please contact '
                       'your system administrator')
                response = self.errorPage(environ, start_response, msg)
                return response
                
            userIdentifier = self._authN.username2UserIdentifiers(
                                            environ,
                                            self.session['username'])[0]
                                            
            # Use the Yadis path because we want to use Yadis only
            # based discovery
            self.identityURI = OpenIDProviderMiddleware.createIdentityURI(
                                                        self.urls['url_yadis'],
                                                        userIdentifier)
        else:
            self.identityURI = oidRequest.identity
        
        response = self._render(GenshiRendering.DECIDE_PAGE_TMPL_NAME,
                                axRequestedAttr=axRequestedAttr,
                                axFetchResponse=axFetchResponse)
        self.identityURI = ''
        
        start_response("200 OK", 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response
        
    def errorPage(self, environ, start_response, msg, code=500):
        '''Display error information'''
        self.title = 'Error with OpenID Provider'
        self.heading = 'Error'
        self.xml = msg
        response = self._render(GenshiRendering.ERROR_PAGE_TMPL_NAME)
        start_response('%d %s' % (code, httplib.responses[code]), 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        self.xml = ''
        return response

    trust_root = property(getTrust_root, setTrust_root, 
                          doc="trust_root - dict of user trusted RPs")

    oidRequest = property(getOidRequest, setOidRequest, 
                          doc="oidRequest - OpenID Request object")

    oidResponse = property(getOidResponse, setOidResponse, 
                           doc="oidRequest - OpenID Response object")
   
    environ = property(getEnviron, setEnviron, None, 
                       "WSGI environ dict")

    identityURI = property(getIdentityURI, setIdentityURI, 
                           doc="User OpenID URI")
