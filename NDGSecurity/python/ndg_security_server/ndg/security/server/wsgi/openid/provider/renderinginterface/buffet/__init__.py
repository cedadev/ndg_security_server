"""NDG Security Pylons Buffet based Rendering Interface for 
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
from pylons.templating import Buffet

from openid.consumer import discover

# Rendering classes for OpenID Provider must derive from generic render 
# interface
from ndg.security.server.wsgi.openid.provider import RenderingInterface, \
    RenderingInterfaceConfigError
    
from ndg.security.server.wsgi.openid.provider import OpenIDProviderMiddleware

# Boiler plate to create renderer
class OpenIDProviderRenderingBuffet(Buffet):
    def _update_names(self, ns):
        return ns

class BuffetRendering(RenderingInterface):
    """Provide Templating for OpenID Provider Middleware via Buffet
    class"""

    propNames = (
        'templateType', 
        'templateRoot',
        'baseURL',
        'leftLogo',
        'leftAlt',
        'ndgLink',
        'ndgImage',
        'disclaimer',
        'stfcLink',
        'stfcImage',
        'helpIcon',
    )
        
    def __init__(self, *arg, **opt):
        '''Extend RenderingInterface to include config and set-up for Buffet
        object
        
        @type *arg: tuple
        @param *arg: RenderingInterface parent class arguments
        @type **opt: dict
        @param **opt: additional keywords to set-up Buffet rendering'''
        super(BuffetRendering, self).__init__(*arg, **opt)
        
        try:
            for i in opt:
                setattr(self, i, opt[i])
        except KeyError, e:
            raise RenderingInterfaceConfigError("Missing property: %s" % e)   
         
        self._buffet = OpenIDProviderRenderingBuffet(self.templateType, 
                                            template_root=self.templateRoot)
        
        self.title = ''
        self.xml = ''
        self.headExtras = ''
        self.loginStatus = True
        
    def _render(self, templateName, c=None, **kw):
        '''Wrapper for Buffet.render'''
        if c is None:
            c = self
            
        kw['c'] = c
        
        rendering = self._buffet.render(template_name=templateName, 
                                        namespace=kw)
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
        
        response = RenderingInterface.tmplYadis % yadisDict
     
        start_response('200 OK',
                       [('Content-type', 'application/xrds+xml'+self.charset),
                        ('Content-length', str(len(response)))])
        return response
 
    def login(self, environ, start_response, success_to=None, fail_to=None, 
              msg=''):
        """Set-up template for OpenID Provider Login"""
        self.title = "OpenID Login"
        self.success_to = success_to or self.urls['url_mainpage']
        self.fail_to = fail_to or self.urls['url_mainpage'] 
        self.xml = msg
        
        response = self._render('ndg.security.login')
        start_response('200 OK', 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        self.xml = ''
        return response
       
        
    def mainPage(self, environ, start_response):
        """Set-up template for OpenID Provider Login"""
        self.title = "OpenID Provider"
        self.headExtras = '<meta http-equiv="x-xrds-location" content="%s"/>'%\
                        self.urls['url_serveryadis']
    
        response = self._render('ndg.security.mainPage')
        start_response('200 OK', 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response


    def identityPage(self, environ, start_response):
        """This page would normally render the user's Identity page but it's
        not needed for Yadis only based discovery"""

        self.xml = 'Invalid page requested for OpenID Provider'
        response = self._render('ndg.security.error') 
        self.xml = ''   
        start_response("404 Not Found", 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response

   
    def decidePage(self, environ, start_response, oidRequest, oidResponse):
        """Handle user interaction required before final submit back to Relying
        Party
        @type oidRequest: openid.server.server.CheckIDRequest
        @param oidRequest: OpenID Check ID Request object
        @type oidResponse: openid.server.server.OpenIDResponse
        @param oidResponse: OpenID response object
        """
        self.title = 'Approve OpenID Request?'
        self.trust_root = oidRequest.trust_root
        self.oidRequest = oidRequest
        self.oidResponse = oidResponse
        self.environ = environ
        
        if oidRequest.idSelect():
            if 'username' not in self.session:
                log.error("No 'username' key set in sessin object for "
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
        
        response = self._render('ndg.security.decidePage')
        self.identityURI = ''
        
        start_response("200 OK", 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        return response

        
    def errorPage(self, environ, start_response, msg, code=500):
        '''Display error information'''
        self.title = 'Error with OpenID Provider'
        self.xml = msg
        response = self._render('ndg.security.error')
        start_response('%d %s' % (code, httplib.responses[code]), 
                       [('Content-type', 'text/html'+self.charset),
                        ('Content-length', str(len(response)))])
        self.xml = ''
        return response
