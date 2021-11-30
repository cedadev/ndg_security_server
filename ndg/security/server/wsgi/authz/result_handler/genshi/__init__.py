"""WSGI Policy Enforcement Point basic result handler module for a Genshi
based implementation.  Access denied HTML response is rendered using the
Genshi templating language.

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "05/01/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
__license__ = "BSD - see LICENSE file in top-level directory"
import logging
log = logging.getLogger(__name__)

from os import path
from http.client import UNAUTHORIZED, FORBIDDEN
from string import Template

from paste.urlparser import StaticURLParser
from genshi.template import TemplateLoader

from ndg.saml.saml2.core import DecisionType
from ndg.security.server.utils.paste_port import Cascade
from ndg.security.server.wsgi.authz.result_handler import \
    PEPResultHandlerMiddlewareBase


class GenshiPEPResultHandlerMiddleware(PEPResultHandlerMiddlewareBase):
    """Genshi based PEP result handler
    """       
    DEFAULT_TMPL_NAME = 'accessdenied.html'
    DEFAULT_TMPL_DIR = path.join(path.dirname(__file__), 'templates')
    
    MSG_TMPL = (
        "$pdpResponseMsg<br/><br/>"
        "Please report this to your site administrator and check that you "
        "have the required access privileges."
    )
    
    PROPERTY_DEFAULTS = {
        'messageTemplate': MSG_TMPL,
        'templateName': DEFAULT_TMPL_NAME,
        'templateRootDir': DEFAULT_TMPL_DIR,
        'baseURL': '',
        'heading': '',
        'title': '',
        'leftLogo': '',
        'leftAlt': '',
        'leftLink': '',
        'leftImage': '',
        'footerText': 'Test deployment only',
        'rightLink': '',
        'rightImage': '',
        'rightAlt': '',
        'helpIcon': ''
    }
    __slots__ = PROPERTY_DEFAULTS
    
    def __init__(self, app, global_conf, prefix='', **app_conf):
        '''
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        super(GenshiPEPResultHandlerMiddleware, self).__init__(app, {}) 
               
        # Initialise attributes
        for k, v in list(GenshiPEPResultHandlerMiddleware.PROPERTY_DEFAULTS.items()):
            setattr(self, k, v)
         
        # Update from keywords   
        for i in app_conf:
            if prefix and i.startswith(prefix):
                attrName = i.rsplit(prefix, 2)[-1]
                setattr(self, attrName, app_conf[i])
            
        self.__loader = TemplateLoader(self.templateRootDir, auto_reload=True)

    @PEPResultHandlerMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        """Render access denied message or else if user is not authenticated,
        set HTTP 401 response
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        """ 
        session = self.environ.get(self.sessionKey)
        if not self.isAuthenticated:
            # sets 401 response to be trapped by authentication handler
            log.warning("GenshiPEPResultHandlerMiddleware: user is not "
                        "authenticated - setting HTTP 401 response")
            return self._setErrorResponse(code=UNAUTHORIZED)
        else:
            # Get response message from PDP recorded by PEP
            cls = self.__class__
            pepCtx = session.get(cls.PEPCTX_SESSION_KEYNAME, {})
            pdpResponse = pepCtx.get(cls.PEPCTX_RESPONSE_SESSION_KEYNAME)
            if pdpResponse is not None:
                # Expecting a SAML response - parse decision values from this
                pdpResponseMsg = ("The authorisation policy has set "
                                  "access denied for this resource.")
                for assertion in pdpResponse.assertions:
                    for authzDecisionStatement in \
                         assertion.authzDecisionStatements:
                        if (authzDecisionStatement.decision.value == 
                            DecisionType.INDETERMINATE_STR):
                            pdpResponseMsg = ("An error occurred making an "
                                              "access decision.")
                            break
            else:
                pdpResponseMsg = "Access is denied for this resource."
                 
            msg = Template(self.messageTemplate).substitute(
                                                pdpResponseMsg=pdpResponseMsg)

            response = self._render(xml=msg)
            start_response(cls.getStatusMessage(FORBIDDEN),
                           [('Content-type', 'text/html'),
                            ('Content-Length', str(len(response)))])
            
            return response
        
    def __setattr__(self, name, value):
        """Apply some generic type checking"""
        if name in GenshiPEPResultHandlerMiddleware.PROPERTY_DEFAULTS:
            if not isinstance(value, str):
                raise TypeError('Expecting string type for %r attribute; got '
                                '%r' % (name, type(value)))
            
        super(GenshiPEPResultHandlerMiddleware, self).__setattr__(name, value)
                       
    def _getLoader(self):
        return self.__loader

    def _setLoader(self, value):
        if not isinstance(value, TemplateLoader):
            raise TypeError('Expecting %r type for "loader"; got %r' % 
                            (TemplateLoader, type(value)))
        self.__loader = value

    loader = property(_getLoader, _setLoader, 
                      doc="Genshi TemplateLoader instance")  
          
    def _render(self, c=None, **kw):
        '''Wrapper for Genshi template rendering
        
        @type c: None/object
        @param c: reference to object to pass into template - defaults to self
        @type kw: dict
        @param kw: keywords to pass to template
        @rtype: string
        @return: rendered template
        '''    
        if c is None:
            kw['c'] = self 
              
        tmpl = self.loader.load(self.templateName)
        rendering = tmpl.generate(**kw).render('html', doctype='html')
        
        return rendering
