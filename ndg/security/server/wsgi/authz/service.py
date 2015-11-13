"""Authorization service with SAML 2.0 authorisation decision query interface

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "17/02/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

from ndg.security.server.xacml.ctx_handler import saml_ctx_handler
from ndg.security.common.utils.factory import importModuleObject


class AuthorisationServiceMiddlewareError(Exception):
    """Authorisation Service generic exception type"""
    

class AuthorisationServiceMiddlewareConfigError(
                                        AuthorisationServiceMiddlewareError):
    """Authorisation Service configuration error"""
    
    
class AuthorisationServiceMiddleware(object):
    '''WSGI to add an NDG Security Authorization Service in the environ.
    
    @cvar PIP_CFG_PREFIX: prefix for Policy Information Point related parameters
    @type PIP_CFG_PREFIX: string
    '''
    DEFAULT_PARAM_PREFIX = 'authorisationService.'
    DEFAULT_QUERY_IFACE_KEYNAME = \
                        'ndg.security.server.wsgi.authzservice.queryInterface'
    
    ENVIRON_KEYNAME_QUERY_IFACE_OPTNAME = 'queryInterfaceKeyName'
    
    XACML_CTX_HANDLER_PARAM_PREFIX = 'ctx_handler.'
    
    # For loop based assignment where possible of config options in initialise()
    AUTHZ_SRVC_OPTION_DEFAULTS = {
        ENVIRON_KEYNAME_QUERY_IFACE_OPTNAME: DEFAULT_QUERY_IFACE_KEYNAME,
    }
    
    POLICY_FILEPATH_OPTNAME = 'policyFilePath'
    
    __slots__ = (
        '__xacmlCtxHandler',
        '__queryInterface', 
        '__' + ENVIRON_KEYNAME_QUERY_IFACE_OPTNAME,
        '_app',
    )
        
    def __init__(self, app):
        '''Set-up an Authorisation Service instance
        
        @param app: next app/middleware in WSGI stack
        @type app: callable
        '''
        self._app = app
        self.__xacmlCtxHandler = saml_ctx_handler.SamlCtxHandler()
        self.__queryInterface = None
        self.__queryInterfaceKeyName = None
        
    def initialise(self, prefix=DEFAULT_PARAM_PREFIX, **app_conf):
        """Set-up Authorization Service middleware from keyword settings
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        cls = AuthorisationServiceMiddleware
        
        # Loop based assignment where possible
        for optName, default in cls.AUTHZ_SRVC_OPTION_DEFAULTS.items():
            value = app_conf.get(prefix + optName, default)
            setattr(self, optName, value)
        
        self.queryInterface = self.createQueryInterface()    
        
        # Initialise the XACML Context handler.  This handles PEP requests and
        # PDP queries to the PIP
        ctxHandlerPrefix = prefix + cls.XACML_CTX_HANDLER_PARAM_PREFIX
        self.__xacmlCtxHandler = saml_ctx_handler.SamlCtxHandler.fromKeywords(
                                                ctxHandlerPrefix, **app_conf)
            
        # Initialise the XACML Context handler
        
    @classmethod
    def filter_app_factory(cls, app, global_conf, **app_conf):
        '''Wrapper to enable instantiation compatible with Paste Deploy
        filter application factory function signature
        
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
        app = cls(app)
        app.initialise(**app_conf)
        
        return app
    
    def __call__(self, environ, start_response):
        '''Set the Authorization Decision function in environ
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: next application in the WSGI stack
        '''
        environ[self.queryInterfaceKeyName] = self.queryInterface
        return self._app(environ, start_response)


    def _get_queryInterfaceKeyName(self):
        return self.__queryInterfaceKeyName

    def _set_queryInterfaceKeyName(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting %r for "getAuthzDecisionKeyName" '
                            'attribute; got %r' % (basestring, type(val)))
        self.__queryInterfaceKeyName = val
        
    queryInterfaceKeyName = property(fget=_get_queryInterfaceKeyName, 
                                     fset=_set_queryInterfaceKeyName, 
                                     doc="Key name used to index "
                                         "Authorization Service SAML authz "
                                         "decision query function in environ "
                                         "dictionary")
    
    def _get_queryInterface(self):
        return self.__queryInterface
    
    def _set_queryInterface(self, value):
        if isinstance(value, basestring):
            self.__queryInterface = importModuleObject(value)
            
        elif callable(value):
            self.__queryInterface = value
        else:
            raise TypeError('Expecting callable for "queryInterface" '
                            'attribute; got %r instead.' % type(value))
    
    queryInterface = property(_get_queryInterface,
                              _set_queryInterface,
                              doc="authorisation decision function set in "
                                  "environ for downstream SAML Query "
                                  "middleware to invoke in response to "
                                  "<authzDecisionQuery>s")
         
    def createQueryInterface(self):
        """Return the authorisation decision function so that __call__ can add
        it to environ for the SAML Query middleware to pick up and invoke
        
        @return: SAML authorisation decision function
        @rtype: callable
        """
        
        # Nest function within AuthorisationServiceMiddleware method so that 
        # self is in its scope
        def getAuthzDecision(authzDecisionQuery, samlResponse):
            """Authorisation decision function accepts a SAML AuthzDecisionQuery
            and calls the XACML context handler returning a response.  The
            context handler is an interface to the the XACML Policy Decision 
            Point, XACML polic(y|ies) and Policy Information Point.
            
            @type authzDecisionQuery: ndg.saml.saml2.core.AuthzDecisionQuery
            @param authzDecisionQuery: WSGI environment variables dictionary
            @rtype: ndg.saml.saml2.core.Response
            @return: SAML response containing Authorisation Decision Statement
            """
            # Create special request object which enables the context handler
            # to formulate a response from the query and the existing response
            # object initialised by this object
            request = saml_ctx_handler.SamlPEPRequest()
            request.authzDecisionQuery = authzDecisionQuery
            request.response = samlResponse
            
            response = self.__xacmlCtxHandler.handlePEPRequest(request)
            
            return response
            
        return getAuthzDecision
