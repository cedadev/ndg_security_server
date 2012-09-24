'''NDG Security Policy Enforcement Point Module

__author__ = "P J Kershaw"
__date__ = "11/07/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
'''
import logging
log = logging.getLogger(__name__)

import httplib
from time import time

import webob

from ndg.soap.client import UrlLib2SOAPClientError
from ndg.saml.saml2.core import DecisionType
from ndg.saml.saml2.binding.soap.client.requestbase import \
                                                        RequestBaseSOAPBinding
from ndg.saml.saml2.binding.soap.client.authzdecisionquery import \
                                            AuthzDecisionQuerySslSOAPBinding
                                            
from ndg.xacml.core import Identifiers as XacmlIdentifiers
from ndg.xacml.core import context as _xacmlCtx
from ndg.xacml.core.attribute import Attribute as XacmlAttribute
from ndg.xacml.core.attributevalue import (
    AttributeValueClassFactory as XacmlAttributeValueClassFactory, 
    AttributeValue as XacmlAttributeValue)
from ndg.xacml.core.context.result import Decision as XacmlDecision
from ndg.xacml.core.context.pdp import PDP
from ndg.xacml.parsers.etree.factory import (
    ReaderFactory as XacmlPolicyReaderFactory)
    
from ndg.security.server.wsgi.session import (SessionMiddlewareBase, 
                                              SessionHandlerMiddleware)
from ndg.security.common.credentialwallet import SAMLAssertionWallet
from ndg.security.common.utils import str2Bool


class SamlPepFilterConfigError(Exception):
    """Error with SAML PEP configuration settings"""
    
    
class SamlPepFilterBase(SessionMiddlewareBase):
    '''Policy Enforcement Point for ESG with SAML based Interface
    
    @requires: ndg.security.server.wsgi.session.SessionHandlerMiddleware 
    instance upstream in the WSGI stack.
    
    @cvar AUTHZ_DECISION_QUERY_PARAMS_PREFIX: prefix for SAML authorisation
    decision query options in config file
    @type AUTHZ_DECISION_QUERY_PARAMS_PREFIX: string
    
    @cvar PARAM_NAMES: list of config option names
    @type PARAM_NAMES: tuple
    
    @ivar __client: SAML authorisation decision query client 
    @type __client: ndg.saml.saml2.binding.soap.client.authzdecisionquery.AuthzDecisionQuerySslSOAPBinding
    '''
    AUTHZ_SERVICE_URI = 'authzServiceURI'
    AUTHZ_DECISION_QUERY_PARAMS_PREFIX = 'authzDecisionQuery.'
    SESSION_KEY_PARAM_NAME = 'sessionKey'
    CACHE_DECISIONS_PARAM_NAME = 'cacheDecisions'   
    LOCAL_POLICY_FILEPATH_PARAM_NAME = 'localPolicyFilePath'
    
    CREDENTIAL_WALLET_SESSION_KEYNAME = \
        SessionHandlerMiddleware.CREDENTIAL_WALLET_SESSION_KEYNAME
    USERNAME_SESSION_KEYNAME = \
        SessionHandlerMiddleware.USERNAME_SESSION_KEYNAME
    
    PARAM_NAMES = (
        AUTHZ_SERVICE_URI,
        SESSION_KEY_PARAM_NAME,
        CACHE_DECISIONS_PARAM_NAME,
        LOCAL_POLICY_FILEPATH_PARAM_NAME
    )
    
    XACML_ATTRIBUTEVALUE_CLASS_FACTORY = XacmlAttributeValueClassFactory()
    
    __slots__ = (
        '_app', '__client', '__session', '__localPdp'
    ) + tuple(('__' + '$__'.join(PARAM_NAMES)).split('$'))
            
    def __init__(self, app):
        '''
        Add reference to next WSGI middleware/app and create a SAML 
        authorisation decision query client interface
        '''
        self._app = app
        self.__client = AuthzDecisionQuerySslSOAPBinding()
        self.__session = None
        self.__authzServiceURI = None
        self.__sessionKey = None
        self.__cacheDecisions = False
        self.__localPdp = None
        self.__localPolicyFilePath = None

    def _getLocalPolicyFilePath(self):
        return self.__localPolicyFilePath

    def _setLocalPolicyFilePath(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "localPolicyFilePath" '
                            'attribute; got %r' % type(value))
            
        self.__localPolicyFilePath = value

    localPolicyFilePath = property(_getLocalPolicyFilePath, 
                                   _setLocalPolicyFilePath, 
                                   doc="Policy file path for local PDP. It's "
                                       "initialised to None in which case the "
                                       "local PDP is disabled and all access "
                                       "control queries will be routed through "
                                       "to the authorisation service")

    def _getLocalPdp(self):
        return self.__localPdp

    def _setLocalPdp(self, value):
        self.__localPdp = value

    localPdp = property(_getLocalPdp, _setLocalPdp, 
                        doc="File path for a local PDP which can be used to "
                            "filters requests from the authorisation service "
                            "so avoiding the web service call performance "
                            "penalty")

    def _getClient(self):
        return self.__client

    def _setClient(self, value):
        if not isinstance(value, RequestBaseSOAPBinding):
            raise TypeError('Expecting type %r for "client" attribute; '
                            'got %r' %
                            (type(RequestBaseSOAPBinding), type(value)))
        self.__client = value

    client = property(_getClient, _setClient, 
                      doc="SAML authorisation decision query SOAP client")

    def _getSession(self):
        return self.__session

    def _setSession(self, value):
        self.__session = value

    session = property(_getSession, _setSession, 
                       doc="Beaker Security Session instance")

    def _getAuthzServiceURI(self):
        return self.__authzServiceURI

    def _setAuthzServiceURI(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "authzServiceURI" '
                            'attribute; got %r' % type(value))
        self.__authzServiceURI = value

    authzServiceURI = property(_getAuthzServiceURI, _setAuthzServiceURI, 
                               doc="Authorisation Service URI")

    def _getSessionKey(self):
        return self.__sessionKey

    def _setSessionKey(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "sessionKey" attribute; '
                            'got %r' % type(value))
        self.__sessionKey = value

    sessionKey = property(_getSessionKey, _setSessionKey, 
                          doc="environ key name for Beaker session object")

    def _getCacheDecisions(self):
        return self.__cacheDecisions

    def _setCacheDecisions(self, value):
        if isinstance(value, basestring):
            self.__cacheDecisions = str2Bool(value)
        elif isinstance(value, bool):
            self.__cacheDecisions = value
        else:
            raise TypeError('Expecting bool/string type for "cacheDecisions" '
                            'attribute; got %r' % type(value))
        
    cacheDecisions = property(_getCacheDecisions, _setCacheDecisions, 
                              doc="Set to True to make the session cache "
                                  "authorisation decisions returned from the "
                                  "Authorisation Service")
    
    def initialise(self, prefix='', **kw):
        '''Initialise object from keyword settings
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type kw: dict        
        @param kw: configuration settings
        dictionary
        @raise SamlPepFilterConfigError: missing option setting(s)
        '''
        # Parse other options
        for name in SamlPepFilter.PARAM_NAMES:
            paramName = prefix + name
            value = kw.get(paramName)
            
            if value is not None:
                setattr(self, name, value)
                
            elif name != self.__class__.LOCAL_POLICY_FILEPATH_PARAM_NAME:
                # Policy file setting is optional
                raise SamlPepFilterConfigError('Missing option %r' % paramName)
            

        # Parse authorisation decision query options
        queryPrefix = prefix + self.__class__.AUTHZ_DECISION_QUERY_PARAMS_PREFIX
        self.client.parseKeywords(prefix=queryPrefix, **kw)

        # Initialise the local PDP  
        if self.localPolicyFilePath:
            self.__localPdp = PDP.fromPolicySource(self.localPolicyFilePath, 
                                                   XacmlPolicyReaderFactory)
                    
    @classmethod
    def filter_app_factory(cls, app, global_conf, prefix='', **app_conf):
        """Set-up using a Paste app factory pattern.  
        
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        app = cls(app)
        app.initialise(prefix=prefix, **app_conf)
        
        return app
                
    def __call__(self, environ, start_response):
        """Intercept request and call authorisation service to make an access
        control decision
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        """
        # Get reference to session object - SessionHandler middleware must be in
        # place upstream of this middleware in the WSGI stack
        if self.sessionKey not in environ:
            raise SamlPepFilterConfigError('No beaker session key "%s" found '
                                           'in environ' % self.sessionKey)
        self.session = environ[self.sessionKey]

        return self.enforce(environ, start_response)

    def enforce(self, environ, start_response):
        """Get access control decision from PDP(s) and enforce the decision
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        """
        raise NotImplementedError("SamlPepFilterBase must be subclassed to"
                                  " implement the enforce method.")

    def _retrieveCachedAssertions(self, resourceId):
        """Return assertions containing authorisation decision for the given
        resource ID.
        
        @param resourceId: search for decisions for this resource Id
        @type resourceId: basestring
        @return: assertion containing authorisation decision for the given
        resource ID or None if no wallet has been set or no assertion was 
        found matching the input resource Id
        @rtype: ndg.saml.saml2.core.Assertion / None type
        """
        # Get reference to wallet
        walletKeyName = self.__class__.CREDENTIAL_WALLET_SESSION_KEYNAME
        credWallet = self.session.get(walletKeyName)
        if credWallet is None:
            return None
        
        # Wallet has a dictionary of credential objects keyed by resource ID
        return credWallet.retrieveCredentials(resourceId)
        
    def _cacheAssertions(self, resourceId, assertions):
        """Cache an authorisation decision from a response retrieved from the 
        authorisation service.  This is invoked only if cacheDecisions boolean
        is set to True
        
        @param resourceId: search for decisions for this resource Id
        @type resourceId: basestring
        @param assertions: list of SAML assertions containing authorisation 
        decision statements
        @type assertions: iterable
        """
        walletKeyName = self.__class__.CREDENTIAL_WALLET_SESSION_KEYNAME
        credWallet = self.session.get(walletKeyName)
        if credWallet is None:
            credWallet = SAMLAssertionWallet()
            
            # Fix: make wallet follow the same clock skew tolerance and as the 
            # SAML authz decision query settings
            credWallet.clockSkewTolerance = self.client.clockSkewTolerance
        
        credWallet.addCredentials(resourceId, assertions)
        self.session[walletKeyName] = credWallet
        self.session.save()
        
    def saveResultCtx(self, request, response, save=True):
        """Set PEP context information in the Beaker session using standard key
        names.  This is a snapshot of the last request and the response 
        received.  It can be used by downstream middleware to provide contextual
        information about authorisation decisions
        
        @param session: beaker session
        @type session: beaker.session.SessionObject
        @param request: authorisation decision query
        @type request: ndg.saml.saml2.core.AuthzDecisionQuery
        @param response: authorisation response
        @type response: ndg.saml.saml2.core.Response
        @param save: determines whether session is saved or not
        @type save: bool
        """
        self.session[self.__class__.PEPCTX_SESSION_KEYNAME] = {
            self.__class__.PEPCTX_REQUEST_SESSION_KEYNAME: request, 
            self.__class__.PEPCTX_RESPONSE_SESSION_KEYNAME: response,
            self.__class__.PEPCTX_TIMESTAMP_SESSION_KEYNAME: time()
        }
        
        if save:
            self.session.save()     

    PDP_DENY_RESPONSES = (
        XacmlDecision.DENY_STR, XacmlDecision.INDETERMINATE_STR
    )
    
    def isApplicableRequest(self, resourceURI):
        """A local PDP can filter out some requests to avoid the need to call
        out to the authorisation service 
        
        @param resourceURI: URI of requested resource
        @type resourceURI: basestring
        """
        if self.__localPdp is None:
            log.debug("No Local PDP set: passing on request to main "
                      "authorisation service...")
            return True
        
        xacmlRequest = self._createXacmlRequestCtx(resourceURI)
        xacmlResponse = self.__localPdp.evaluate(xacmlRequest)
        for result in xacmlResponse.results:
            if result.decision.value != XacmlDecision.NOT_APPLICABLE_STR:
                log.debug("Local PDP returned %s decision, passing request on "
                          "to main authorisation service ...", 
                          result.decision.value)
                return True
            
        return False

    def _createXacmlRequestCtx(self, resourceURI):
        """Wrapper to create a request context for a local PDP - see 
        isApplicableRequest
        
        @param resourceURI: URI of requested resource
        @type resourceURI: basestring
        """
        request = _xacmlCtx.request.Request()
        
        resource = _xacmlCtx.request.Resource()
        resourceAttribute = XacmlAttribute()
        resource.attributes.append(resourceAttribute)
        
        resourceAttribute.attributeId = XacmlIdentifiers.Resource.RESOURCE_ID
                                        
        XacmlAnyUriAttributeValue = \
            self.__class__.XACML_ATTRIBUTEVALUE_CLASS_FACTORY(
                                            XacmlAttributeValue.ANY_TYPE_URI)
                                    
        resourceAttribute.dataType = XacmlAnyUriAttributeValue.IDENTIFIER
        resourceAttribute.attributeValues.append(XacmlAnyUriAttributeValue())
        resourceAttribute.attributeValues[-1].value = resourceURI

        request.resources.append(resource)
        
        return request
        
class SamlPepFilter(SamlPepFilterBase):

    def enforce(self, environ, start_response):
        """Get access control decision from PDP(s) and enforce the decision
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response
        """
        request = webob.Request(environ)
        requestURI = request.url
        # Nb. user may not be logged in hence REMOTE_USER is not set
        remoteUser = request.remote_user or ''
        
        # Apply local PDP if set
        if not self.isApplicableRequest(requestURI):
            # The local PDP has returned a decision that the requested URI is
            # not applicable and so the authorisation service need not be 
            # invoked.  This step is an efficiency measure to avoid multiple
            # callouts to the authorisation service for resources which 
            # obviously don't need any restrictions 
            return self._app(environ, start_response)
            
        # Check for cached decision
        if self.cacheDecisions:
            assertions = self._retrieveCachedAssertions(requestURI)
        else:
            assertions = None  
             
        noCachedAssertion = assertions is None or len(assertions) == 0
        if noCachedAssertion:
            # No stored decision in cache, invoke the authorisation service   
            query = self.client.makeQuery()
            query.resource = request.url
            self.client.setQuerySubjectId(query, remoteUser)
            
            try:
                samlAuthzResponse = self.client.send(query,
                                                     uri=self.authzServiceURI)
            except UrlLib2SOAPClientError, e:
                import traceback
                
                log.error("Error, HTTP %s response from authorisation service "
                          "%r requesting access to %r: %s", 
                          e.urllib2Response.code,
                          self.authzServiceURI, 
                          requestURI,
                          traceback.format_exc())
                
                response = webob.Response()
                response.status = httplib.FORBIDDEN
                response.body = ('An error occurred retrieving an access '
                                 'decision for %r for user %r' % 
                                 (requestURI, remoteUser))
                response.content_type = 'text/plain'
                return response(environ, start_response)
                         
            assertions = samlAuthzResponse.assertions
            
            # Record the result in the user's session to enable later 
            # interrogation by any result handler Middleware
            self.saveResultCtx(query, samlAuthzResponse)
        
        
        # Set HTTP 403 Forbidden response if any of the decisions returned are
        # deny or indeterminate status
        failDecisions = (DecisionType.DENY, DecisionType.INDETERMINATE)
        
        # Review decision statement(s) in assertions and enforce the decision
        assertion = None
        for assertion in assertions:
            for authzDecisionStatement in assertion.authzDecisionStatements:
                if authzDecisionStatement.decision.value in failDecisions:
                    response = webob.Response()
                    
                    if not remoteUser:
                        # Access failed and the user is not logged in
                        response.status = httplib.UNAUTHORIZED
                    else:
                        # The user is logged in but not authorised
                        response.status = httplib.FORBIDDEN
                        
                    response.body = 'Access denied to %r for user %r' % (
                                                                     requestURI,
                                                                     remoteUser)
                    response.content_type = 'text/plain'
                    log.info(response.body)
                    return response(environ, start_response)

        if assertion is None:
            log.error("No assertions set in authorisation decision response "
                      "from %r", self.authzServiceURI)
            
            response = webob.Response()
            response.status = httplib.FORBIDDEN
            response.body = ('An error occurred retrieving an access decision '
                             'for %r for user %r' % (
                                                                 requestURI,
                                                                 remoteUser))
            response.content_type = 'text/plain'
            log.info(response.body)
            return response(environ, start_response)     
               
        # Cache assertion if flag is set and it's one that's been freshly 
        # obtained from an authorisation decision query rather than one 
        # retrieved from the cache
        if self.cacheDecisions and noCachedAssertion:
            self._cacheAssertions(request.url, [assertion])
            
        # If got through to here then all is well, call next WSGI middleware/app
        return self._app(environ, start_response)
