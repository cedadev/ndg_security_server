'''NDG Security Policy Enforcement Point Module

__author__ = "P J Kershaw"
__date__ = "11/07/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: pep.py 7897 2011-04-27 11:02:23Z pjkersha $'
'''
import logging
log = logging.getLogger(__name__)

import httplib
import webob

from ndg.security.common.config import importElementTree
ElementTree = importElementTree()
from ndg.security.common.utils import str2Bool

from ndg.saml.saml2.core import DecisionType
from ndg.saml.saml2.binding.soap.client.xacmlauthzdecisionquery import \
                                        XACMLAuthzDecisionQuerySslSOAPBinding
from ndg.saml.saml2.xacml_profile import XACMLAuthzDecisionStatement
from ndg.saml.xml.etree import QName
import ndg.saml.xml.etree_xacml_profile as etree_xacml_profile

from ndg.xacml.core import Identifiers as XacmlIdentifiers
from ndg.xacml.core.attribute import Attribute as XacmlAttribute
from ndg.xacml.core.attributevalue import (
    AttributeValueClassFactory as XacmlAttributeValueClassFactory, 
    AttributeValue as XacmlAttributeValue)
    
import ndg.security.common.utils.etree as etree
from ndg.security.server.wsgi.authz.pep import SamlPepFilterConfigError
from ndg.security.server.wsgi.authz.pep import SamlPepFilterBase

from ndg.xacml.core.context.action import Action as XacmlAction
from ndg.xacml.core.context.environment import Environment as XacmlEnvironment
from ndg.xacml.core.context.request import Request as XacmlRequest
from ndg.xacml.core.context.resource import Resource as XacmlResource
from ndg.xacml.core.context.result import Decision as XacmlDecision
from ndg.xacml.core.context.subject import Subject as XacmlSubject
from ndg.xacml.core.context import XacmlContextBase


class XacmlSamlPepFilter(SamlPepFilterBase):
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
    SUBJECT_ID_FORMAT_PARAM_NAME = 'subjectIdFormat'

    PARAM_NAMES = [
        SUBJECT_ID_FORMAT_PARAM_NAME
    ]

    __slots__ = tuple(('__' + '$__'.join(PARAM_NAMES)).split('$'))

    def _getSubjectIdFormat(self):
        return self.__subjectIdFormat

    def _setSubjectIdFormat(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "subjectIdFormat" '
                            'attribute; got %r' % type(value))
        self.__subjectIdFormat = value

    subjectIdFormat = property(_getSubjectIdFormat, _setSubjectIdFormat, 
                          doc="Subject format ID to use in XACML subject "
                          "attribute")

    def _setCacheDecisions(self, value):
        """Override method from SamlPepFilterBase to prevent decision caching
        from being enabled since it doesn't work with the XACML profile request.
        """
        if isinstance(value, basestring):
            newValue = str2Bool(value)
        elif isinstance(value, bool):
            newValue = value
        else:
            raise TypeError('Expecting bool/string type for "cacheDecisions" '
                            'attribute; got %r' % type(value))
        if newValue != False:
            raise AttributeError('Caching of decisions cannot be enabled since '
                                 'it does not work in this version.')

    def initialise(self, prefix='', **kw):
        '''Initialise object from keyword settings
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type kw: dict        
        @param kw: configuration settings
        dictionary
        @raise SamlPepFilterConfigError: missing option setting(s)
        '''
        self.client = XACMLAuthzDecisionQuerySslSOAPBinding()
        # Additional parameter required for XAML profile:
        for name in self.__class__.PARAM_NAMES:
            paramName = prefix + name
            value = kw.get(paramName)
            
            if value is not None:
                setattr(self, name, value)
            else:
                raise SamlPepFilterConfigError(
                    'Missing option %r for XACML profile' % paramName)

        # Include XACML profile elements for element tree processing.
        etree_xacml_profile.setElementTreeMap()

        super(XacmlSamlPepFilter, self).initialise(prefix, **kw)

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
        
        # Apply local PDP if set
        if not self.isApplicableRequest(requestURI):
            # The local PDP has returned a decision that the requested URI is
            # not applicable and so the authorisation service need not be 
            # invoked.  This step is an efficiency measure to avoid multiple
            # callouts to the authorisation service for resources which 
            # obviously don't need any restrictions 
            return self._app(environ, start_response)

        # Check for cached decision
        # Note: 
        if self.cacheDecisions:
            assertions = self._retrieveCachedAssertions(requestURI)
        else:
            assertions = None  

        subjectID = request.remote_user or ''

        noCachedAssertion = assertions is None or len(assertions) == 0
        if noCachedAssertion:
            xacmlContextRequest = self._make_xacml_context_request(
                                            request.method,
                                            request.url,
                                            request.body_file_seekable.read(),
                                            subjectID,
                                            self.subjectIdFormat)
            self.client.query.xacmlContextRequest = xacmlContextRequest
            samlAuthzResponse = self.client.send(uri=self.authzServiceURI)
            assertions = samlAuthzResponse.assertions
            
            # SamlPepFilter has the following, which cannot be used here as
            # pickling of XACML requests fails (in Python 2.6.2)
            # Record the result in the user's session to enable later 
            # interrogation by any result handler Middleware
            # self.saveResultCtx(self.client.query, samlAuthzResponse)
        
        (assertion,
         error_status,
         error_message) = self._evaluate_assertions(assertions, subjectID,
                                                    requestURI,
                                                    self.authzServiceURI)
        if error_status is not None:
            response = webob.Response()
            response.status = error_status
            response.body = error_message
            response.content_type = 'text/plain'
            log.info(response.body)
            return response(environ, start_response)

        log.debug('Response contains permit assertion')

        # Cache assertion if flag is set and it's one that's been freshly 
        # obtained from an authorisation decision query rather than one 
        # retrieved from the cache
        if self.cacheDecisions and noCachedAssertion:
            self._cacheAssertions(request.url, [assertion])
            
        # If got through to here then all is well, call next WSGI middleware/app
        return self._app(environ, start_response)

    @classmethod
    def _make_xacml_context_request(cls, httpMethod, resourceURI,
                                    resourceContents, subjectID,
                                    subjectIdFormat, actions=None):
        """Create a XACML Request. Include post data as resource content if the
        HTTP method is POST.
        @type httpMethod: str
        @param httpMethod: HTTP method
        @type resourceURI: str
        @param resourceURI: resource URI
        @type resourceContents: basestr
        @param resourceContents: resource contents XML as string
        @type subjectID: str
        @param subjectID: subject ID
        @type subjectIdFormat: str
        @param subjectIdFormat: subject ID format
        @type actions: list of str
        @param actions: actions
        """
        if actions is None:
            actions = []
        if httpMethod == 'GET':
            ### TODO Should action be related to HTTP method?
            return cls._createXacmlProfileRequestCtx(subjectIdFormat,
                                                     subjectID, resourceURI,
                                                     None, actions)

        elif httpMethod == 'POST':
            resourceContentsElem = ElementTree.XML(resourceContents)
            tag = str(QName(XacmlContextBase.XACML_2_0_CONTEXT_NS,
                            XacmlResource.RESOURCE_CONTENT_ELEMENT_LOCAL_NAME))
            resourceContent = etree.makeEtreeElement(tag,
                                XacmlContextBase.XACML_2_0_CONTEXT_NS_PREFIX,
                                XacmlContextBase.XACML_2_0_CONTEXT_NS)
            resourceContent.append(resourceContentsElem)
    
            request = cls._createXacmlProfileRequestCtx(subjectIdFormat,
                                                        subjectID, resourceURI,
                                                        resourceContent,
                                                        actions)

            return request

    @staticmethod
    def _createXacmlProfileRequestCtx(subjectNameIdFormat, subjectNameId,
                                      resourceUri, resourceContent, actions):
        """Translate SAML authorisation decision query into a XACML request
        context
        @type subjectNameIdFormat: str
        @param subjectNameIdFormat: subject ID format
        @type subjectNameId: str
        @param subjectNameId: subject ID
        @type resourceUri: str
        @param resourceUri: resource URI
        @type resourceContent: ElementTree.Element
        @param resourceContent: data to include as resource content
        @type actions: list of str
        @param actions: action values
        """
        xacmlRequest = XacmlRequest()
        xacmlSubject = XacmlSubject()
        
        xacmlAttributeValueFactory = XacmlAttributeValueClassFactory()
        
        openidSubjectAttribute = XacmlAttribute()
        
        openidSubjectAttribute.attributeId = \
                                subjectNameIdFormat
                                        
        XacmlAnyUriAttributeValue = xacmlAttributeValueFactory(
                                            XacmlAttributeValue.ANY_TYPE_URI)
        
        openidSubjectAttribute.dataType = XacmlAnyUriAttributeValue.IDENTIFIER
        
        openidSubjectAttribute.attributeValues.append(
                                                    XacmlAnyUriAttributeValue())
        openidSubjectAttribute.attributeValues[-1].value = \
                                subjectNameId
        
        xacmlSubject.attributes.append(openidSubjectAttribute)

        XacmlStringAttributeValue = xacmlAttributeValueFactory(
                                            XacmlAttributeValue.STRING_TYPE_URI)
                                  
        xacmlRequest.subjects.append(xacmlSubject)
        
        resource = XacmlResource()
        resourceAttribute = XacmlAttribute()
        resource.attributes.append(resourceAttribute)
        if resourceContent is not None:
            resource.resourceContent = resourceContent
        
        resourceAttribute.attributeId = XacmlIdentifiers.Resource.RESOURCE_ID
                            
        resourceAttribute.dataType = XacmlAnyUriAttributeValue.IDENTIFIER
        resourceAttribute.attributeValues.append(XacmlAnyUriAttributeValue())
        resourceAttribute.attributeValues[-1].value = \
                                                resourceUri

        xacmlRequest.resources.append(resource)
        
        xacmlRequest.action = XacmlAction()
        
        for action in actions:
            xacmlActionAttribute = XacmlAttribute()
            xacmlRequest.action.attributes.append(xacmlActionAttribute)
            
            xacmlActionAttribute.attributeId = XacmlIdentifiers.Action.ACTION_ID
            xacmlActionAttribute.dataType = XacmlStringAttributeValue.IDENTIFIER
            xacmlActionAttribute.attributeValues.append(
                                                    XacmlStringAttributeValue())
            xacmlActionAttribute.attributeValues[-1].value = action.value

        xacmlRequest.environment = XacmlEnvironment()

        return xacmlRequest

    @staticmethod
    def _evaluate_assertions(assertions, subjectID, requestURI,
                             authzServiceURI):
        """Evaluates the assertions from a SAML authorisation response and
        returns either a HTTP status and message indicating that access is not
        granted or the assertion permitting access.
        @type assertions: list of ndg.saml.xml.etree.AssertionElementTree
        @param assertions: assertions to evaluate
        @type subjectID: str
        @param subjectID: subject used in request
        @type requestURI: str
        @param requestURI: request URI
        @type authzServiceURI: str
        @param authzServiceURI: authorisation service URI used for request
        @rtype: tuple (
          ndg.saml.xml.etree.AssertionElementTree,
          int,
          str)
        @return: (
          assertion if access permitted or None
          HTTP status if access not permitted or None
          error message if access not permitted or None
        """
        error_status = None
        error_message = None

        # Set HTTP 403 Forbidden response if any of the decisions returned are
        # deny or indeterminate status
        failDecisions = (DecisionType.DENY, DecisionType.INDETERMINATE)
        ### TODO What should be done with NOT_APPLICABLE decision?
        xacmlFailDecisions = [XacmlDecision.DENY, XacmlDecision.INDETERMINATE,
                              XacmlDecision.NOT_APPLICABLE]
        
        # Review decision statement(s) in assertions and enforce the decision
        assertion = None
        invalid_response = False
        for assertion in assertions:
            for statement in assertion.statements:
                if not isinstance(statement, XACMLAuthzDecisionStatement):
                    # Unexpected statement type
                    invalid_response = True
                    break
                results = statement.xacmlContextResponse.results
                # Should be one result as only supplying one resource in the
                # request.
                if len(results) != 1:
                    invalid_response = True

                if results[0].decision in xacmlFailDecisions:
                    if not subjectID:
                        # Access failed and the user is not logged in
                        error_status = httplib.UNAUTHORIZED
                    else:
                        # The user is logged in but not authorised
                        error_status = httplib.FORBIDDEN

                    error_message = 'Access denied to %r for user %r' % (
                                                                     requestURI,
                                                                     subjectID)
                    return (None, error_status, error_message)

            ### TODO Is a non-XACML-profile response permitted?
            for authzDecisionStatement in assertion.authzDecisionStatements:
                if authzDecisionStatement.decision.value in failDecisions:
                    if not subjectID:
                        # Access failed and the user is not logged in
                        error_status = httplib.UNAUTHORIZED
                    else:
                        # The user is logged in but not authorised
                        error_status = httplib.FORBIDDEN
                        
                    error_message = 'Access denied to %r for user %r' % (
                                                     requestURI,
                                                     subjectID)
                    return (None, error_status, error_message)

            if invalid_response:
                error_status = httplib.INTERNAL_SERVER_ERROR
                error_message = 'Unexpected response from security service'
                return (None, error_status, error_message)

        if assertion is None:
            log.error("No assertions set in authorisation decision response "
                      "from %r", authzServiceURI)

            error_status = httplib.FORBIDDEN
            error_message = ('An error occurred retrieving an access decision '
                             'for %r for user %r' % (
                                             requestURI,
                                             subjectID))
            return (None, error_status, error_message)
        return (assertion, None, None)
