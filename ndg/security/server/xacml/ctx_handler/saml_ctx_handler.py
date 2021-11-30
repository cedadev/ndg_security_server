"""XACML Context handler translates to and from SAML Authorisation Decision
Query / Response

"""
__author__ = "P J Kershaw"
__date__ = "14/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

from os import path
from configparser import SafeConfigParser, ConfigParser
from datetime import datetime, timedelta
from uuid import uuid4

from ndg.saml.saml2 import core as _saml
from ndg.saml.common import SAMLVersion
from ndg.saml.saml2.xacml_profile import (XACMLAuthzDecisionQuery,
                                          XACMLAuthzDecisionStatement)

from ndg.xacml.core import Identifiers
from ndg.xacml.core.context.pdp import PDP
from ndg.xacml.core import context as _xacmlContext
from ndg.xacml.core.attribute import Attribute as XacmlAttribute
from ndg.xacml.core.attributevalue import (
    AttributeValueClassFactory as XacmlAttributeValueClassFactory, 
    AttributeValue as XacmlAttributeValue)
from ndg.xacml.parsers.etree.factory import ReaderFactory as \
    XacmlPolicyReaderFactory
from ndg.xacml.utils.xpath_selector import EtreeXPathSelector

from ndg.security.server.xacml.pip.saml_pip import PIP
from ndg.security.common.utils.factory import importModuleObject


class SamlPEPRequest(object):
    """Helper class for SamlCtxHandler.handlePEPRequest"""
    __slots__ = ('__authzDecisionQuery', '__response', '__policyFilePath')
    
    def __init__(self):
        self.__authzDecisionQuery = None
        self.__response = None
    
    def _getAuthzDecisionQuery(self):
        return self.__authzDecisionQuery

    def _setAuthzDecisionQuery(self, value):
        if not (isinstance(value, _saml.AuthzDecisionQuery) or
                isinstance(value, XACMLAuthzDecisionQuery)):
            raise TypeError('Expecting %r or %r type for "authzDecisionQuery" '
                            'attribute, got %r' %
                            (_saml.AuthzDecisionQuery, XACMLAuthzDecisionQuery,
                             type(value)))
        self.__authzDecisionQuery = value
        
    authzDecisionQuery = property(_getAuthzDecisionQuery, 
                                  _setAuthzDecisionQuery, 
                                  doc="SAML Authorisation Decision Query")

    def _getResponse(self):
        return self.__response

    def _setResponse(self, value):
        if not isinstance(value, _saml.Response):
            raise TypeError('Expecting %r type for "response" attribute, got %r'
                            % (_saml.Response, type(value)))
        self.__response = value

    response = property(_getResponse, _setResponse, doc="SAML Response")
   
        
class SamlCtxHandler(_xacmlContext.handler.CtxHandlerBase):
    """XACML Context handler for accepting SAML 2.0 based authorisation
    decision queries and interfacing to a PEP with SAML based Attribute Query
    Interface
    """
    DEFAULT_OPT_PREFIX = 'saml_ctx_handler.'
    PIP_OPT_PREFIX = 'pip.'
    
    __slots__ = (
        '__policyFilePath',
        '__issuerProxy', 
        '__assertionLifetime',
        '__xacmlExtFunc'
    )
    
    def __init__(self):
        super(SamlCtxHandler, self).__init__()
        
        # Proxy object for SAML AuthzDecisionQueryResponse Issuer attributes.  
        # By generating a proxy the Response objects inherent attribute 
        # validation can be applied to Issuer related config parameters before 
        # they're assigned to the response issuer object generated in the 
        # authorisation decision query response
        self.__issuerProxy = _saml.Issuer()
        self.__assertionLifetime = 0.
        self.__policyFilePath = None
        self.__xacmlExtFunc = None

    def _getXacmlExtFunc(self):
        """Get XACML extensions functions"""
        return self.__xacmlExtFunc

    def _setXacmlExtFunc(self, value):
        """Set XACML extensions functions"""
        self.__xacmlExtFunc = []
        if isinstance(value, str):
            for fnspec in value.split():
                log.debug("XACML extension function: %s", fnspec)
                self.__xacmlExtFunc.append(importModuleObject(fnspec))
            
        elif callable(value):
            self.__xacmlExtFunc.append(value)
        else:
            try:
                for fn in value:
                    if callable(fn):
                        self.__xacmlExtFunc.append(fn)
                    else:
                        raise TypeError(
                            'Expecting module object import path strings or '
                            'callable/callable list; got %r' % type(value))
            except TypeError:
                raise TypeError(
                            'Expecting module object import path strings or '
                            'callable/callable list; got %r' % type(value))
            
    xacmlExtFunc = property(_getXacmlExtFunc, _setXacmlExtFunc, 
                            doc="Function or other callable which will be "
                                "called to set any XACML specific "
                                "extensions such as new custom attribute value "
                                "types.  The function should accept no input "
                                "arguments and any return value is ignored")   
    
    def load(self):
        """Load Policy file, mapping file and extensions functions.  In each
        case load only if they're set.
        """  
        # This must be called first before the policy is loaded so that any
        # new custom types are added before a parse is attempted.          
        if self.xacmlExtFunc:
            for fn in self.xacmlExtFunc:
                fn()
            
        if self.policyFilePath:
            self.pdp = PDP.fromPolicySource(self.policyFilePath, 
                                            XacmlPolicyReaderFactory)
        
        if self.pip.mappingFilePath:
            self.pip.readMappingFile()
        
    @classmethod
    def fromConfig(cls, cfg, **kw):
        '''Alternative constructor makes object from config file settings
        @type cfg: basestring /ConfigParser derived type
        @param cfg: configuration file path or ConfigParser type object
        @rtype: ndg.security.server.xacml.ctx_handler.saml_ctx_handler
        @return: new instance of this class
        '''
        obj = cls()
        obj.parseConfig(cfg, **kw)
        
        # Post initialisation steps - load policy and PIP mapping file
        obj.load()
           
        return obj

    def parseConfig(self, cfg, prefix=DEFAULT_OPT_PREFIX, section='DEFAULT'):
        '''Read config settings from a file, config parser object or dict
        
        @type cfg: basestring / ConfigParser derived type / dict
        @param cfg: configuration file path or ConfigParser type object
        @type prefix: basestring
        @param prefix: prefix for option names e.g. "attributeQuery."
        @type section: basetring
        @param section: configuration file section from which to extract
        parameters.
        '''  
        if isinstance(cfg, str):
            cfgFilePath = path.expandvars(cfg)
            
            # Add a 'here' helper option for setting dir paths in the config
            # file
            hereDir = path.abspath(path.dirname(cfgFilePath))
            _cfg = SafeConfigParser(defaults={'here': hereDir})
            
            # Make option name reading case sensitive
            _cfg.optionxform = str
            _cfg.read(cfgFilePath)
            items = _cfg.items(section)
            
        elif isinstance(cfg, ConfigParser):
            items = cfg.items(section)
         
        elif isinstance(cfg, dict):
            items = list(cfg.items())     
        else:
            raise AttributeError('Expecting basestring, ConfigParser or dict '
                                 'type for "cfg" attribute; got %r type' % 
                                 type(cfg))
        
        self.__parseFromItems(items, prefix=prefix)
        
    def __parseFromItems(self, items, prefix=DEFAULT_OPT_PREFIX): 
        """Update from list of tuple name, value pairs - for internal use
        by parseKeywords and parseConfig
        """
        prefixLen = len(prefix) 
        pipPrefix = self.__class__.PIP_OPT_PREFIX
        pipPrefixLen = len(pipPrefix)
        
        def _setAttr(__optName):
            """Convenience function to check for PIP attribute related items
            """
            if __optName.startswith(pipPrefix):
                if self.pip is None:    
                    # Create Policy Information Point so that settings can be 
                    # assigned
                    self.pip = PIP()
                    
                setattr(self.pip, __optName[pipPrefixLen:], val)
            else:
                setattr(self, __optName, val)
                
        for optName, val in items:
            if prefix:
                # Filter attributes based on prefix
                if optName.startswith(prefix):
                    _optName = optName[prefixLen:]
                    _setAttr(_optName)
            else:
                # No prefix set - attempt to set all attributes   
                _setAttr(optName)
        
    def parseKeywords(self, prefix=DEFAULT_OPT_PREFIX, **kw):
        """Update object from input keywords
        
        @type prefix: basestring
        @param prefix: if a prefix is given, only update self from kw items 
        where keyword starts with this prefix
        @type kw: dict
        @param kw: items corresponding to class instance variables to 
        update.  Keyword names must match their equivalent class instance 
        variable names.  However, they may prefixed with <prefix>
        """
        self.__parseFromItems(list(kw.items()), prefix=prefix)
                
    @classmethod
    def fromKeywords(cls, prefix=DEFAULT_OPT_PREFIX, **kw):
        """Create a new instance initialising instance variables from the 
        keyword inputs
        @type prefix: basestring
        @param prefix: if a prefix is given, only update self from kw items 
        where keyword starts with this prefix
        @type kw: dict
        @param kw: items corresponding to class instance variables to 
        update.  Keyword names must match their equivalent class instance 
        variable names.  However, they may prefixed with <prefix>
        @return: new instance of this class
        @rtype: ndg.saml.saml2.binding.soap.client.SOAPBinding or derived type
        """
        obj = cls()
        obj.parseKeywords(prefix=prefix, **kw)
        
        # Post initialisation steps - load policy and PIP mapping file
        obj.load()
                       
        return obj
                                       
    def _getPolicyFilePath(self):
        return self.__policyFilePath

    def _setPolicyFilePath(self, value):
        if not isinstance(value, str):
            raise TypeError('Expecting string type for "policyFilePath"; got '
                            '%r' % type(value))
        self.__policyFilePath = path.expandvars(value)

    policyFilePath = property(_getPolicyFilePath, 
                              _setPolicyFilePath, 
                              doc="Policy file path for policy used by the PDP")
       
    def _getIssuerFormat(self):
        if self.__issuerProxy is None:
            return None
        else:
            return self.__issuerProxy.format

    def _setIssuerFormat(self, value):
        if self.__issuerProxy is None:
            self.__issuerProxy = _saml.Issuer()
            
        self.__issuerProxy.format = value

    issuerFormat = property(_getIssuerFormat, _setIssuerFormat, 
                            doc="Issuer format of SAML Authorisation Query "
                                "Response")

    def _getIssuerName(self):
        if self.__issuerProxy is None:
            return None
        else:
            return self.__issuerProxy.value

    def _setIssuerName(self, value):
        if self.__issuerProxy is None:
            self.__issuerProxy = _saml.Issuer()
            
        self.__issuerProxy.value = value

    issuerName = property(_getIssuerName, _setIssuerName, 
                          doc="Name of issuer of SAML Authorisation Query "
                              "Response")
    
    _getAssertionLifetime = lambda self: self.__assertionLifetime
    
    def _setAssertionLifetime(self, value):
        if isinstance(value, (int, float, str)):
            self.__assertionLifetime = float(value)
        else:
            raise TypeError('Expecting int, long, float or string type for '
                            '"assertionLifetime" attribute; got %s instead' % 
                            type(value))

    assertionLifetime = property(fget=_getAssertionLifetime,
                                 fset=_setAssertionLifetime,
                                 doc="lifetime of assertion in seconds used to "
                                     "set assertion conditions notOnOrAfter "
                                     "time")
 
    def handlePEPRequest(self, pepRequest):
        """Handle request from Policy Enforcement Point
        
        @param pepRequest: request containing a SAML authorisation decision
        query and optionally an initialised SAML response object
        @type pepRequest: ndg.security.server.xacml.saml_ctx_handler.SamlPEPRequest
        @return: SAML authorisation decision response
        @rtype: ndg.saml.saml2.core.Response
        """
        samlAuthzDecisionQuery = pepRequest.authzDecisionQuery

        xacml_profile = isinstance(samlAuthzDecisionQuery,
                                   XACMLAuthzDecisionQuery)
        if xacml_profile:
            # Using XACML profile so the Request is passed in the query.
            xacmlRequest = samlAuthzDecisionQuery.xacmlContextRequest
        else:
            xacmlRequest = self._createXacmlRequestCtx(samlAuthzDecisionQuery)
        
        # Add a reference to this context so that the PDP can invoke queries
        # back to the PIP
        xacmlRequest.ctxHandler = self

        # Set XPath implementation for attribute selector.
        ### TODO make this configurable?
        if xacmlRequest.elem is not None:
            xacmlRequest.attributeSelector = EtreeXPathSelector(
                                                            xacmlRequest.elem)

        # Call the PDP
        xacmlResponse = self.pdp.evaluate(xacmlRequest)
        
        # Create the SAML Response
        samlResponse, assertion = self._createSAMLResponseAssertion(
                                    samlAuthzDecisionQuery, pepRequest.response)

        # Add decision statement to assertion.
        if xacml_profile:
            # Using XACML profile so the Response is returned in the decision
            # statement.
            self._createXacmlAuthzDecisionStatement(assertion,
                                                    samlAuthzDecisionQuery,
                                                    xacmlResponse)
        else:
            self._createSamlAuthzDecisionStatement(assertion,
                                                   samlAuthzDecisionQuery,
                                                   xacmlResponse)

        return samlResponse
        
    def pipQuery(self, request, designator):
        """Implements interface method:
        
        Query a Policy Information Point to retrieve the attribute values
        corresponding to the specified input designator.  Optionally, update the
        request context.  This could be a subject, environment or resource.  
        Matching attributes values are returned
        
        @param request: request context
        @type request: ndg.xacml.core.context.request.Request
        @param designator: designator requiring additional subject attribute 
        information
        @type designator: ndg.xacml.core.expression.Expression derived type
        @return: list of attribute values for subject corresponding to given
        policy designator.  Return None if none can be found or if no PIP has
        been assigned to this handler
        @rtype: ndg.xacml.utils.TypedList(<designator attribute type>) / None
        type
        """
        if self.pip is None:
            return None
        else:
            return self.pip.attributeQuery(request, designator)
    
    def _createXacmlRequestCtx(self, samlAuthzDecisionQuery):
        """Translate SAML authorisation decision query into a XACML request
        context
        @param authzDecisionQuery: SAML Authorisation Decision Query
        @type authzDecisionQuery: ndg.saml.saml2.core.AuthzDecisionQuery
        """
        xacmlRequest = _xacmlContext.request.Request()
        xacmlSubject = _xacmlContext.subject.Subject()
        
        xacmlAttributeValueFactory = XacmlAttributeValueClassFactory()
        
        openidSubjectAttribute = XacmlAttribute()
        
        openidSubjectAttribute.attributeId = \
                                samlAuthzDecisionQuery.subject.nameID.format
                                        
        XacmlAnyUriAttributeValue = xacmlAttributeValueFactory(
                                            XacmlAttributeValue.ANY_TYPE_URI)
        
        openidSubjectAttribute.dataType = XacmlAnyUriAttributeValue.IDENTIFIER
        
        openidSubjectAttribute.attributeValues.append(
                                                    XacmlAnyUriAttributeValue())
        openidSubjectAttribute.attributeValues[-1].value = \
                                samlAuthzDecisionQuery.subject.nameID.value
        
        xacmlSubject.attributes.append(openidSubjectAttribute)

        XacmlStringAttributeValue = xacmlAttributeValueFactory(
                                            XacmlAttributeValue.STRING_TYPE_URI)
                                  
        xacmlRequest.subjects.append(xacmlSubject)
        
        resource = _xacmlContext.resource.Resource()
        resourceAttribute = XacmlAttribute()
        resource.attributes.append(resourceAttribute)
        
        resourceAttribute.attributeId = Identifiers.Resource.RESOURCE_ID
                            
        resourceAttribute.dataType = XacmlAnyUriAttributeValue.IDENTIFIER
        resourceAttribute.attributeValues.append(XacmlAnyUriAttributeValue())
        resourceAttribute.attributeValues[-1].value = \
                                                samlAuthzDecisionQuery.resource

        xacmlRequest.resources.append(resource)
        
        xacmlRequest.action = _xacmlContext.action.Action()
        
        for action in samlAuthzDecisionQuery.actions:
            xacmlActionAttribute = XacmlAttribute()
            xacmlRequest.action.attributes.append(xacmlActionAttribute)
            
            xacmlActionAttribute.attributeId = Identifiers.Action.ACTION_ID
            xacmlActionAttribute.dataType = XacmlStringAttributeValue.IDENTIFIER
            xacmlActionAttribute.attributeValues.append(
                                                    XacmlStringAttributeValue())
            xacmlActionAttribute.attributeValues[-1].value = action.value
        
        return xacmlRequest
    
    def _createSAMLResponseAssertion(self, authzDecisionQuery, response):
        """Helper method to add an assertion containing an Authorisation
        Decision Statement to the SAML response
        
        @param authzDecisionQuery: SAML Authorisation Decision Query
        @type authzDecisionQuery: ndg.saml.saml2.core.AuthzDecisionQuery
        @param response: SAML response
        @type response: ndg.saml.saml2.core.Response
        """
        
        # Check for a response set, if none present create one.
        if response is None:
            response = _saml.Response()
            
            now = datetime.utcnow()
            response.issueInstant = now
            
            # Make up a request ID that this response is responding to
            response.inResponseTo = authzDecisionQuery.id
            response.id = str(uuid4())
            response.version = SAMLVersion(SAMLVersion.VERSION_20)
                
            response.issuer = _saml.Issuer()
            response.issuer.format = self.issuerFormat
            response.issuer.value = self.issuerName
    
            response.status = _saml.Status()
            response.status.statusCode = _saml.StatusCode()
            response.status.statusMessage = _saml.StatusMessage()        
            
            response.status.statusCode.value = _saml.StatusCode.SUCCESS_URI
            response.status.statusMessage.value = ("Response created "
                                                   "successfully")
        
        assertion = _saml.Assertion()
        response.assertions.append(assertion)
           
        assertion.version = SAMLVersion(SAMLVersion.VERSION_20)
        assertion.id = str(uuid4())
        
        assertion.issuer = _saml.Issuer()
        assertion.issuer.value = self.issuerName
        assertion.issuer.format = self.issuerFormat
        
        now = datetime.utcnow()
        assertion.issueInstant = now
        
        # Add a conditions statement for a validity of 8 hours
        assertion.conditions = _saml.Conditions()
        assertion.conditions.notBefore = now
        assertion.conditions.notOnOrAfter = now + timedelta(
                                                seconds=self.assertionLifetime)
        ### TODO Better way to do this?
        if hasattr(authzDecisionQuery, 'subject'):
            assertion.subject = _saml.Subject()
            assertion.subject.nameID = _saml.NameID()
            assertion.subject.nameID.format = \
                authzDecisionQuery.subject.nameID.format
            assertion.subject.nameID.value = \
                authzDecisionQuery.subject.nameID.value
        
        return (response, assertion)

    def _createSamlAuthzDecisionStatement(self, assertion, authzDecisionQuery,
                                          xacmlResponse):
        """Adds an AuthzDecisionStatement to an assertion, converting the XACML
        response decision to a SAML decision.
        @param assertion: SAML assertion
        @type assertion: ndg.saml.saml2.core.Assertion
        @param authzDecisionQuery: SAML Authorisation Decision Query
        @type authzDecisionQuery: ndg.saml.saml2.core.AuthzDecisionQuery
        @param xacmlResponse: XACML response
        @type xacmlResponse: ndg.xacml.core.context.Response
        """
        samlAuthzDecisionStatement = _saml.AuthzDecisionStatement()
        assertion.authzDecisionStatements.append(samlAuthzDecisionStatement)

        samlAuthzDecisionStatement.resource = authzDecisionQuery.resource

        for action in authzDecisionQuery.actions:
            samlAuthzDecisionStatement.actions.append(_saml.Action())
            samlAuthzDecisionStatement.actions[-1].namespace = action.namespace
            samlAuthzDecisionStatement.actions[-1].value = action.value

        # Convert the decision status
        if (xacmlResponse.results[0].decision ==
            _xacmlContext.result.Decision.PERMIT):
            log.info("PDP granted access for URI path [%s]",
                     authzDecisionQuery.resource)

            samlAuthzDecisionStatement.decision = _saml.DecisionType.PERMIT

        # Nb. Mapping XACML NotApplicable => SAML INDETERMINATE
        elif (xacmlResponse.results[0].decision in
              (_xacmlContext.result.Decision.INDETERMINATE,
               _xacmlContext.result.Decision.NOT_APPLICABLE)):
            log.info("PDP returned a status of [%s] for URI path [%s]; "
                     "mapping to SAML response [%s] ...", 
                     xacmlResponse.results[0].decision,
                     authzDecisionQuery.resource,
                     _saml.DecisionType.INDETERMINATE)

            samlAuthzDecisionStatement.decision = \
                                                _saml.DecisionType.INDETERMINATE
        else:
            log.info("PDP returned a status of [%s] denying access for URI "
                     "path [%s]", _xacmlContext.result.Decision.DENY,
                     authzDecisionQuery.resource)

            samlAuthzDecisionStatement.decision = _saml.DecisionType.DENY

    def _createXacmlAuthzDecisionStatement(self, assertion,
                                           authzDecisionQuery,
                                           xacmlResponse):
        """Adds an AuthzDecisionStatement to an assertion including the XACML
        response.
        @param assertion: SAML assertion
        @type assertion: ndg.saml.saml2.core.Assertion
        @param authzDecisionQuery: SAML Authorisation Decision Query
        @type authzDecisionQuery: ndg.saml.saml2.core.AuthzDecisionQuery
        @param xacmlResponse: XACML response
        @type xacmlResponse: ndg.xacml.core.context.Response
        """
        authzDecisionStatement = XACMLAuthzDecisionStatement()
        authzDecisionStatement.xacmlContextResponse = xacmlResponse
        if authzDecisionQuery.returnContext:
            authzDecisionStatement.xacmlContextRequest = \
                                        authzDecisionQuery.xacmlContextRequest
                                        
        assertion.statements.append(authzDecisionStatement)
