"""XACML 2.0 profile for SAML 2.0 module

NERC DataGrid Project
"""
__author__ = "R B Wilkinson"
__date__ = "23/12/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

from ndg.saml.common.xml import SAMLConstants, QName
from ndg.saml.saml2.core import RequestAbstractType, Statement

from ndg.xacml.core.context.request import Request
from ndg.xacml.core.context.response import Response


class XACMLAuthzDecisionQuery(RequestAbstractType):
    '''SAML 2.0 XACML Profile XACMLAuthzDecisionQuery
    
    @cvar DEFAULT_ELEMENT_LOCAL_NAME: Element local name.
    @type DEFAULT_ELEMENT_LOCAL_NAME: string
    @cvar DEFAULT_ELEMENT_NAME: Default element name.
    @type DEFAULT_ELEMENT_NAME: string
    @cvar TYPE_LOCAL_NAME: Local name of the XSI type.
    @type TYPE_LOCAL_NAME: string
    @cvar TYPE_NAME: QName of the XSI type.
    @type TYPE_NAME: string
    @cvar RETURN_CONTEXT_ATTRIB_NAME: ReturnContext attribute name.
    @type RETURN_CONTEXT_ATTRIB_NAME: string
   
    @ivar inputContextOnly: InputContextOnly attribute value.
    @type inputContextOnly: bool
    @ivar returnContext: ReturnContext attribute value.
    @type returnContext: bool
    @ivar xacmlContextRequest: XACML context request
    @type xacmlContextRequest: ndg.xacml.core.context.request.Request
    '''

    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "XACMLAuthzDecisionQuery"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML2_XACML_PROTOCOL_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML2_XACML_PROTOCOL_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "XACMLAuthzDecisionQueryType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML2_XACML_PROTOCOL_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML2_XACML_PROTOCOL_PREFIX)

    # InputContextOnly attribute name
    INPUT_CONTEXT_ONLY_ATTRIB_NAME = "InputContextOnly"

    # ReturnContext attribute name
    RETURN_CONTEXT_ATTRIB_NAME = "ReturnContext"

    __slots__ = (
       '__inputContextOnly',
       '__returnContext',
       '__xacmlContextRequest'
    )
    
    def __init__(self):
        '''Create new authorisation decision query
        '''
        super(XACMLAuthzDecisionQuery, self).__init__()

        # Input context only attribute value
        self.__inputContextOnly = None
    
        # Return context attribute value
        self.__returnContext = None

        # XACML request context child element
        self.__xacmlContextRequest = None

    def __getstate__(self):
        '''Enable pickling
        
        @return: object's attribute dictionary
        @rtype: dict
        '''
        _dict = super(XACMLAuthzDecisionQuery, self).__getstate__()
        for attrName in XACMLAuthzDecisionQuery.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_XACMLAuthzDecisionQuery" + attrName
                
            _dict[attrName] = getattr(self, attrName)
            
        return _dict

    def _getInputContextOnly(self):
        '''Get the InputContextOnly attribute value of this query

        @return: InputContextOnly value
        @rtype: bool
        '''
        return self.__inputContextOnly
    
    def _setInputContextOnly(self, value):
        '''Sets the InputContextOnly attribute value of this query.
        
        @param value: the new InputContextOnly attribute value
        @type value: bool
        @raise TypeError: if incorrect input type 
        '''
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "InputContextOnly" '
                            'attribute; got %r instead' % type(value))
        
        self.__inputContextOnly = value
    
    inputContextOnly = property(fget=_getInputContextOnly,
                                fset=_setInputContextOnly,
                                doc="Determines whether the decision is made "
                                "using information in the decision query only "
                                "- unused")

    def _getReturnContext(self):
        '''Get the ReturnContext attribute value of this query

        @return: ReturnContext value
        @rtype: bool
        '''
        return self.__returnContext
    
    def _setReturnContext(self, value):
        '''Sets the ReturnContext attribute value of this query.
        
        @param value: the new ReturnContext attribute value
        @type value: bool
        @raise TypeError: if incorrect input type 
        '''
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "ReturnContext" '
                            'attribute; got %r instead' % type(value))
        
        self.__returnContext = value
    
    returnContext = property(fget=_getReturnContext,
                             fset=_setReturnContext,
                            doc="Determines whether the request context is"
                            "response")

    def _getXacmlContextRequest(self):
        '''
        Gets the XACML context request.

        @rtype: 
        @return: XACML context request
        '''
        return self.__xacmlContextRequest

    def _setXacmlContextRequest(self, value):
        '''
        Sets the XacmlContextRequest.

        @param value: XacmlContextRequest
        @raise TypeError: input value is incorrect type
        '''
        if not isinstance(value, Request):
            raise TypeError('Expecting %r type for "decision" attribute; '
                            'got %r instead' % (Request, type(value)))
        self.__xacmlContextRequest = value

    xacmlContextRequest = property(_getXacmlContextRequest,
                                   _setXacmlContextRequest, 
                                   doc="XACML context request")

    def getOrderedChildren(self):
        '''Return attributes for this element as a tuple

        @return: attributes for this element
        @rtype: tuple
        '''
        children = []

        superChildren = super(XACMLAuthzDecisionQuery, self).getOrderedChildren()
        if superChildren:
            children.extend(superChildren)

        children.extend(self.__xacmlContextRequest)

        if len(children) == 0:
            return None

        return tuple(children)


class XACMLAuthzDecisionStatement(Statement):
    '''SAML 2.0 XACML Profile XACMLAuthzDecisionQuery
    
    @cvar DEFAULT_ELEMENT_LOCAL_NAME: Element local name.
    @type DEFAULT_ELEMENT_LOCAL_NAME: string
    @cvar DEFAULT_ELEMENT_NAME: Default element name.
    @type DEFAULT_ELEMENT_NAME: string
    @cvar TYPE_LOCAL_NAME: Local name of the XSI type.
    @type TYPE_LOCAL_NAME: string
    @cvar TYPE_NAME: QName of the XSI type.
    @type TYPE_NAME: string
    '''

    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "XACMLAuthzDecisionStatement"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML2_XACML_ASSERTION_NS,
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML2_XACML_ASSERTION_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "XACMLAuthzDecisionStatementType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML2_XACML_ASSERTION_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML2_XACML_ASSERTION_PREFIX)
    __slots__ = (
        '__xacmlContextRequest',
        '__xacmlContextResponse'
    )
    
    def __init__(self):
        '''Create new authorisation decision statement
        '''
        super(XACMLAuthzDecisionStatement, self).__init__(
                    namespaceURI=SAMLConstants.SAML2_XACML_ASSERTION_NS, 
                    namespacePrefix=SAMLConstants.SAML2_XACML_ASSERTION_PREFIX)
        self.__xacmlContextRequest = None
        self.__xacmlContextResponse = None

    def __getstate__(self):
        '''Enable pickling
        
        @return: object's attribute dictionary
        @rtype: dict
        '''
        _dict = super(XACMLAuthzDecisionStatement, self).__getstate__()
        for attrName in XACMLAuthzDecisionStatement.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_XACMLAuthzDecisionStatement" + attrName
                
            _dict[attrName] = getattr(self, attrName)
            
        return _dict

    def _getXacmlContextRequest(self):
        '''Gets the XACML context Request child element.

        @return: Request value
        @rtype: ndg.xacml.core.context.request.Request
        '''
        return self.__xacmlContextRequest
    
    def _setXacmlContextRequest(self, value):
        '''Sets  the XACML context Request child element.
        
        @param value: the new Request attribute value
        @type value: ndg.xacml.core.context.request.Request
        @raise TypeError: if incorrect input type 
        '''
        if not isinstance(value, Request):
            raise TypeError('Expecting string type for "Request" '
                            'attribute; got %r instead' % type(value))
        
        self.__xacmlContextRequest = value
    
    xacmlContextRequest = property(fget=_getXacmlContextRequest,
                                   fset=_setXacmlContextRequest,
                                   doc="XACML context Request")

    def _getXacmlContextResponse(self):
        '''Gets the XACML context Response child element.

        @return: Response value
        @rtype: ndg.xacml.core.context.request.Response
        '''
        return self.__xacmlContextResponse
    
    def _setXacmlContextResponse(self, value):
        '''Sets  the XACML context Response child element.
        
        @param value: the new Response attribute value
        @type value: ndg.xacml.core.context.request.Response
        @raise TypeError: if incorrect input type 
        '''
        if not isinstance(value, Response):
            raise TypeError('Expecting string type for "Response" '
                            'attribute; got %r instead' % type(value))
        
        self.__xacmlContextResponse = value
    
    xacmlContextResponse = property(fget=_getXacmlContextResponse,
                                    fset=_setXacmlContextResponse,
                                    doc="XACML context Response")
