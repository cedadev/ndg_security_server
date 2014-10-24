"""WSGI SAML package for SAML 2.0 Attribute and Authorisation Decision Query/
Request Profile interfaces

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/02/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
import logging
log = logging.getLogger(__name__)
import traceback
from cStringIO import StringIO
from uuid import uuid4
from datetime import datetime, timedelta

from ndg.soap.server.wsgi.middleware import SOAPMiddleware
from ndg.soap.etree import SOAPEnvelope

from ndg.saml.utils import str2Bool
from ndg.saml.utils.factory import importModuleObject
from ndg.saml.xml import UnknownAttrProfile
from ndg.saml.xml.etree import QName
from ndg.saml.common import SAMLVersion
from ndg.saml.utils import SAMLDateTime
from ndg.saml.saml2.core import (Response, Status, StatusCode, StatusMessage, 
                                 Issuer) 
from ndg.saml.saml2.binding.soap import SOAPBindingInvalidResponse

try:
    from ndg.saml.saml2.xacml_profile import XACMLAuthzDecisionQuery
    import ndg.saml.xml.etree_xacml_profile as etree_xacml_profile
except ImportError, e:
    from warnings import warn
    warn('Error importing XACML packages - disabling SAML XACML profile ' + \
         'support.  (Error is: %s)' % e)
    class XACMLAuthzDecisionQuery(object):
        """XACML Authz Decision Query substitute"""
        DEFAULT_ELEMENT_LOCAL_NAME = 'XACMLAuthzDecisionQuery'
        
    
class SOAPQueryInterfaceMiddlewareError(Exception):
    """Base class for WSGI SAML 2.0 SOAP Query Interface Errors"""


class SOAPQueryInterfaceMiddlewareConfigError(Exception):
    """WSGI SAML 2.0 SOAP Query Interface Configuration problem"""


class QueryIssueInstantInvalid(SOAPBindingInvalidResponse):
    """Invalid timestamp for incoming query"""
    
    
class SOAPQueryInterfaceMiddleware(SOAPMiddleware):
    """Implementation of SAML 2.0 SOAP Binding for Query/Request Binding
    
    @type PATH_OPTNAME: basestring
    @cvar PATH_OPTNAME: name of app_conf option for specifying a path or paths
    that this middleware will intercept and process
    @type QUERY_INTERFACE_KEYNAME_OPTNAME: basestring
    @cvar QUERY_INTERFACE_KEYNAME_OPTNAME: app_conf option name for key name
    used to reference the SAML query interface in environ
    @type DEFAULT_QUERY_INTERFACE_KEYNAME: basestring
    @param DEFAULT_QUERY_INTERFACE_KEYNAME: default key name for referencing
    SAML query interface in environ
    """
    log = logging.getLogger('SOAPQueryInterfaceMiddleware')
    PATH_OPTNAME = "mountPath"
    QUERY_INTERFACE_KEYNAME_OPTNAME = "queryInterfaceKeyName"
    DEFAULT_QUERY_INTERFACE_KEYNAME = ("ndg.security.server.wsgi.saml."
                            "SOAPQueryInterfaceMiddleware.queryInterface")
    
    REQUEST_ENVELOPE_CLASS_OPTNAME = 'requestEnvelopeClass'
    RESPONSE_ENVELOPE_CLASS_OPTNAME = 'responseEnvelopeClass'
    SERIALISE_OPTNAME = 'serialise'
    DESERIALISE_OPTNAME = 'deserialise' 
    DESERIALISE_XACML_PROFILE_OPTNAME = 'deserialiseXacmlProfile'
    SAML_VERSION_OPTNAME = 'samlVersion'
    ISSUER_NAME_OPTNAME = 'issuerName'
    ISSUER_FORMAT_OPTNAME = 'issuerFormat'
    CLOCK_SKEW_TOLERANCE_OPTNAME = 'clockSkewTolerance'
    
    CONFIG_FILE_OPTNAMES = (
        PATH_OPTNAME,
        QUERY_INTERFACE_KEYNAME_OPTNAME,
        DEFAULT_QUERY_INTERFACE_KEYNAME,
        REQUEST_ENVELOPE_CLASS_OPTNAME,
        RESPONSE_ENVELOPE_CLASS_OPTNAME,
        SERIALISE_OPTNAME,
        DESERIALISE_OPTNAME,
        DESERIALISE_XACML_PROFILE_OPTNAME,
        SAML_VERSION_OPTNAME,
        ISSUER_NAME_OPTNAME,
        ISSUER_FORMAT_OPTNAME,
        CLOCK_SKEW_TOLERANCE_OPTNAME
    )
    
    def __init__(self, app):
        '''@type app: callable following WSGI interface
        @param app: next middleware application in the chain 
        '''     
        super(SOAPQueryInterfaceMiddleware, self).__init__()
        
        self._app = app
        
        # Set defaults
        cls = SOAPQueryInterfaceMiddleware
        self.__queryInterfaceKeyName = cls.DEFAULT_QUERY_INTERFACE_KEYNAME
        self.__mountPath = '/'
        self.__requestEnvelopeClass = None
        self.__responseEnvelopeClass = None
        self.__serialise = None
        self.__deserialise = None
        self.__deserialiseXacmlProfile = None
        self.__issuer = None
        self.__clockSkewTolerance = timedelta(seconds=0.)
        self.__verifyTimeConditions = True
        self.__verifySAMLVersion = True
        self.__samlVersion = SAMLVersion.VERSION_20
        
        # Proxy object for SAML Response Issuer attributes.  By generating a 
        # proxy the Response objects inherent attribute validation can be 
        # applied to Issuer related config parameters before they're assigned to
        # the response issuer object generated in the authorisation decision 
        # query response
        self.__issuerProxy = Issuer()
      
    def initialise(self, global_conf, prefix='', **app_conf):
        '''
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        # Override where set in config
        for name in SOAPQueryInterfaceMiddleware.CONFIG_FILE_OPTNAMES:
            val = app_conf.get(prefix + name)
            if val is not None:
                setattr(self, name, val)

        if self.serialise is None:
            raise AttributeError('No "serialise" method set to serialise the '
                                 'SAML response from this middleware.')

        if self.deserialise is None:
            raise AttributeError('No "deserialise" method set to parse the '
                                 'SAML request to this middleware.')
            
    def _getSerialise(self):
        return self.__serialise

    def _setSerialise(self, value):
        if isinstance(value, basestring):
            self.__serialise = importModuleObject(value)
            
        elif callable(value):
            self.__serialise = value
        else:
            raise TypeError('Expecting callable for "serialise"; got %r' % 
                            value)

    serialise = property(_getSerialise, _setSerialise, 
                         doc="callable to serialise request into XML type")

    def _getDeserialise(self):
        return self.__deserialise

    def _setDeserialise(self, value):
        if isinstance(value, basestring):
            self.__deserialise = importModuleObject(value)
            
        elif callable(value):
            self.__deserialise = value
        else:
            raise TypeError('Expecting callable for "deserialise"; got %r' % 
                            value)
        
    deserialise = property(_getDeserialise, 
                           _setDeserialise, 
                           doc="callable to de-serialise response from XML "
                               "type")        

    def _getDeserialiseXacmlProfile(self):
        return self.__deserialiseXacmlProfile

    def _setDeserialiseXacmlProfile(self, value):
        if isinstance(value, basestring):
            self.__deserialiseXacmlProfile = importModuleObject(value)

        elif callable(value):
            self.__deserialiseXacmlProfile = value
        else:
            raise TypeError('Expecting callable for "deserialiseXacmlProfile"; '
                            'got %r' % value)

    deserialiseXacmlProfile = property(_getDeserialiseXacmlProfile,
                                       _setDeserialiseXacmlProfile,
                                       doc="callable to de-serialise response "
                                       "from XML type with XACML profile")

    def _getIssuer(self):
        return self.__issuer

    def _setIssuer(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "issuer"; got %r' %
                            type(value))
            
        self.__issuer = value
        
    issuer = property(fget=_getIssuer, 
                      fset=_setIssuer, 
                      doc="Name of issuing authority")

    def _getIssuerFormat(self):
        if self.__issuerProxy is None:
            return None
        else:
            return self.__issuerProxy.format

    def _setIssuerFormat(self, value):
        if self.__issuerProxy is None:
            self.__issuerProxy = Issuer()
            
        self.__issuerProxy.format = value

    issuerFormat = property(_getIssuerFormat, _setIssuerFormat, 
                            doc="Issuer format")

    def _getIssuerName(self):
        if self.__issuerProxy is None:
            return None
        else:
            return self.__issuerProxy.value

    def _setIssuerName(self, value):
        self.__issuerProxy.value = value

    issuerName = property(_getIssuerName, _setIssuerName, 
                          doc="Name of issuer of SAML Query Response")

    def _getVerifyTimeConditions(self):
        return self.__verifyTimeConditions

    def _setVerifyTimeConditions(self, value):
        if isinstance(value, bool):
            self.__verifyTimeConditions = value
            
        if isinstance(value, basestring):
            self.__verifyTimeConditions = str2Bool(value)
        else:
            raise TypeError('Expecting bool or string type for '
                            '"verifyTimeConditions"; got %r instead' % 
                            type(value))

    verifyTimeConditions = property(_getVerifyTimeConditions, 
                                    _setVerifyTimeConditions, 
                                    doc='Set to True to verify any time '
                                        'Conditions set in the returned '
                                        'response assertions')

    def _getVerifySAMLVersion(self):
        return self.__verifySAMLVersion

    def _setVerifySAMLVersion(self, value):
        if isinstance(value, bool):
            self.__verifySAMLVersion = value
            
        if isinstance(value, basestring):
            self.__verifySAMLVersion = str2Bool(value)
        else:
            raise TypeError('Expecting bool or string type for '
                            '"verifySAMLVersion"; got %r instead' % 
                            type(value))

    verifySAMLVersion = property(_getVerifySAMLVersion, 
                                 _setVerifySAMLVersion, 
                                 doc='Set to True to verify the SAML version '
                                     'set in the query against the SAML '
                                     'Version set in the "samlVersion" '
                                     'attribute')
        
    def _getClockSkewTolerance(self):
        return self.__clockSkewTolerance

    def _setClockSkewTolerance(self, value):
        if isinstance(value, timedelta):
            self.__clockSkewTolerance = value
            
        elif isinstance(value, (float, int, long)):
            self.__clockSkewTolerance = timedelta(seconds=value)
            
        elif isinstance(value, basestring):
            self.__clockSkewTolerance = timedelta(seconds=float(value))
        else:
            raise TypeError('Expecting timedelta, float, int, long or string '
                            'type for "clockSkewTolerance"; got %r' % 
                            type(value))  
                
    clockSkewTolerance = property(fget=_getClockSkewTolerance, 
                                  fset=_setClockSkewTolerance, 
                                  doc="Set a tolerance of +/- n seconds to "
                                      "allow for clock skew when checking the "
                                      "timestamps of client queries")

    def _getSamlVersion(self):
        return self.__samlVersion

    def _setSamlVersion(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "samlVersion"; got %r' % 
                            type(value)) 
        self.__samlVersion = value

    samlVersion = property(_getSamlVersion, _setSamlVersion, None, 
                           "SAML Version to enforce for incoming queries.  "
                           "Defaults to version 2.0")
        
    def _getMountPath(self):
        return self.__mountPath
    
    def _setMountPath(self, value):
        '''
        @type value: basestring
        @param value: URL paths to apply this middleware to. Paths are relative 
        to the point at which this middleware is mounted as set in 
        environ['PATH_INFO']
        @raise TypeError: incorrect input type
        '''
        
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "mountPath" attribute; '
                            'got %r' % value)
            
        self.__mountPath = value
            
    mountPath = property(fget=_getMountPath,
                         fset=_setMountPath,
                         doc='URL path to mount this application equivalent to '
                             'environ[\'PATH_INFO\'] (Nb. doesn\'t '
                             'include server domain name or '
                             'environ[\'SCRIPT_NAME\'] setting')
    
    @classmethod
    def filter_app_factory(cls, app, global_conf, **app_conf):
        """Set-up using a Paste app factory pattern.  Set this method to avoid
        possible conflicts from multiple inheritance
        
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
        app.initialise(global_conf, **app_conf)
        
        return app
    
    def _getQueryInterfaceKeyName(self):
        return self.__queryInterfaceKeyName

    def _setQueryInterfaceKeyName(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "queryInterfaceKeyName"'
                            ' got %r' % value)
            
        self.__queryInterfaceKeyName = value

    queryInterfaceKeyName = property(fget=_getQueryInterfaceKeyName, 
                                     fset=_setQueryInterfaceKeyName, 
                                     doc="environ key name for Attribute Query "
                                         "interface")
    
    def __call__(self, environ, start_response):
        """Check for and parse a SOAP SAML Attribute Query and return a
        SAML Response
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        """
    
        # Ignore non-matching path
        if environ['PATH_INFO'] not in (self.mountPath, self.mountPath + '/'):
            return self._app(environ, start_response)
          
        # Ignore non-POST requests
        if environ.get('REQUEST_METHOD') != 'POST':
            return self._app(environ, start_response)
        
        soapRequestStream = environ.get('wsgi.input')
        if soapRequestStream is None:
            raise SOAPQueryInterfaceMiddlewareError('No "wsgi.input" in '
                                                    'environ')
        
        # TODO: allow for chunked data
        contentLength = environ.get('CONTENT_LENGTH')
        if contentLength is None:
            raise SOAPQueryInterfaceMiddlewareError('No "CONTENT_LENGTH" in '
                                                    'environ')

        contentLength = int(contentLength)
        if contentLength <= 0:
            raise SOAPQueryInterfaceMiddlewareError('"CONTENT_LENGTH" in '
                                                    'environ is %d' %
                                                    contentLength)
            
        soapRequestTxt = soapRequestStream.read(contentLength)
        
        # Parse into a SOAP envelope object
        soapRequest = SOAPEnvelope()
        soapRequest.parse(StringIO(soapRequestTxt))
        
        log.debug("SOAPQueryInterfaceMiddleware.__call__: received SAML "
                  "SOAP Query: %s", soapRequestTxt)
       
        queryElem = soapRequest.body.elem[0]
        
        # Create a response with basic attributes if provided in the 
        # initialisation config
        samlResponse = self._initResponse()
        
        try:
            queryType = QName.getLocalPart(queryElem.tag)
            if queryType == XACMLAuthzDecisionQuery.DEFAULT_ELEMENT_LOCAL_NAME:
                # Set up additional ElementTree parsing for XACML profile.
                etree_xacml_profile.setElementTreeMap()
                samlQuery = self.deserialiseXacmlProfile(queryElem)
            else:
                samlQuery = self.deserialise(queryElem)

        except UnknownAttrProfile, e:
            log.exception("%r raised parsing incoming query: %s" % 
                          (type(e), traceback.format_exc()))
            samlResponse.status.statusCode.value = \
                                            StatusCode.UNKNOWN_ATTR_PROFILE_URI
        else:   
            # Check for Query Interface in environ
            queryInterface = environ.get(self.queryInterfaceKeyName,
                                         NotImplemented)
            if queryInterface == NotImplemented:
                raise SOAPQueryInterfaceMiddlewareConfigError(
                                'No query interface %r key found in environ' %
                                self.queryInterfaceKeyName)
                
            elif not callable(queryInterface):
                raise SOAPQueryInterfaceMiddlewareConfigError(
                    'Query interface %r set in %r environ key is not callable' %
                    (queryInterface, self.queryInterfaceKeyName))
            
            # Basic validation
            self._validateQuery(samlQuery, samlResponse)
            
            samlResponse.inResponseTo = samlQuery.id
            
            # Call query interface        
            queryInterface(samlQuery, samlResponse)
        
        # Convert to ElementTree representation to enable attachment to SOAP
        # response body
        samlResponseElem = self.serialise(samlResponse)
        
        # Create SOAP response and attach the SAML Response payload
        soapResponse = SOAPEnvelope()
        soapResponse.create()
        soapResponse.body.elem.append(samlResponseElem)
        
        response = soapResponse.serialize()
        
        log.debug("SOAPQueryInterfaceMiddleware.__call__: sending response "
                  "...\n\n%s",
                  response)
        start_response("200 OK",
                       [('Content-length', str(len(response))),
                        ('Content-type', 'text/xml')])
        return [response]
    
    def _validateQuery(self, query, response):
        """Checking incoming query issue instant and version
        @type query: saml.saml2.core.SubjectQuery 
        @param query: SAML subject query to be checked
        @type: saml.saml2.core.Response
        @param: SAML Response 
        """
        self._verifyQueryTimeConditions(query, response)
        self._verifyQuerySAMLVersion(query, response)
        
    def _verifyQueryTimeConditions(self, query, response):
        """Checking incoming query issue instant
        @type query: saml.saml2.core.SubjectQuery 
        @param query: SAML subject query to be checked
        @type: saml.saml2.core.Response
        @param: SAML Response 
        @raise QueryIssueInstantInvalid: for invalid issue instant
        """
        if not self.verifyTimeConditions: 
            log.debug("Skipping verification of SAML query time conditions")
            return
              
        utcNow = datetime.utcnow() 
        nowPlusSkew = utcNow + self.clockSkewTolerance
        
        if query.issueInstant > nowPlusSkew:
            msg = ('SAML Attribute Query issueInstant [%s] is after '
                   'the clock time [%s] (skewed +%s)' % 
                   (query.issueInstant, 
                    SAMLDateTime.toString(nowPlusSkew),
                    self.clockSkewTolerance))
             
            samlRespError = QueryIssueInstantInvalid(msg)
            samlRespError.response = response
            raise samlRespError
            
    def _verifyQuerySAMLVersion(self, query, response):
        """Checking incoming query issue SAML version
        
        @type query: saml.saml2.core.SubjectQuery 
        @param query: SAML subject query to be checked
        @type: saml.saml2.core.Response
        @param: SAML Response 
        """
        if not self.verifySAMLVersion:
            log.debug("Skipping verification of SAML query version")
            return
        
        if query.version < self.samlVersion:
            log.debug("Query SAML version %r is lower than the supported "
                      "value %r", query.version, self.samlVersion)
            response.status.statusCode.value = \
                                        StatusCode.REQUEST_VERSION_TOO_LOW_URI
        
        elif query.version > self.samlVersion:
            log.debug("Query SAML version %r is higher than the supported "
                      "value %r", query.version, self.samlVersion)
            response.status.statusCode.value = \
                                        StatusCode.REQUEST_VERSION_TOO_HIGH_URI
            
        
    def _initResponse(self):
        """Create a SAML Response object with basic settings if any have been
        provided at initialisation of this class - see initialise
        
        @return: SAML response object
        @rtype: ndg.saml.saml2.core.Response
        """
        samlResponse = Response()
        utcNow = datetime.utcnow()
        
        samlResponse.issueInstant = utcNow
        samlResponse.id = str(uuid4())
        samlResponse.issuer = Issuer()
        
        if self.issuerName is not None:
            samlResponse.issuer.value = self.issuerName
        
        if self.issuerFormat is not None:
            # TODO: Check SAML 2.0 spec says issuer format must be omitted??
            samlResponse.issuer.format = self.issuerFormat
        
        # Initialise to success status but reset on error
        samlResponse.status = Status()
        samlResponse.status.statusCode = StatusCode()
        samlResponse.status.statusMessage = StatusMessage()
        samlResponse.status.statusCode.value = StatusCode.SUCCESS_URI
        
        samlResponse.status.statusMessage = StatusMessage()

        return samlResponse

