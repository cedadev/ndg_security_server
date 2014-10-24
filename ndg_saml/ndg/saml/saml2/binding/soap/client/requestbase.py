"""SAML 2.0 bindings module implements SOAP binding for base request

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "12/02/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: subjectquery.py 7634 2010-10-20 20:23:29Z pjkersha $'
import logging
log = logging.getLogger(__name__)

import copy
from datetime import datetime, timedelta
from uuid import uuid4

from ndg.saml.utils import SAMLDateTime
from ndg.saml.saml2.core import (RequestAbstractType, StatusCode, Issuer,
                                 SAMLVersion)

from ndg.saml.utils import str2Bool
from ndg.saml.saml2.binding.soap.client import (SOAPBinding,
    SOAPBindingInvalidResponse)


class RequestResponseError(SOAPBindingInvalidResponse):
    """SAML Response error from request"""
    

class IssueInstantInvalid(RequestResponseError):
    """Issue instant of SAML artifact is invalid"""

  
class ResponseIssueInstantInvalid(IssueInstantInvalid):
    """Issue instant of a response is after the current time"""

    
class AssertionIssueInstantInvalid(IssueInstantInvalid):
    """Issue instant of an assertion is after the current time"""


class AssertionConditionNotBeforeInvalid(RequestResponseError):
    """An assertion condition notBefore time is set after the current clock
    time"""
    

class AssertionConditionNotOnOrAfterInvalid(RequestResponseError):
    """An assertion condition notOnOrAfter time is set before the current clock
    time"""

   
class RequestBaseSOAPBinding(SOAPBinding): 
    """SAML Request Base SOAP Binding
    """
    ISSUER_NAME_OPTNAME = 'issuerName'
    ISSUER_FORMAT_OPTNAME = 'issuerFormat'
    CLOCK_SKEW_OPTNAME = 'clockSkewTolerance'
    VERIFY_TIME_CONDITIONS_OPTNAME = 'verifyTimeConditions'
    
    CONFIG_FILE_OPTNAMES = (
        ISSUER_NAME_OPTNAME, 
        ISSUER_FORMAT_OPTNAME,                
        CLOCK_SKEW_OPTNAME,
        VERIFY_TIME_CONDITIONS_OPTNAME            
    )
    
    __PRIVATE_ATTR_PREFIX = "__"
    __slots__ = tuple([__PRIVATE_ATTR_PREFIX + i 
                       for i in CONFIG_FILE_OPTNAMES + ('issuer',)])
    del i
    
    QUERY_TYPE = RequestAbstractType
    
    def __init__(self, **kw):
        '''Create SOAP Client for a SAML Subject Query'''       
        self.__clockSkewTolerance = timedelta(seconds=0.)
        self.__verifyTimeConditions = True
        self.__issuer = Issuer()
        self.__issuer.format = Issuer.X509_SUBJECT
        
        super(RequestBaseSOAPBinding, self).__init__(**kw)

    def makeQuery(self):
        query = self.__class__.QUERY_TYPE()
        query.version = SAMLVersion(SAMLVersion.VERSION_20)
        self.addQueryAttributes(query)
        return query

    def addQueryAttributes(self, query):
        query.issuer = copy.deepcopy(self.issuer)

    def _getIssuer(self):
        return self.__issuer

    def _setIssuer(self, value):
        self.__issuer = value

    issuer = property(_getIssuer, _setIssuer, 
                      doc="Issuer")

    def _getIssuerFormat(self):
        if self.issuer is None:
            return None
        else:
            return self.issuer.format

    def _setIssuerFormat(self, value):
        if self.issuer is None:
            self.issuer = Issuer()

        self.issuer.format = value

    issuerFormat = property(_getIssuerFormat, _setIssuerFormat, 
                            doc="Issuer format")

    def _getIssuerName(self):
        if self.issuer is None:
            return None
        else:
            return self.issuer.value

    def _setIssuerName(self, value):
        if self.issuer is None:
            self.issuer = Issuer()

        self.issuer.value = value

    issuerName = property(_getIssuerName, _setIssuerName, 
                          doc="Name of issuer of SAML Subject Query")

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
                                  doc="Allow a tolerance in seconds for SAML "
                                      "Query issueInstant parameter check and "
                                      "assertion condition notBefore and "
                                      "notOnOrAfter times to allow for clock "
                                      "skew")
    
    def _validateQueryParameters(self, query):
        """Perform sanity check immediately before creating the query and 
        sending it"""
        errors = []
        
        if query.issuer.value is None:
            errors.append('issuer name')

        if query.issuer.format is None:
            errors.append('issuer format')
        
        if errors:
            raise AttributeError('Missing attribute(s) for SAML Query: %s' %
                                 ', '.join(errors))

    def _initSend(self, query):
        """Perform any final initialisation prior to sending the query - derived
        classes may overload to specify as required"""
        query.issueInstant = datetime.utcnow()
        
        # Set ID here to ensure it's unique for each new call
        query.id = str(uuid4())

    def _verifyTimeConditions(self, response):
        """Verify time conditions set in a response
        @param response: SAML Response returned from remote service
        @type response: ndg.saml.saml2.core.Response
        @raise RequestResponseError: if a timestamp is invalid
        """
        
        if not self.verifyTimeConditions:
            log.debug("Skipping verification of SAML Response time conditions")
            
        utcNow = datetime.utcnow() 
        nowMinusSkew = utcNow - self.clockSkewTolerance
        nowPlusSkew = utcNow + self.clockSkewTolerance
        
        if response.issueInstant > nowPlusSkew:
            msg = ('SAML Attribute Response issueInstant [%s] is after '
                   'the clock time [%s] (skewed +%s)' % 
                   (response.issueInstant, 
                    SAMLDateTime.toString(nowPlusSkew),
                    self.clockSkewTolerance))
             
            samlRespError = ResponseIssueInstantInvalid(msg)
            samlRespError.response = response
            raise samlRespError
        
        for assertion in response.assertions:
            if assertion.issueInstant is None:
                samlRespError = AssertionIssueInstantInvalid("No issueInstant "
                                                             "set in response "
                                                             "assertion")
                samlRespError.response = response
                raise samlRespError
            
            elif nowPlusSkew < assertion.issueInstant:
                msg = ('The clock time [%s] (skewed +%s) is before the '
                       'SAML Attribute Response assertion issue instant [%s]' % 
                       (SAMLDateTime.toString(utcNow),
                        self.clockSkewTolerance,
                        assertion.issueInstant))
                samlRespError = AssertionIssueInstantInvalid(msg)
                samlRespError.response = response
                raise samlRespError
            
            if assertion.conditions is not None:
                if nowPlusSkew < assertion.conditions.notBefore:            
                    msg = ('The clock time [%s] (skewed +%s) is before the '
                           'SAML Attribute Response assertion conditions not '
                           'before time [%s]' % 
                           (SAMLDateTime.toString(utcNow),
                            self.clockSkewTolerance,
                            assertion.conditions.notBefore))
                              
                    samlRespError = AssertionConditionNotBeforeInvalid(msg)
                    samlRespError.response = response
                    raise samlRespError
                 
                if nowMinusSkew >= assertion.conditions.notOnOrAfter:           
                    msg = ('The clock time [%s] (skewed -%s) is on or after '
                           'the SAML Attribute Response assertion conditions '
                           'not on or after time [%s]' % 
                           (SAMLDateTime.toString(utcNow),
                            self.clockSkewTolerance,
                            assertion.conditions.notOnOrAfter))
                    
                    samlRespError = AssertionConditionNotOnOrAfterInvalid(msg) 
                    samlRespError.response = response
                    raise samlRespError
                
    def send(self, query, **kw):
        '''Make an attribute query to a remote SAML service
        
        @type uri: basestring 
        @param uri: uri of service.  May be omitted if set from request.url
        @type request: ndg.security.common.soap.UrlLib2SOAPRequest
        @param request: SOAP request object to which query will be attached
        defaults to ndg.security.common.soap.client.UrlLib2SOAPRequest
        '''
        self._validateQueryParameters(query)
        self._initSend(query)
           
        log.debug("Sending request: query ID: %s", query.id)
        response = super(RequestBaseSOAPBinding, self).send(query, **kw)

        # Perform validation
        if response.status.statusCode.value != StatusCode.SUCCESS_URI:
            msg = ('Return status code flagged an error, %r.  '
                   'The message is, %r' %
                   (response.status.statusCode.value,
                    response.status.statusMessage.value))
            samlRespError = RequestResponseError(msg)
            samlRespError.response = response
            raise samlRespError
        
        # Check Query ID matches the query ID the service received
        if response.inResponseTo != query.id:
            msg = ('Response in-response-to ID %r, doesn\'t match the original '
                   'query ID, %r' % (response.inResponseTo, query.id))
            
            samlRespError = RequestResponseError(msg)
            samlRespError.response = response
            raise samlRespError
        
        self._verifyTimeConditions(response)
            
        return response 
