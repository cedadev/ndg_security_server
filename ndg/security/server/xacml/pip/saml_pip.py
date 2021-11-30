"""Module for XACML Policy Information Point with SAML interface to
Attribute Authority

"""
__author__ = "P J Kershaw"
__date__ = "06/08/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

from os import path
import base64

import beaker.session

from ndg.xacml.core.attributedesignator import SubjectAttributeDesignator
from ndg.xacml.core.attribute import Attribute as XacmlAttribute
from ndg.xacml.core.attributevalue import AttributeValueClassFactory as \
    XacmlAttributeValueClassFactory
from ndg.xacml.core.context.pipinterface import PIPInterface
from ndg.xacml.core.context.request import Request as XacmlRequestCtx

from ndg.saml.saml2.core import (Attribute as SamlAttribute,
                                 Assertion as SamlAssertion)
from ndg.saml.utils import TypedList as SamlTypedList
from ndg.saml.utils.factory import AttributeQueryFactory
from ndg.saml.saml2.binding.soap.client.attributequery import \
                                            AttributeQuerySslSOAPBinding

from ndg.security.common.utils import VettedDict, str2Bool
from ndg.security.common.credentialwallet import SAMLAssertionWallet
from ndg.security.server.utils.parsers import keyword_parser


class SessionCache(object):
    """Class to cache previous attribute query results retrieved from
    Attribute Authority callouts.  This is to optimise performance.  Session
    caching is based on beaker.session

    @ivar __session: wrapped beaker session instance
    @type __session: beaker.session.Session
    """
    __slots__ = ('__session', )

    def __init__(self, _id, data_dir=None, timeout=None,
                 assertionClockSkewTolerance=1.0):
        """
        @param _id: unique identifier for session to be created, or one to reload
        from store
        @type _id: basestring
        @param data_dir: directory for permanent storage of sessions.
        Sessions are used as a means of optimisation caching Attribute Query
        results to reduce the number of Attribute Authority web service calls.
        If set to None, sessions are cached in memory only.
        @type data_dir: None type / basestring
        @param timeout: time in seconds for individual caches' lifetimes.  Set
        to None to set no expiry.
        @type timeout: float/int/long or None type
        """
        # Expecting URIs for Ids, make them safe for storage by encoding first
        encodedId = base64.b64encode(_id.encode('utf-8'))

        # The first argument is the request object, a dictionary-like object
        # from which and to which cookie settings are made.  This can be ignored
        # here as the cookie functionality is not being used.
        self.__session = beaker.session.Session({}, id=encodedId,
                                                data_dir=data_dir,
                                                timeout=timeout,
                                                use_cookies=False)
        if 'wallet' not in self.__session:
            self.__session['wallet'] = SAMLAssertionWallet()
            self.__session['wallet'
                           ].clockSkewTolerance = assertionClockSkewTolerance
        else:
            # Prune expired assertions
            self.__session['wallet'].audit()

    def add(self, assertions, issuerEndpoint):
        """Add a SAML assertion containing attribute statement(s) from an
        Attribute Authority

        @type assertions: ndg.security.common.utils.TypedList
        @param assertions: new SAML assertions to be added corresponding to the
        issuerEndpoint
        @type issuerEndpoint: basestring
        @param issuerEndpoint: input the issuing service URI from
        which assertions were retrieved.  This is added to a dict to enable
        access to given Assertions keyed by issuing service URI. See the
        retrieveAssertions method.
        @raise KeyError: error with session object - no wallet key set
        """
        self.__session['wallet'].addCredentials(issuerEndpoint, assertions)

    def retrieve(self, issuerEndpoint):
        '''Get the cached assertions for the given Attribute Authority issuer

        @type issuerEndpoint: basestring
        @param issuerEndpoint: input the issuing service URI from
        which assertion was retrieved.
        @return: SAML assertion response cached from a previous call to the
        Attribute Authority with the given endpoint
        @raise KeyError: error with session object - no wallet key set
        '''
        wallet = self.__session['wallet']
        return wallet.retrieveCredentials(issuerEndpoint)

    def __del__(self):
        """Ensure session is saved when this object goes out of scope"""
        if isinstance(self.__session, beaker.session.Session):
            self.__session.save()


class PIPException(Exception):
    """Base exception type for XACML PIP (Policy Information Point) class"""


class PIPConfigException(PIPException):
    """Configuration errors related to the XACML PIP (Policy Information Point)
    class
    """


class PIPRequestCtxException(PIPException):
    """Error with request context passed to XACML PIP object's attribute query
    """


class PIP(PIPInterface):
    '''Policy Information Point enables XACML PDP to query for additional user
    attributes.  The PDP does this indirectly via the Context Handler
    '''
    # Subject attributes makes no sense for external configuration - these
    # are set at run time based on the given subject identity
    DISALLOWED_ATTRIBUTE_QUERY_OPTNAMES = (
        'subject.nameID.value'
    )

    # Special attribute setting for SAML Attribute Query attributes - see
    # __setattr__
    ATTRIBUTE_QUERY_ATTRNAME = 'attribute_query.'
    LEN_ATTRIBUTE_QUERY_ATTRNAME = len(ATTRIBUTE_QUERY_ATTRNAME)

    # +1 allows for '.' or other separator e.g.
    # pip.attribute_query.issuerName
    #                   ^
    ATTRIBUTE_QUERY_ATTRNAME_OFFSET = LEN_ATTRIBUTE_QUERY_ATTRNAME

    # Likewise for the query binding.  The binding is the join between SAML
    # message and the transport.  In this case SOAP over SSL.
    ATTRIBUTE_QUERY_BINDING_ATTRNAME = 'attribute_query_binding.'
    LEN_ATTRIBUTE_QUERY_BINDING_ATTRNAME = len(ATTRIBUTE_QUERY_BINDING_ATTRNAME)
    ATTRIBUTE_QUERY_BINDING_ATTRNAME_OFFSET = \
                                        LEN_ATTRIBUTE_QUERY_BINDING_ATTRNAME + 1

    DEFAULT_OPT_PREFIX = 'saml_pip.'

    XACML_ATTR_VAL_CLASS_FACTORY = XacmlAttributeValueClassFactory()

    MAPPING_FILE_FIELD_SEP = ','

    __slots__ = (
        '__subjectAttributeId',
        '__mappingFilePath',
        '__attributeId2AttributeAuthorityMap',
        '__attribute_query',
        '__attribute_query_binding',
        '__cacheSessions',
        '__sessionCacheDataDir',
        '__sessionCacheTimeout',
        '__sessionCacheAssertionClockSkewTol'
    )

    def __init__(self, sessionCacheDataDir=None, sessionCacheTimeout=None,
                 sessionCacheAssertionClockSkewTol=1.0):
        '''Initialise settings for connection to an Attribute Authority

        @param sessionCacheDataDir: directory for permanent storage of sessions.
        Sessions are used as a means of optimisation caching Attribute Query
        results to reduce the number of Attribute Authority web service calls.
        If set to None, sessions are cached in memory only.
        @type sessionCacheDataDir: None type / basestring
        @param sessionCacheTimeout: time in seconds for individual caches'
        lifetimes.  Set to None to set no expiry.
        @type sessionCacheTimeout: float/int/long/string or None type
        '''
        self.sessionCacheDataDir = sessionCacheDataDir
        self.sessionCacheTimeout = sessionCacheTimeout
        self.__sessionCacheAssertionClockSkewTol = \
            sessionCacheAssertionClockSkewTol

        self.__subjectAttributeId = None
        self.__mappingFilePath = None

        # Force mapping dict to have string type keys and items
        _typeCheckers = (lambda val: isinstance(val, str),)*2
        self.__attributeId2AttributeAuthorityMap = VettedDict(*_typeCheckers)

        self.__attribute_query = AttributeQueryFactory.create()
        self.__attribute_query_binding = AttributeQuerySslSOAPBinding()

        self.__cacheSessions = True

    def _getSessionCacheTimeout(self):
        return self.__sessionCacheTimeout

    def _setSessionCacheTimeout(self, value):
        if value is None:
            self.__sessionCacheTimeout = value

        elif isinstance(value, str):
            self.__sessionCacheTimeout = float(value)

        elif isinstance(value, (int, float)):
            self.__sessionCacheTimeout = value

        else:
            raise TypeError('Expecting None, float, int, long or string type; '
                            'got %r' % type(value))

    sessionCacheTimeout = property(_getSessionCacheTimeout,
                                   _setSessionCacheTimeout,
                                   doc='Set individual session caches to '
                                       'timeout after this period (seconds).  '
                                       'Set to None to have no timeout')

    @property
    def sessionCacheAssertionClockSkewTol(self):
        """Clock tolerance of +/- value set for checking the validity times
        of SAML assertions cached in the Session Cache"""
        return self.__sessionCacheAssertionClockSkewTol

    @sessionCacheAssertionClockSkewTol.setter
    def sessionCacheAssertionClockSkewTol(self, value):
        """Clock tolerance of +/- value set for checking the validity times
        of SAML assertions cached in the Session Cache"""
        if value is None:
            self.__sessionCacheAssertionClockSkewTol = value

        elif isinstance(value, str):
            self.__sessionCacheAssertionClockSkewTol = float(value)

        elif isinstance(value, (int, float)):
            self.__sessionCacheAssertionClockSkewTol = value

        else:
            raise TypeError('Expecting None, float, int, long or string type; '
                            'got %r' % type(value))

    def _getCacheSessions(self):
        return self.__cacheSessions

    def _setCacheSessions(self, value):
        if isinstance(value, str):
            self.__cacheSessions = str2Bool(value)
        elif isinstance(value, bool):
            self.__cacheSessions = value
        else:
            raise TypeError('Expecting string/bool type for "cacheSessions" '
                            'attribute; got %r' % type(value))

        self.__cacheSessions = value

    cacheSessions = property(_getCacheSessions, _setCacheSessions,
                             doc="Cache attribute query results to optimise "
                                 "performance")

    def _getSessionCacheDataDir(self):
        return self.__sessionCacheDataDir

    def _setSessionCacheDataDir(self, value):
        if not isinstance(value, (str, type(None))):
            raise TypeError('Expecting string/None type for '
                            '"sessionCacheDataDir"; got %r' % type(value))

        self.__sessionCacheDataDir = value

    sessionCacheDataDir = property(_getSessionCacheDataDir,
                                   _setSessionCacheDataDir,
                                   doc="Data Directory for Session Cache.  "
                                       "This setting will be ignored if "
                                       '"cacheSessions" is set to False')

    def _getMappingFilePath(self):
        return self.__mappingFilePath

    def _setMappingFilePath(self, value):
        if not isinstance(value, str):
            raise TypeError('Expecting string type for "mappingFilePath"; got '
                            '%r' % type(value))
        self.__mappingFilePath = path.expandvars(value)

    mappingFilePath = property(_getMappingFilePath,
                               _setMappingFilePath,
                               doc="Mapping File maps Attribute ID -> "
"Attribute Authority mapping file.  The PIP, on receipt of a query from the "
"XACML context handler, checks the attribute(s) being queried for and looks up "
"this mapping to determine which attribute authority to query to find out if "
"the subject has the attribute in their entitlement.")

    attribute2AttributeAuthorityMap = property(
                    fget=lambda self: self.__attributeId2AttributeAuthorityMap,
                    doc="Mapping from attribute Id to attribute authority "
                        "endpoint")

    @property
    def attribute_query(self):
        '''Attribute Query to be used to query attribute service'''
        return self.__attribute_query

    @property
    def attribute_query_binding(self):
        """SAML SOAP Attribute Query client binding object"""
        return self.__attribute_query_binding

    def __setattr__(self, name, val):
        if '.' in name:
            obj_name, obj_attr_name = name.split('.', 1)
            obj = getattr(self, obj_name)
            keyword_parser(obj, **{obj_attr_name: val})
        else:
            return super(PIP, self).__setattr__(name, val)

    def readMappingFile(self):
        """Read the file which maps attribute names to Attribute Authorities
        """
        mappingFile = open(self.mappingFilePath)
        for line in mappingFile.readlines():
            _line = path.expandvars(line).strip()

            if _line and not _line.startswith('#'):
                try:
                    attribute_id, attribute_authority_uri = _line.split(
                                        self.__class__.MAPPING_FILE_FIELD_SEP)
                except ValueError:
                    raise PIPConfigException("Error parsing line - expecting "
                                             "form '<attribute id>, <attribute "
                                             "authority uri>', got: %r" % _line)

                self.__attributeId2AttributeAuthorityMap[attribute_id.strip()
                                            ] = attribute_authority_uri.strip()

    def attributeQuery(self, context, attributeDesignator):
        """Query this PIP for the given request context attribute specified by
        the attribute designator.  Nb. this implementation is only intended to
        accept queries for a given *subject* in the request

        @param context: the request context
        @type context: ndg.xacml.core.context.request.Request
        @param designator:
        @type designator: ndg.xacml.core.attributedesignator.SubjectAttributeDesignator
        @rtype: ndg.xacml.utils.TypedList(<attributeDesignator.dataType>) / None
        @return: attribute values found for query subject or None if none
        could be found
        @raise PIPConfigException: if attribute ID -> Attribute Authority
        mapping is empty
        """

        # Check the attribute designator type - this implementation takes
        # queries for request context subjects only
        if not isinstance(attributeDesignator, SubjectAttributeDesignator):
            log.debug('This PIP query interface can only accept subject '
                      'attribute designator related queries')
            return None

        attributeFormat = attributeDesignator.dataType
        attributeId = attributeDesignator.attributeId
        exptd_attribute_id = self.attribute_query.subject.nameID.format

        if not isinstance(context, XacmlRequestCtx):
            raise TypeError('Expecting %r type for context input; got %r' %
                            (XacmlRequestCtx, type(context)))

        # Look up mapping from request attribute ID to Attribute Authority to
        # query
        if len(self.__attributeId2AttributeAuthorityMap) == 0:
            raise PIPConfigException('No entries found in attribute ID to '
                                     'Attribute Authority mapping')

        attributeAuthorityURI = self.__attributeId2AttributeAuthorityMap.get(
                                            attributeId, None)
        if attributeAuthorityURI is None:
            log.debug("No matching attribute authority endpoint found in "
                      "mapping file %r for input attribute ID %r",
                      self.mappingFilePath, attributeId)
            return None

        # Get subject from the request context
        subject = None
        subjectId = None
        for subject in context.subjects:
            for attribute in subject.attributes:
                if attribute.attributeId == exptd_attribute_id:
                    if len(attribute.attributeValues) != 1:
                        raise PIPRequestCtxException("Expecting a single "
                                                     "attribute value "
                                                     "for query subject ID")
                    subjectId = attribute.attributeValues[0].value
                    break

        if subjectId is None:
            raise PIPRequestCtxException('No subject found of type %r in '
                                         'request context' % exptd_attribute_id)
        elif not subjectId:
            # Empty string
            return None
        else:
            # Keep a reference to the matching Subject instance
            xacmlCtxSubject = subject

        # Check for cached attributes for this subject (i.e. user)
        # If none found send a query to the attribute authority
        assertions = None
        attributeIdFoundInCache = False
        if self.cacheSessions:
            attributeIdFoundInCache = False
            sessionCache = SessionCache(subjectId,
                                    data_dir=self.sessionCacheDataDir,
                                    timeout=self.sessionCacheTimeout,
                                    assertionClockSkewTolerance=\
                                        self.sessionCacheAssertionClockSkewTol)

            assertions = sessionCache.retrieve(attributeAuthorityURI)
            if assertions is not None:
                # Check for attributes matching the requested ID
                for assertion in assertions:
                    for statement in assertion.attributeStatements:
                        for attribute in statement.attributes:
                            if attribute.name == attributeId:
                                attributeIdFoundInCache = True
                                break

        if not attributeIdFoundInCache:
            # No cached assertions are available for this Attribute Authority,
            # for the required attribute ID - make a fresh call to the
            # Attribute Authority

            # Initialise the attribute to be queried for and add it to the
            # SAML query
            samlAttribute = SamlAttribute()
            samlAttribute.name = attributeId
            samlAttribute.nameFormat = attributeFormat

            # Copy attributes for this query from constants set at
            # initialisation
            query = AttributeQueryFactory.create()
            query.subject.nameID.value = subjectId
            query.subject.nameID.format = exptd_attribute_id
            query.issuer.value = self.attribute_query.issuer.value
            query.issuer.format = self.attribute_query.issuer.format
            query.attributes.append(samlAttribute)

            # Dispatch query
            try:
                response = self.attribute_query_binding.send(query,
                                                    uri=attributeAuthorityURI)

                log.debug('Retrieved response from attribute service %r',
                          attributeAuthorityURI)
            except Exception:
                log.exception('Error querying Attribute service %r with '
                              'subject %r', attributeAuthorityURI, subjectId)
                raise

            if assertions is None:
                assertions = SamlTypedList(SamlAssertion)

            assertions.extend(response.assertions)

            if self.cacheSessions:
                sessionCache.add(assertions, attributeAuthorityURI)

        # Unpack SAML assertion attribute corresponding to the name
        # format specified and copy into XACML attributes
        xacmlAttribute = XacmlAttribute()
        xacmlAttribute.attributeId = attributeId
        xacmlAttribute.dataType = attributeFormat

        # Create XACML class from SAML type identifier
        factory = self.__class__.XACML_ATTR_VAL_CLASS_FACTORY
        xacmlAttrValClass = factory(attributeFormat)

        for assertion in assertions:
            for statement in assertion.attributeStatements:
                for attribute in statement.attributes:
                    if attribute.nameFormat == attributeFormat:
                        # Convert SAML Attribute values to XACML equivalent
                        # types
                        for samlAttrVal in attribute.attributeValues:
                            # Instantiate and initial new XACML value
                            xacmlAttrVal = xacmlAttrValClass(
                                                        value=samlAttrVal.value)

                            xacmlAttribute.attributeValues.append(xacmlAttrVal)

        # Update the XACML request context subject with the new attributes
        matchFound = False
        for attr in xacmlCtxSubject.attributes:
            matchFound = attr.attributeId == attributeId
            if matchFound:
                # Weed out duplicates
                newAttrVals = [attrVal
                               for attrVal in xacmlAttribute.attributeValues
                               if attrVal not in attr.attributeValues]
                attr.attributeValues.extend(newAttrVals)
                break

        if not matchFound:
            xacmlCtxSubject.attributes.append(xacmlAttribute)

        # Return the attributes to the caller to comply with the interface
        return xacmlAttribute.attributeValues
