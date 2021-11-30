"""NDG Attribute Authority server side code

handles security user attribute (role) queries

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "15/04/05"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:attributeauthority.py 4367 2008-10-29 09:27:59Z pjkersha $'
import logging
log = logging.getLogger(__name__)

import os
import re
import traceback

# SAML 2.0 Attribute Query Support - added 20/08/2009
from uuid import uuid4
from datetime import timedelta

from ndg.saml.utils import SAMLDateTime
from ndg.saml.saml2.core import (Response, Assertion, Attribute,
                                 AttributeStatement, SAMLVersion, Subject,
                                 NameID, Issuer, Conditions, AttributeQuery,
                                 XSStringAttributeValue, Status,
                                 StatusCode, StatusMessage)

from ndg.security.common.saml_utils.esgf import ESGFSamlNamespaces
from ndg.security.common.openssl import X500DN
from ndg.security.common.utils.classfactory import instantiateClass
from ndg.security.common.utils.factory import importModuleObject
from ndg.security.common.utils.configfileparsers import (
    CaseSensitiveConfigParser)


class AttributeAuthorityError(Exception):
    """Exception handling for NDG Attribute Authority class."""
    def __init__(self, msg):
        log.error(msg)
        Exception.__init__(self, msg)


class AttributeAuthorityConfigError(Exception):
    """NDG Attribute Authority error with configuration. e.g. properties file
    directory permissions or role mapping file"""
    def __init__(self, msg):
        log.error(msg)
        Exception.__init__(self, msg)


class AttributeAuthority(object):
    """NDG Attribute Authority - rewritten with a SAML 2.0 Attribute Query
    interface for Earth System Grid

    @type PROPERTY_DEFAULTS: dict
    @cvar PROPERTY_DEFAULTS: valid configuration property keywords

    @type ATTRIBUTE_INTERFACE_PROPERTY_DEFAULTS: dict
    @cvar ATTRIBUTE_INTERFACE_PROPERTY_DEFAULTS: valid configuration property
    keywords for the Attribute Interface plugin

    @type DEFAULT_CONFIG_DIRNAME: string
    @cvar DEFAULT_CONFIG_DIRNAME: configuration directory under $NDGSEC_DIR -
    default location for properties file

    @type DEFAULT_PROPERTY_FILENAME: string
    @cvar DEFAULT_PROPERTY_FILENAME: default file name for properties file
    under DEFAULT_CONFIG_DIRNAME

    @type ATTRIBUTE_INTERFACE_OPTPREFIX: basestring
    @param ATTRIBUTE_INTERFACE_OPTPREFIX: attribute interface parameters key
    name - see initAttributeInterface for details
    """

    DEFAULT_CONFIG_DIRNAME = "conf"
    DEFAULT_PROPERTY_FILENAME = "attributeAuthority.cfg"

    # Config file special parameters
    HERE_OPTNAME = 'here'
    PREFIX_OPTNAME = 'prefix'

    # Config file option names
    ISSUER_NAME_OPTNAME = 'issuerName'
    ASSERTION_LIFETIME_OPTNAME = 'assertionLifetime'

    ATTRIBUTE_INTERFACE_OPTPREFIX = 'attributeInterface'
    ATTRIBUTE_INTERFACE_MOD_FILEPATH_OPTNAME = 'modFilePath'
    ATTRIBUTE_INTERFACE_CLASSNAME_OPTNAME = 'className'

    CONFIG_LIST_SEP_PAT = re.compile(',\s*')


    ATTRIBUTE_INTERFACE_PROPERTY_DEFAULTS = {
        ATTRIBUTE_INTERFACE_MOD_FILEPATH_OPTNAME:  '',
        ATTRIBUTE_INTERFACE_CLASSNAME_OPTNAME:    ''
    }

    # valid configuration property keywords with accepted default values.
    # Values set to not NotImplemented here denote keys which must be specified
    # in the config
    PROPERTY_DEFAULTS = {
        ISSUER_NAME_OPTNAME:            '',
        ASSERTION_LIFETIME_OPTNAME:     -1,
        ATTRIBUTE_INTERFACE_OPTPREFIX:  ATTRIBUTE_INTERFACE_PROPERTY_DEFAULTS
    }

    __slots__ = (
        '__assertionLifetime',
        '__propFilePath',
        '__propFileSection',
        '__propPrefix',
        '__attributeInterface',
        '__attributeInterfaceCfg'
    )

    def __init__(self):
        """Create new Attribute Authority instance"""
        log.info("Initialising service ...")

        # Initial config file property based attributes
        self.__assertionLifetime = None

        self.__propFilePath = None
        self.__propFileSection = 'DEFAULT'
        self.__propPrefix = ''

        self.__attributeInterfaceCfg = \
                AttributeAuthority.ATTRIBUTE_INTERFACE_PROPERTY_DEFAULTS.copy()

    def __getstate__(self):
        '''Enable pickling with __slots__'''
        _dict = {}
        for attrName in AttributeAuthority.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_AttributeAuthority" + attrName

            _dict[attrName] = getattr(self, attrName)

        return _dict

    def __setstate__(self, attrDict):
        '''Enable pickling with __slots__'''
        for attrName, val in list(attrDict.items()):
            setattr(self, attrName, val)

    def _getAssertionLifetime(self):
        return self.__assertionLifetime

    def _setAssertionLifetime(self, value):
        if isinstance(value, float):
            self.__assertionLifetime = value

        elif isinstance(value, (str, int)):
            self.__assertionLifetime = float(value)
        else:
            raise TypeError('Expecting float, int, long or string type for '
                            '"assertionLifetime"; got %r' % type(value))

    def _getAttributeInterface(self):
        return self.__attributeInterface

    def _setAttributeInterface(self, value):
        if not isinstance(value, AttributeInterface):
            raise TypeError('Expecting %r type for "attributeInterface" '
                            'attribute; got %r' %
                            (AttributeInterface, type(value)))

        self.__attributeInterface = value

    def _get_attributeInterfaceCfg(self):
        return self.__attributeInterfaceCfg

    attributeInterfaceCfg = property(fget=_get_attributeInterfaceCfg,
                                     doc="Settings for Attribute Interface "
                                         "initialisation")

    def setPropFilePath(self, val=None):
        """Set properties file from input or based on environment variable
        settings

        @type val: basestring
        @param val: properties file path"""
        log.debug("Setting property file path")
        if not val:
            if 'NDGSEC_AA_PROPFILEPATH' in os.environ:
                val = os.environ['NDGSEC_AA_PROPFILEPATH']

            elif 'NDGSEC_DIR' in os.environ:
                val = os.path.join(os.environ['NDGSEC_DIR'],
                                   AttributeAuthority.DEFAULT_CONFIG_DIRNAME,
                                   AttributeAuthority.DEFAULT_PROPERTY_FILENAME)
            else:
                raise AttributeError('Unable to set default Attribute '
                                     'Authority properties file path: neither '
                                     '"NDGSEC_AA_PROPFILEPATH" or "NDGSEC_DIR"'
                                     ' environment variables are set')

        if not isinstance(val, str):
            raise AttributeError("Input Properties file path "
                                 "must be a valid string.")

        self.__propFilePath = os.path.expandvars(val)
        log.debug("Path set to: %s" % val)

    def getPropFilePath(self):
        '''Get the properties file path

        @rtype: basestring
        @return: properties file path'''
        return self.__propFilePath

    # Also set up as a property
    propFilePath = property(fset=setPropFilePath,
                            fget=getPropFilePath,
                            doc="path to file containing Attribute Authority "
                                "configuration parameters.  It defaults to "
                                "$NDGSEC_AA_PROPFILEPATH or if not set, "
                                "$NDGSEC_DIR/conf/attributeAuthority.cfg")

    def setPropFileSection(self, val=None):
        """Set section name to read properties from ini file.  This is set from
        input or based on environment variable setting
        NDGSEC_AA_PROPFILESECTION

        @type val: basestring
        @param val: section name"""
        if not val:
            val = os.environ.get('NDGSEC_AA_PROPFILESECTION', 'DEFAULT')

        if not isinstance(val, str):
            raise AttributeError("Input Properties file section name "
                                 "must be a valid string.")

        self.__propFileSection = val
        log.debug("Properties file section set to: \"%s\"" % val)

    def getPropFileSection(self):
        '''Get the section name to extract properties from an ini file -
        DOES NOT apply to XML file properties

        @rtype: basestring
        @return: section name'''
        return self.__propFileSection

    # Also set up as a property
    propFileSection = property(fset=setPropFileSection,
                               fget=getPropFileSection,
                               doc="Set the file section name for ini file "
                                   "properties")

    def setPropPrefix(self, val=None):
        """Set prefix for properties read from ini file.  This is set from
        input or based on environment variable setting
        NDGSEC_AA_PROPFILEPREFIX

        DOES NOT apply to XML file properties

        @type val: basestring
        @param val: section name"""
        log.debug("Setting property file section name")
        if val is None:
            val = os.environ.get('NDGSEC_AA_PROPFILEPREFIX', 'DEFAULT')

        if not isinstance(val, str):
            raise AttributeError("Input Properties file section name "
                                 "must be a valid string.")

        self.__propPrefix = val
        log.debug("Properties file section set to: %s" % val)

    def getPropPrefix(self):
        '''Get the prefix name used for properties in an ini file -
        DOES NOT apply to XML file properties

        @rtype: basestring
        @return: section name'''
        return self.__propPrefix


    # Also set up as a property
    propPrefix = property(fset=setPropPrefix,
                          fget=getPropPrefix,
                          doc="Set a prefix for ini file properties")

    assertionLifetime = property(fget=_getAssertionLifetime,
                                 fset=_setAssertionLifetime,
                                 doc="validity lifetime (s) for Attribute "
                                     "assertions issued")

    attributeInterface = property(fget=_getAttributeInterface,
                                  fset=_setAttributeInterface,
                                  doc="Attribute Interface object")

    @classmethod
    def fromPropertyFile(cls, propFilePath=None, section='DEFAULT',
                         prefix='attributeauthority.'):
        """Create new NDG Attribute Authority instance from the property file
        settings

        @type propFilePath: string
        @param propFilePath: path to file containing Attribute Authority
        configuration parameters.  It defaults to $NDGSEC_AA_PROPFILEPATH or
        if not set, $NDGSEC_DIR/conf/attributeAuthority.cfg
        @type section: basestring
        @param section: section of properties file to read from.
        properties files
        @type prefix: basestring
        @param prefix: set a prefix for filtering attribute authority
        property names - useful where properties are being parsed from a file
        section containing parameter names for more than one application
        """

        attributeAuthority = AttributeAuthority()
        if section:
            attributeAuthority.propFileSection = section

        if prefix:
            attributeAuthority.propPrefix = prefix

        # If path is None it will default to setting derived from environment
        # variable - see setPropFilePath()
        attributeAuthority.propFilePath = propFilePath

        attributeAuthority.readProperties()
        attributeAuthority.initialise()

        return attributeAuthority

    @classmethod
    def fromProperties(cls, prefix='attributeauthority.', **prop):
        """Create new NDG Attribute Authority instance from input property
        keywords

        @type propPrefix: basestring
        @param propPrefix: set a prefix for filtering attribute authority
        property names - useful where properties are being parsed from a file
        section containing parameter names for more than one application
        """
        attributeAuthority = AttributeAuthority()
        if prefix:
            attributeAuthority.propPrefix = prefix

        attributeAuthority.setProperties(**prop)
        attributeAuthority.initialise()

        return attributeAuthority

    def initialise(self):
        """Convenience method for set up of Attribute Interface, map
        configuration and PKI"""

        # Instantiate Certificate object
        log.debug("Reading and checking Attribute Authority X.509 cert. ...")

        # Load user - user attribute look-up plugin
        self.initAttributeInterface()

    def setProperties(self, **prop):
        """Set configuration from an input property dictionary
        @type prop: dict
        @param prop: properties dictionary containing configuration items
        to be set
        """
        lenPropPrefix = len(self.propPrefix)

        # '+ 1' allows for the dot separator
        lenAttributeInterfacePrefix = len(
                        AttributeAuthority.ATTRIBUTE_INTERFACE_OPTPREFIX) + 1

        for name, val in list(prop.items()):
            if name.startswith(self.propPrefix):
                name = name[lenPropPrefix:]

            if name.startswith(
                            AttributeAuthority.ATTRIBUTE_INTERFACE_OPTPREFIX):
                name = name[lenAttributeInterfacePrefix:]
                self.attributeInterfaceCfg[name] = val
                continue

            if name not in AttributeAuthority.PROPERTY_DEFAULTS:
                raise AttributeError('Invalid attribute name "%s"' % name)

            if isinstance(val, str):
                val = os.path.expandvars(val)

            if isinstance(AttributeAuthority.PROPERTY_DEFAULTS[name], list):
                val = AttributeAuthority.CONFIG_LIST_SEP_PAT.split(val)

            # This makes an implicit call to the appropriate property method
            try:
                setattr(self, name, val)
            except AttributeError:
                raise AttributeError("Can't set attribute \"%s\": %s" %
                                     (name, traceback.format_exc()))

    def readProperties(self):
        '''Read the properties files and do some checking/converting of input
        values
        '''
        if not os.path.isfile(self.propFilePath):
            raise IOError('Error parsing properties file "%s": No such file' %
                          self.propFilePath)

        defaultItems = {
            AttributeAuthority.HERE_OPTNAME: os.path.dirname(self.propFilePath)
        }

        cfg = CaseSensitiveConfigParser(defaults=defaultItems)
        cfg.read(self.propFilePath)

        if cfg.has_option(self.propFileSection,
                          AttributeAuthority.PREFIX_OPTNAME):
            self.propPrefix = cfg.get(self.propFileSection,
                                      AttributeAuthority.PREFIX_OPTNAME)

        cfgItems = dict([(name, val)
                         for name, val in cfg.items(self.propFileSection)
                         if (name != AttributeAuthority.HERE_OPTNAME and
                             name != AttributeAuthority.PREFIX_OPTNAME)])
        self.setProperties(**cfgItems)

    def initAttributeInterface(self):
        '''Load host sites custom user roles interface to enable the AA to
        # assign roles in an attribute certificate on a getAttCert request'''
        classProperties = {}
        classProperties.update(self.attributeInterfaceCfg)

        className = classProperties.pop('className', None)
        if className is None:
            raise AttributeAuthorityConfigError('No Attribute Interface '
                                                '"className" property set')

        # file path may be omitted
        modFilePath = classProperties.pop('modFilePath', None)

        self.__attributeInterface = instantiateClass(className,
                                             moduleFilePath=modFilePath,
                                             objectType=AttributeInterface,
                                             classProperties=classProperties)

    def samlAttributeQuery(self, attributeQuery, samlResponse):
        """Respond to SAML 2.0 Attribute Query.  This method follows the
        signature for the SAML query interface:

        ndg.saml.saml2.binding.soap.server.wsgi.queryinterface.SOAPQueryInterfaceMiddleware

        @param attributeQuery: SAML attribute query to process
        @type attributeQuery: ndg.saml.saml2.core.AttributeQuery
        @param samlResponse: partially filled out SAML response.  This method
        completes it
        @type samlResponse: ndg.saml.saml2.core.Response
        """
        if not isinstance(attributeQuery, AttributeQuery):
            raise TypeError('Expecting %r for attribute query; got %r' %
                            (AttributeQuery, type(attributeQuery)))

        # Attribute Query validation ...
        if (attributeQuery.subject.nameID.format !=
            ESGFSamlNamespaces.NAMEID_FORMAT):
            log.error('SAML Attribute Query subject format is %r; expecting '
                      '%r' % (attributeQuery.subject.nameID.format,
                                ESGFSamlNamespaces.NAMEID_FORMAT))

            samlResponse.status.statusCode.value = StatusCode.REQUESTER_URI
            samlResponse.status.statusMessage.value = \
                                "Subject Name ID format is not recognised"
            return samlResponse

        elif attributeQuery.issuer.format != Issuer.X509_SUBJECT:
            log.error('SAML Attribute Query issuer format is %r; expecting '
                      '%r' % (attributeQuery.issuer.format,
                              Issuer.X509_SUBJECT))
            samlResponse.status.statusCode.value = StatusCode.REQUESTER_URI
            samlResponse.status.statusMessage.value = \
                                            "Issuer format is not recognised"
            return samlResponse

        try:
            # Return a dictionary of name, value pairs
            self.attributeInterface.getAttributes(attributeQuery, samlResponse)

        except InvalidUserId as e:
            log.exception(e)
            samlResponse.status.statusCode.value = \
                                        StatusCode.UNKNOWN_PRINCIPAL_URI
            return samlResponse

        except UserIdNotKnown as e:
            log.exception(e)
            samlResponse.status.statusCode.value = \
                                        StatusCode.UNKNOWN_PRINCIPAL_URI
            samlResponse.status.statusMessage.value = str(e)
            return samlResponse

        except InvalidRequestorId as e:
            log.exception(e)
            samlResponse.status.statusCode.value = StatusCode.REQUEST_DENIED_URI
            samlResponse.status.statusMessage.value = str(e)
            return samlResponse

        except AttributeReleaseDenied as e:
            log.exception(e)
            samlResponse.status.statusCode.value = \
                                        StatusCode.INVALID_ATTR_NAME_VALUE_URI
            samlResponse.status.statusMessage.value = str(e)
            return samlResponse

        except AttributeNotKnownError as e:
            log.exception(e)
            samlResponse.status.statusCode.value = \
                                        StatusCode.INVALID_ATTR_NAME_VALUE_URI
            samlResponse.status.statusMessage.value = str(e)
            return samlResponse

        except Exception as e:
            log.exception("Unexpected error calling Attribute Interface "
                          "for subject [%s] and query issuer [%s]" %
                          (attributeQuery.subject.nameID.value,
                           attributeQuery.issuer.value))

            # SAML spec says application server should set a HTTP 500 Internal
            # Server error in this case
            raise

        return samlResponse

    def samlAttributeQueryFactory(self):
        """Factory method to create SAML Attribute Query wrapper function
        @rtype: function
        @return: samlAttributeQuery method function wrapper
        """
        def samlAttributeQueryWrapper(attributeQuery, response):
            """Attribute Query method.  This must adhere to the function
            signature specified by
            ndg.security.server.wsgi.saml.SOAPQueryInterfaceMiddleware
            @type attributeQuery: ndg.saml.saml2.core.AttributeQuery
            @param attributeQuery: SAML Attribute Query
            @rtype: ndg.saml.saml2.core.Response
            @return: SAML response
            """
            return self.samlAttributeQuery(attributeQuery, response)

        return samlAttributeQueryWrapper


class AttributeInterfaceError(Exception):
    """Exception handling for NDG Attribute Authority User Roles interface
    class."""


class AttributeInterfaceConfigError(AttributeInterfaceError):
    """Invalid configuration set for Attribute interface"""


class AttributeInterfaceRetrieveError(AttributeInterfaceError):
    """Error retrieving attributes for Attribute interface class"""


class AttributeReleaseDenied(AttributeInterfaceError):
    """Requestor was denied release of the requested attributes"""


class AttributeNotKnownError(AttributeInterfaceError):
    """Requested attribute names are not known to this authority"""


class InvalidRequestorId(AttributeInterfaceError):
    """Requestor is not known or not allowed to request attributes"""


class UserIdNotKnown(AttributeInterfaceError):
    """User ID passed to getAttributes is not known to the authority"""


class InvalidUserId(AttributeInterfaceError):
    """User Id passed to getAttributes is invalid"""


class AttributeInterface(object):
    """An abstract base class to define the user roles interface to an
    Attribute Authority.

    Each NDG data centre should implement a derived class which implements
    the way user roles are provided to its representative Attribute Authority.

    Roles are expected to indexed by user Distinguished Name (DN).  They
    could be stored in a database or file."""

    # User defined class may wish to specify a URI for a database interface or
    # path for a user roles configuration file
    def __init__(self, **prop):
        """User Roles base class - derive from this class to define
        roles interface to Attribute Authority

        @type prop: dict
        @param prop: custom properties to pass to this class
        """

    def getRoles(self, userId):
        """Virtual method - Derived method should return the roles for the
        given user's Id or else raise an exception

        @type userId: string
        @param userId: user identity e.g. user Distinguished Name
        @rtype: list
        @return: list of roles for the given user ID
        @raise AttributeInterfaceError: an error occured requesting
        attributes
        """
        raise NotImplementedError(self.getRoles.__doc__)

    def getAttributes(self, attributeQuery, response):
        """Virtual method should be implemented in a derived class to enable
        AttributeAuthority.samlAttributeQuery - The derived method should
        return the attributes requested for the given user's Id or else raise
        an exception

        @type attributeQuery: saml.saml2.core.AttributeQuery
        @param userId: query containing requested attributes
        @type: saml.saml2.core.Response
        @param: Response - add an assertion with the list of attributes
        for the given subject ID in the query or set an error Status code and
        message
        @raise AttributeInterfaceError: an error occured requesting
        attributes
        @raise AttributeReleaseDeniedError: Requestor was denied release of the
        requested attributes
        @raise AttributeNotKnownError: Requested attribute names are not known
        to this authority
        """
        raise NotImplementedError(self.getAttributes.__doc__)


class CSVFileAttributeInterface(AttributeInterface):
    """Attribute Interface based on a Comma Separated Variable file containing
    user identities and associated attributes.  For test/development purposes
    only.  The SAML getAttributes method is NOT implemented here

    The expected file format is:

    <userID>, <role1>, <role2>, ... <roleN>
    """
    def __init__(self, propertiesFilePath=None):
        """
        @param propertiesFilePath: file path to Comma Separated file
        containing user ids and roles
        @type propertiesFilePath: basestring
        """
        if propertiesFilePath is None:
            raise AttributeError("Expecting propertiesFilePath setting")

        propertiesFile = open(propertiesFilePath)
        lines = propertiesFile.readlines()

        self.attributeMap = {}
        for line in lines:
            fields = re.split(',\s*', line.strip())
            self.attributeMap[fields[0]] = fields[1:]

    def getRoles(self, userId):
        """
        @param userId: user identity to key into attributeMap
        @type userId: basestring
        """
        log.debug('CSVFileAttributeInterface.getRoles for user "%s" ...',
                  userId)
        return self.attributeMap.get(userId, [])


# Properties file
from configparser import SafeConfigParser, NoOptionError

try:
    # PostgreSQL interface
    from psycopg2 import connect
except ImportError:
    pass


import traceback
from string import Template
try:
    from sqlalchemy import create_engine, exc, sql
    sqlAlchemyInstalled = True
except ImportError:
    sqlAlchemyInstalled = False


class SQLAlchemyAttributeInterface(AttributeInterface):
    '''SQLAlchemy based Attribute interface enables the Attribute Authority
    to interface to any database type supported by it

    @type SQLQUERY_USERID_KEYNAME: basestring
    @cvar SQLQUERY_USERID_KEYNAME: key corresponding to string to be
    substituted into attribute query for user identifier e.g.

    select attr from user_table where username = $userId

    @type SAML_VALID_REQUESTOR_DNS_PAT: _sre.SRE_Pattern
    @param SAML_VALID_REQUESTOR_DNS_PAT: regular expression to split list of
    SAML requestor DNs.  These must comma separated.  Each comma may be
    separated by any white space including new line characters
    '''
    DEFAULT_SAML_ASSERTION_LIFETIME = timedelta(seconds=60*60*8)

    SQLQUERY_USERID_KEYNAME = 'userId'

    ISSUER_NAME_FORMAT = Issuer.X509_SUBJECT
    CONNECTION_STRING_OPTNAME = 'connectionString'
    ATTRIBUTE_SQLQUERY_OPTNAME = 'attributeSqlQuery'
    SAML_SUBJECT_SQLQUERY_OPTNAME = 'samlSubjectSqlQuery'
    SAML_VALID_REQUESTOR_DNS_OPTNAME = 'samlValidRequestorDNs'
    SAML_ASSERTION_LIFETIME_OPTNAME = 'samlAssertionLifetime'
    SAML_ATTRIBUTE2SQLQUERY_OPTNAME = 'samlAttribute2SqlQuery'
    
    OPTNAMES = (
        CONNECTION_STRING_OPTNAME,
        ATTRIBUTE_SQLQUERY_OPTNAME,
        SAML_SUBJECT_SQLQUERY_OPTNAME,
        SAML_VALID_REQUESTOR_DNS_OPTNAME,
        SAML_ASSERTION_LIFETIME_OPTNAME,
        SAML_ATTRIBUTE2SQLQUERY_OPTNAME        
        )
    SAML_ATTRIBUTE2SQLQUERY_OPTNAME_LEN = len(SAML_ATTRIBUTE2SQLQUERY_OPTNAME)

    SAML_ATTRIBUTE2SQLQUERY_ATTRNAME_DELIMITERS = ('.', '_')
    SAML_ATTRIBUTE2SQLQUERY_ATTRVAL_PAT = re.compile('\"\W+\"')

#    For Reference - split based on space separated ' or " quoted items
#    SAML_VALID_REQUESTOR_DNS_PAT = re.compile("['\"]?\s*['\"]")

    SAML_VALID_REQUESTOR_DNS_PAT = re.compile(',\s*')

    def __init__(self, **properties):
        '''Instantiate object taking in settings from the input properties'''
        log.debug('Initialising SQLAlchemyAttributeInterface instance ...')

        if not sqlAlchemyInstalled:
            raise AttributeInterfaceConfigError("SQLAlchemy is not installed")

        self.__connectionString = None
        self.__attributeSqlQuery = None
        self.__samlSubjectSqlQuery = None
        self.__samlValidRequestorDNs = []
        self.__samlAssertionLifetime = \
            SQLAlchemyAttributeInterface.DEFAULT_SAML_ASSERTION_LIFETIME
        self.__samlAttribute2SqlQuery = {}

        self.setProperties(**properties)

    def __setattr__(self, name, value):
        """Provide a way to set the attribute map by dynamically handling
        attribute names containing the SAML attribute name as a suffix e.g.

        attributeInterface.samlAttribute2SqlQuery_firstName = 'Philip'

        will update __samlAttribute2SqlQuery with the 'firstName', 'Philip'
        key value pair.  Similarly,

        setattr('samlAttribute2SqlQuery.emailAddress', 'pjk@somewhere.ac.uk')

        sets __samlAttribute2SqlQuery with the 'emailAddress',
        'pjk@somewhere.ac.uk' key value pair

        This is useful in enabling settings to be made direct from a dict of
        option name and values parsed from an ini file.
        """
        cls = SQLAlchemyAttributeInterface

        if name == cls.SAML_ATTRIBUTE2SQLQUERY_OPTNAME:
            for attribute_name in value:
                attribute_sql_query = value.get(attribute_name)
                if not isinstance(attribute_name, str):
                    raise TypeError('Expecting string type for \'{}\' attribute'
                                    ' name; got {}'.format(
                                        cls.SAML_ATTRIBUTE2SQLQUERY_OPTNAME,
                                        type(attribute_name)))

                if not isinstance(attribute_sql_query, str):
                    raise TypeError('Expecting string type for \'{}\' attribute'
                                    ' SQL query; got {}'.format(
                                        cls.SAML_ATTRIBUTE2SQLQUERY_OPTNAME,
                                        type(attribute_sql_query)))

                self.__samlAttribute2SqlQuery[attribute_name] = (
                    attribute_sql_query,
                    self.xsstringAttributeValueParser
                    )

        elif max([name.endswith(opt_name) for opt_name in cls.OPTNAMES]):
            object.__setattr__(self, name, value)

        elif (len(name) > cls.SAML_ATTRIBUTE2SQLQUERY_OPTNAME_LEN and
              name[cls.SAML_ATTRIBUTE2SQLQUERY_OPTNAME_LEN] in
              cls.SAML_ATTRIBUTE2SQLQUERY_ATTRNAME_DELIMITERS):
            # A special 'samlAttribute2SqlQuery[._]+' attribute name has been
            # found.  The first item is the attribute name and the second, the
            # corresponding SQL query to get the values corresponding to that
            # name.  An optional 3rd element is a callback which converts the
            # retrieved SQL query result to required the attribute value type.
            # This defaults to do a conversion to XS:String if not explicitly
            # set
            _value = value.strip()
            attr2sqlQueryOpts = [v.strip('"') for v in
                self.__class__.SAML_ATTRIBUTE2SQLQUERY_ATTRVAL_PAT.split(_value)
                ]
            if len(attr2sqlQueryOpts) > 2:
                (samlAttributeName,
                 samlAttributeSqlQuery,
                 samlAttributeValueParserName) = attr2sqlQueryOpts

                # Get parser from module path provided
                samlAttributeParser = importModuleObject(
                                                samlAttributeValueParserName)
            else:
                # No attribute value conversion callback given - default to
                # XS:String
                try:
                    samlAttributeName, samlAttributeSqlQuery = attr2sqlQueryOpts
                except ValueError:
                    raise AttributeAuthorityConfigError(
                        'For \'samlAttribute2SqlQuery\' attribute, expecting '
                        'string with format: \'"attribute name id" '
                        '"SQL query to retrieve attribute"\'')

                samlAttributeParser = self.xsstringAttributeValueParser

            # Set mapping of attribute name to SQL query + conversion routine
            # tuple
            self.__samlAttribute2SqlQuery[samlAttributeName] = (
                                    samlAttributeSqlQuery, samlAttributeParser)
        else:
            raise AttributeError("'SQLAlchemyAttributeInterface' has no "
                                 "attribute %r" % name)

    def xsstringAttributeValueParser(self, attrVal):
        """Convert string attribute value retrieved from database query into
        the respective SAML Attribute Value type
        """
        xsstringAttrVal = XSStringAttributeValue()
        xsstringAttrVal.value = attrVal
        return xsstringAttrVal

    def setProperties(self, prefix='', **properties):
        for name, val in list(properties.items()):
            if prefix:
                if name.startswith(prefix):
                    name = name.replace(prefix, '', 1)
                    setattr(self, name, val)
            else:
                setattr(self, name, val)

    def _getSamlAssertionLifetime(self):
        return self.__samlAssertionLifetime

    def _setSamlAssertionLifetime(self, value):
        if isinstance(value, timedelta):
            self.__samlAssertionLifetime = value

        if isinstance(value, (float, int)):
            self.__samlAssertionLifetime = timedelta(seconds=value)

        elif isinstance(value, str):
            self.__samlAssertionLifetime = timedelta(seconds=float(value))
        else:
            raise TypeError('Expecting float, int, long, string or timedelta '
                'type for "%s"; got %r' %
                (SQLAlchemyAttributeInterface.SAML_ASSERTION_LIFETIME_OPTNAME,
                 type(value)))

    samlAssertionLifetime = property(_getSamlAssertionLifetime,
                                     _setSamlAssertionLifetime,
                                     doc="Time validity for SAML Assertion "
                                         "set in SAML Response returned from "
                                         "getAttributes")

    def _getSamlSubjectSqlQuery(self):
        return self.__samlSubjectSqlQuery

    def _setSamlSubjectSqlQuery(self, value):
        if not isinstance(value, str):
            raise TypeError('Expecting string type for "%s" attribute; got %r'%
                    (SQLAlchemyAttributeInterface.SAML_SUBJECT_SQLQUERY_OPTNAME,
                     type(value)))

        self.__samlSubjectSqlQuery = value

    def _getSamlValidRequestorDNs(self):
        return self.__samlValidRequestorDNs

    def _setSamlValidRequestorDNs(self, value):
        if isinstance(value, str):

            pat = SQLAlchemyAttributeInterface.SAML_VALID_REQUESTOR_DNS_PAT
            self.__samlValidRequestorDNs = [
                X500DN.from_string(dn) for dn in pat.split(value)
            ]

        elif isinstance(value, (tuple, list)):
            self.__samlValidRequestorDNs = [X500DN.from_string(dn)
                                            for dn in value]
        else:
            raise TypeError('Expecting list/tuple or basestring type for "%s" '
                'attribute; got %r' %
                (SQLAlchemyAttributeInterface.SAML_VALID_REQUESTOR_DNS_OPTNAME,
                 type(value)))

    samlValidRequestorDNs = property(_getSamlValidRequestorDNs,
                                     _setSamlValidRequestorDNs,
                                     doc="list of certificate Distinguished "
                                         "Names referring to the client "
                                         "identities permitted to query the "
                                         "Attribute Authority via the SAML "
                                         "Attribute Query interface")

    def _getConnectionString(self):
        return self.__connectionString

    def _setConnectionString(self, value):
        if not isinstance(value, str):
            raise TypeError('Expecting string type for "%s" attribute; got %r'%
                        (SQLAlchemyAttributeInterface.CONNECTION_STRING_OPTNAME,
                         type(value)))
        self.__connectionString = value

    connectionString = property(fget=_getConnectionString,
                                fset=_setConnectionString,
                                doc="Database connection string")

    def _getAttributeSqlQuery(self):
        return self.__attributeSqlQuery

    def _setAttributeSqlQuery(self, value):
        if not isinstance(value, str):
            raise TypeError('Expecting string type for "%s" attribute; got %r'%
                    (SQLAlchemyAttributeInterface.ATTRIBUTE_SQLQUERY_OPTNAME,
                     type(value)))
        self.__attributeSqlQuery = value

    attributeSqlQuery = property(fget=_getAttributeSqlQuery,
                                 fset=_setAttributeSqlQuery,
                                 doc="SQL Query for attribute query")

    def getRoles(self, userId):
        """Return valid roles for the given userId

        @type userId: basestring
        @param userId: user identity
        @rtype: list
        @return: list of roles for the given user
        """
        query_inputs = {
            SQLAlchemyAttributeInterface.SQLQUERY_USERID_KEYNAME: userId
        }
        query = Template(self.attributeSqlQuery).substitute(query_inputs)

        dbEngine = create_engine(self.connectionString)
        connection = dbEngine.connect()

        try:
            filtered_query = sql.text(query)
            result = connection.execute(filtered_query, userId=userId)

            try:
                attributes = [attr for attr in result][0][0]

            except (IndexError, TypeError):
                raise AttributeInterfaceRetrieveError(
                                                "Error with result set: %s" %
                                                traceback.format_exc())
        except exc.ProgrammingError:
            raise AttributeInterfaceRetrieveError("Error with SQL Syntax: %s" %
                                                  traceback.format_exc())
        finally:
            connection.close()

        log.debug('Attributes=%r retrieved for user=%r' % (attributes,
                                                           userId))

        return attributes

    def getAttributes(self, attributeQuery, response):
        """Attribute Authority SAML AttributeQuery

        @type attributeQuery: saml.saml2.core.AttributeQuery
        @param userId: query containing requested attributes
        @type response: saml.saml2.core.Response
        @param response: add an assertion with the list of attributes
        for the given subject ID in the query or set an error Status code and
        message
        @raise AttributeInterfaceError: an error occured requesting
        attributes
        @raise AttributeReleaseDeniedError: Requestor was denied release of the
        requested attributes
        @raise AttributeNotKnownError: Requested attribute names are not known
        to this authority
        """
        userId = attributeQuery.subject.nameID.value
        requestedAttributeNames = [attribute.name
                                   for attribute in attributeQuery.attributes]

        requestorDN = X500DN.from_string(attributeQuery.issuer.value)

        if not self._queryDbForSamlSubject(userId):
            raise UserIdNotKnown('Subject Id "%s" is not known to this '
                                 'authority' % userId)

        if (len(self.samlValidRequestorDNs) > 0 and
            requestorDN not in self.samlValidRequestorDNs):
            raise InvalidRequestorId('Requester identity "%s" is invalid' %
                                     requestorDN)

        unknownAttrNames = [attrName for attrName in requestedAttributeNames
                            if attrName not in self.__samlAttribute2SqlQuery]

        if len(unknownAttrNames) > 0:
            raise AttributeNotKnownError("Unknown attributes requested: %r" %
                                         unknownAttrNames)

        # Create a new assertion to hold the attributes to be returned
        assertion = Assertion()

        assertion.version = SAMLVersion(SAMLVersion.VERSION_20)
        assertion.id = str(uuid4())
        assertion.issueInstant = response.issueInstant

        # Assumes SAML response issuer details as set by -
        # ndg.security.server.wsgi.saml.SOAPQueryInterfaceMiddleware
        assertion.issuer = Issuer()
        assertion.issuer.value = response.issuer.value

        if response.issuer.format:
            assertion.issuer.format = response.issuer.format

        assertion.conditions = Conditions()
        assertion.conditions.notBefore = assertion.issueInstant
        assertion.conditions.notOnOrAfter = (assertion.conditions.notBefore +
                                             self.samlAssertionLifetime)

        assertion.subject = Subject()
        assertion.subject.nameID = NameID()
        assertion.subject.nameID.format = attributeQuery.subject.nameID.format
        assertion.subject.nameID.value = attributeQuery.subject.nameID.value

        attributeStatement = AttributeStatement()

        # Query the database for the requested attributes and return them
        # mapped to their attribute names as specified by the attributeNames
        # property
        for requestedAttribute in attributeQuery.attributes:
            attributeVals = self._queryDbForSamlAttributes(
                                                    requestedAttribute.name,
                                                    userId)

            # Make a new SAML attribute object to hold the values obtained
            attribute = Attribute()
            attribute.name = requestedAttribute.name
            attribute.nameFormat = requestedAttribute.nameFormat

            if requestedAttribute.friendlyName is not None:
                attribute.friendlyName = requestedAttribute.friendlyName

            # Call specific conversion utility to convert the retrieved field
            # to the correct SAML attribute value type
            try:
                field2SamlAttributeVal = self.__samlAttribute2SqlQuery[
                                        requestedAttribute.name][-1]
            except (IndexError, TypeError) as e:
                raise AttributeInterfaceConfigError('Bad format for SAML '
                                                    'attribute to SQL query '
                                                    'look-up for attribute '
                                                    'name %r: %s' %
                                                    (requestedAttribute.name,
                                                    e))

            for val in attributeVals:
                attributeValue = field2SamlAttributeVal(val)
                attribute.attributeValues.append(attributeValue)

            attributeStatement.attributes.append(attribute)

        assertion.attributeStatements.append(attributeStatement)
        response.assertions.append(assertion)

    def _queryDbForSamlSubject(self, userId):
        """Check a given SAML subject (user) is registered in the database.
        This method is called from the getAttributes() method

        @type userId: basestring
        @param userId: user identity
        @rtype: bool
        @return: True/False is user registered?
        """
        if self.samlSubjectSqlQuery is None:
            log.debug('No "self.samlSubjectSqlQuery" property has been set, '
                      'skipping SAML subject query step')
            return True

        if self.connectionString is None:
            raise AttributeInterfaceConfigError('No "connectionString" setting '
                                                'has been made')

        dbEngine = create_engine(self.connectionString)

        try:
            query_inputs = {
                SQLAlchemyAttributeInterface.SQLQUERY_USERID_KEYNAME: userId
            }
            query = Template(self.samlSubjectSqlQuery).substitute(query_inputs)

        except KeyError:
            raise AttributeInterfaceConfigError("Invalid key for SAML subject "
                        "query string.  The valid key is %r" %
                        SQLAlchemyAttributeInterface.SQLQUERY_USERID_KEYNAME)

        log.debug('Checking for SAML subject with SQL Query = "%s"', query)

        connection = dbEngine.connect()

        try:
            filtered_query = sql.text(query)
            result = connection.execute(filtered_query, userId=userId)

            try:
                found = [entry for entry in result][0][0] > 0

            except (IndexError, TypeError):
                raise AttributeInterfaceRetrieveError(
                                                "Error with result set: %s" %
                                                traceback.format_exc())

        except (exc.ProgrammingError, exc.OperationalError):
            raise AttributeInterfaceRetrieveError('SQL error: %s' %
                                                  traceback.format_exc())
        finally:
            connection.close()

        log.debug('user=%r found=%r' % (userId, found))

        return found

    def _queryDbForSamlAttributes(self, attributeName, userId):
        """Query the database in response to a SAML attribute query

        This method is called from the getAttributes() method

        @type userId: basestring
        @param userId: user identity
        @rtype: bool
        @return: True/False is user registered?
        """

        if self.connectionString is None:
            raise AttributeInterfaceConfigError('No "connectionString" setting '
                                                'has been made')

        dbEngine = create_engine(self.connectionString)

        try:
            query_tmpl = self.__samlAttribute2SqlQuery.get(attributeName)[0]

        except (IndexError, TypeError) as e:
            raise AttributeInterfaceConfigError('Bad format for SAML attribute '
                                                'to SQL query look-up: %s' % e)
        if query_tmpl is None:
            raise AttributeInterfaceConfigError('No SQL query set for '
                                                'attribute %r' % attributeName)

        try:
            query_inputs = {
                SQLAlchemyAttributeInterface.SQLQUERY_USERID_KEYNAME: userId
            }
            query = Template(query_tmpl).substitute(query_inputs)

        except KeyError as e:
            raise AttributeInterfaceConfigError("Invalid key %s for SAML "
                        "attribute query string.  The valid key is %r" %
                        (e,
                         SQLAlchemyAttributeInterface.SQLQUERY_USERID_KEYNAME))

        log.debug('Checking for SAML attributes with SQL Query = "%s"', query)

        connection = dbEngine.connect()

        try:
            filtered_query = sql.text(query)
            result = connection.execute(filtered_query, userId=userId)

            try:
                attributeValues = [entry[0] for entry in result]

            except (IndexError, TypeError):
                raise AttributeInterfaceRetrieveError("Error with result set: "
                                                      "%s" %
                                                      traceback.format_exc())
        except (exc.ProgrammingError, exc.OperationalError):
            raise AttributeInterfaceRetrieveError('SQL error: %s' %
                                                  traceback.format_exc())
        finally:
            connection.close()

        log.debug('Database results for SAML Attribute query user=%r '
                  'attribute values=%r' % (userId, attributeValues))

        return attributeValues

    def __getstate__(self):
        '''Explicit pickling required with __slots__'''
        return dict([(attrName, getattr(self, attrName))
                      for attrName in SQLAlchemyAttributeInterface.__slots__])

    def __setstate__(self, attrDict):
        '''Enable pickling for use with beaker.session'''
        for attr, val in list(attrDict.items()):
            setattr(self, attr, val)



