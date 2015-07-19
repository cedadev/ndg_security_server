"""X.509 certificate extension application for adding SAML assertions into
certificates issued by MyProxy

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "29/10/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

import traceback
from string import Template

from sqlalchemy import create_engine, exc
from ConfigParser import ConfigParser

from ndg.security.common.config import Config, importElementTree
ElementTree = importElementTree()

from ndg.saml.utils import SAMLDateTime
from ndg.saml.common.xml import SAMLConstants
from ndg.saml.saml2.core import (Attribute, 
                             SAMLVersion, 
                             Subject, 
                             NameID, 
                             Issuer, 
                             AttributeQuery, 
                             XSStringAttributeValue, 
                             Status,
                             StatusCode,
                             StatusMessage)
from ndg.saml.xml.etree import AssertionElementTree, ResponseElementTree
   
from ndg.saml.saml2.binding.soap.client.attributequery import \
                                                AttributeQuerySslSOAPBinding
from ndg.security.common.saml_utils.esgf import (ESGFSamlNamespaces,
                                                ESGFDefaultQueryAttributes)
from ndg.security.common.utils.etree import prettyPrint
from ndg.security.common.openssl import X500DN
from ndg.security.common.utils.configfileparsers import (     
                                                    CaseSensitiveConfigParser,)

class CertExtAppError(Exception):
    """Base class for CertExtApp class exceptions"""
    
    
class CertExtAppConfigError(CertExtAppError):
    """Configuration fault for CertExtApp instance"""


class CertExtAppRetrieveError(CertExtAppError):
    """Error retrieving results from user database or attribute authority"""
    

class CertExtAppSqlError(CertExtAppError):   
    """Error with SQL query syntax"""
    
    
class CertExtAppSamlResponseError(CertExtAppError):
    """Attribute Authority returned a SAML Response error code"""
    def __init__(self, *arg, **kw):
        CertExtAppError.__init__(self, *arg, **kw)
        self.__status = Status()
        self.__status.statusCode = StatusCode()
        self.__status.statusMessage = StatusMessage()
    
    def _getStatus(self):
        '''Gets the Status of this response.
        
        @return the Status of this response
        '''
        return self.__status

    def _setStatus(self, value):
        '''Sets the Status of this response.
        
        @param value: the Status of this response
        '''
        if not isinstance(value, Status):
            raise TypeError('"status" must be a %r, got %r' % (Status,
                                                               type(value)))
        self.__status = value
        
    status = property(fget=_getStatus, fset=_setStatus, 
                      doc="Attribute Authority SAML Response error status")
    
    def __str__(self):
        if self.status is not None:
            return self.status.statusMessage.value or ''
        else:
            return ''
    
           
class CertExtApp(object):
    """Application to create a X.509 certificate extension containing a SAML
    assertion for inclusion by MyProxy into an issued certificate
    """
    DEFAULT_QUERY_ATTRIBUTES = ESGFDefaultQueryAttributes.ATTRIBUTES
    N_DEFAULT_QUERY_ATTRIBUTES = len(DEFAULT_QUERY_ATTRIBUTES)
    ESG_NAME_ID_FORMAT = ESGFSamlNamespaces.NAMEID_FORMAT
    
    CONNECTION_STRING_OPTNAME = 'connectionString'
    OPENID_SQLQUERY_OPTNAME = 'openIdSqlQuery'
    ATTRIBUTE_AUTHORITY_URI_OPTNAME = 'attributeAuthorityURI'
    
    CONFIG_FILE_OPTNAMES = (
        ATTRIBUTE_AUTHORITY_URI_OPTNAME,
        CONNECTION_STRING_OPTNAME,
        OPENID_SQLQUERY_OPTNAME,
    )
    ATTRIBUTE_QUERY_ATTRNAME = 'attributeQuery'
    LEN_ATTRIBUTE_QUERY_ATTRNAME = len(ATTRIBUTE_QUERY_ATTRNAME)
    __PRIVATE_ATTR_PREFIX = '__'
    __slots__ = tuple(
        [__PRIVATE_ATTR_PREFIX + i 
         for i in CONFIG_FILE_OPTNAMES + (ATTRIBUTE_QUERY_ATTRNAME,)]
    )
    del i
    
    def __init__(self):
        self.__attributeAuthorityURI = None
        self.__connectionString = None
        self.__openIdSqlQuery = None
        self.__attributeQuery = AttributeQuerySslSOAPBinding() 

    @classmethod
    def fromConfigFile(cls, configFilePath, **kw):
        '''Alternative constructor makes object from config file settings
        @type configFilePath: basestring
        @param configFilePath: configuration file path
        '''
        certExtApp = cls()
        certExtApp.readConfig(configFilePath, **kw)
        
        return certExtApp
        
    def __call__(self, username):
        """Main method - create SAML assertion by querying the user's OpenID
        identifier from the user database and using this to query the 
        Attribute Authority for attributes
        """
        self.__attributeQuery.subjectID = self.queryOpenId(username)
        response = self.__attributeQuery.send(uri=self.attributeAuthorityURI)
        
        try:
            assertionStr = self.serialiseAssertion(response.assertions[0])
            
        except (IndexError, TypeError):
            raise CertExtAppRetrieveError("Error accessing assertion from "
                                          "Attribute Authority SAML response: "
                                          "%s" % traceback.format_exc())
            
        return assertionStr

    def readConfig(self, cfg, prefix='', section='DEFAULT'):
        '''Read config file settings
        @type cfg: basestring /ConfigParser derived type
        @param cfg: configuration file path or ConfigParser type object
        @type prefix: basestring
        @param prefix: prefix for option names e.g. "certExtApp."
        @type section: baestring
        @param section: configuration file section from which to extract
        parameters.
        '''
        if isinstance(cfg, basestring):
            cfgFilePath = os.path.expandvars(cfg)
            _cfg = CaseSensitiveConfigParser()
            _cfg.read(cfgFilePath)
            
        elif isinstance(cfg, ConfigParser):
            _cfg = cfg   
        else:
            raise AttributeError('Expecting basestring or ConfigParser type '
                                 'for "cfg" attribute; got %r type' % type(cfg))
        
        prefixLen = len(prefix)
        for optName, val in _cfg.items(section):
            if prefix:
                # Filter attributes based on prefix
                if optName.startswith(prefix):
                    setattr(self, optName[prefixLen:], val)
            else:
                # No prefix set - attempt to set all attributes   
                setattr(self, optName, val)
            
    def __setattr__(self, name, value):
        """Enable setting of AttributeQuerySslSOAPBinding attributes from
        names starting with attributeQuery.* / attributeQuery_*.  Addition for
        setting these values from ini file
        """
        try:
            super(CertExtApp, self).__setattr__(name, value)
            
        except AttributeError:
            # Coerce into setting AttributeQuerySslSOAPBinding attributes - 
            # names must start with 'attributeQuery\W' e.g.
            # attributeQuery.clockSkew or attributeQuery_issuerDN
            if name.startswith(CertExtApp.ATTRIBUTE_QUERY_ATTRNAME):                
                setattr(self.__attributeQuery, 
                        name[CertExtApp.LEN_ATTRIBUTE_QUERY_ATTRNAME+1:], 
                        value)
            else:
                raise

    @property
    def attributeQuery(self):
        """SAML SOAP Attribute Query client binding object"""
        return self.__attributeQuery
    
    def _getAttributeAuthorityURI(self):
        return self.__attributeAuthorityURI

    def _setAttributeAuthorityURI(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "attributeAuthorityURI";'
                            ' got %r instead' % type(value))
        self.__attributeAuthorityURI = value

    attributeAuthorityURI = property(_getAttributeAuthorityURI,
                                     _setAttributeAuthorityURI, 
                                     doc="Attribute Authority SOAP SAML URI")

    def _getConnectionString(self):
        return self.__connectionString

    def _setConnectionString(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "%s" attribute; got %r'%
                            (CertExtApp.CONNECTION_STRING_OPTNAME,
                             type(value)))
        self.__connectionString = os.path.expandvars(value)

    connectionString = property(fget=_getConnectionString, 
                                fset=_setConnectionString, 
                                doc="Database connection string")

    def _getOpenIdSqlQuery(self):
        return self.__openIdSqlQuery

    def _setOpenIdSqlQuery(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "%s" attribute; got %r'% 
                        (CertExtApp.OPENID_SQLQUERY_OPTNAME,
                         type(value)))
        self.__openIdSqlQuery = value

    openIdSqlQuery = property(fget=_getOpenIdSqlQuery, 
                        fset=_setOpenIdSqlQuery, 
                        doc="SQL Query for authentication request")
        
    def __getstate__(self):
        '''Specific implementation needed with __slots__'''
        return dict([(attrName, getattr(self, attrName)) 
                     for attrName in CertExtApp.__slots__])
        
    def __setstate__(self, attrDict):
        '''Specific implementation needed with __slots__'''
        for attr, val in attrDict.items():
            setattr(self, attr, val)
    
    def serialiseAssertion(self, assertion):
        """Convert SAML assertion object into a string"""
        samlAssertionElem = AssertionElementTree.toXML(assertion)
        return ElementTree.tostring(samlAssertionElem)
    
    def queryOpenId(self, username):
        """Given a username, query for user OpenID from the user 
        database

        @type username: basestring
        @param username: username
        @rtype: basestring
        @return: the OpenID identifier corresponding to the input username
        """

        try:
            dbEngine = create_engine(self.connectionString)
        except ImportError, e:
            raise CertExtAppConfigError("Missing database engine for "
                                        "SQLAlchemy: %s" % e)
        connection = dbEngine.connect()
        
        try:
            queryInputs = dict(username=username)
            query = Template(self.openIdSqlQuery).substitute(queryInputs)
            result = connection.execute(query)

        except exc.ProgrammingError:
            raise CertExtAppSqlError("Error with SQL Syntax: %s" %
                                     traceback.format_exc())
        finally:
            connection.close()

        try:
            openId = [r for r in result][0][0]
        
        except Exception:
            raise CertExtAppRetrieveError("Error with result set: %s" %
                                          traceback.format_exc())
        
        log.debug('Query succeeded for user %r' % username)
        return openId
    
    
import optparse
import os

class CertExtConsoleApp(CertExtApp):
    """Extend CertExtApp with functionality for command line options"""

    DEBUG_ENVVAR_NAME = 'NDGSEC_MYPROXY_CERT_EXT_APP_DEBUG'
    
    # Essential to have slots declaration otherwise superclass __setattr__
    # will not behave correctly
    __slots__ = ()
    
    @classmethod
    def run(cls):
        """Parse command line arguments and run the query specified"""

        if cls.DEBUG_ENVVAR_NAME in os.environ:
            import pdb
            pdb.set_trace()

        parser = optparse.OptionParser()

        parser.add_option("-f",
                          "--config-file",
                          dest="configFilePath",
                          help="ini style configuration file path containing "
                               "the options: connectionString, "
                               "openIdSqlQuery, identityUriTemplate, "
                               "attributeAuthorityURI and issuerDN.  The file "
                               "can also contain sections to configure logging "
                               "using the standard logging module log file "
                               "format")

        parser.add_option("-u",
                          "--username",
                          dest="username",
                          help="username to generate a SAML assertion for")

        opt = parser.parse_args()[0]

        if not opt.configFilePath:
            msg = "Error: no configuration file set.\n\n" + parser.format_help()
            raise SystemExit(msg)
        elif not opt.username:
            msg = "Error: no username set.\n\n" + parser.format_help()
            raise SystemExit(msg)
        
        # Enable the setting of logging configuration from config file
        from logging.config import fileConfig
        from ConfigParser import NoSectionError
        try:
            fileConfig(opt.configFilePath)
        except NoSectionError:
            pass

        certExtApp = cls.fromConfigFile(opt.configFilePath)
        assertion = certExtApp(opt.username)
        print(assertion)

