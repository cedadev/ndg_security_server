"""Credential Wallet classes

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "30/11/05"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:credentialwallet.py 4378 2008-10-29 10:30:14Z pjkersha $'

import logging
log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

import os
import warnings

# Check Attribute Certificate validity times
from datetime import datetime, timedelta

from ConfigParser import ConfigParser

try:
    from abc import ABCMeta, abstractmethod
except ImportError:
    # Allow for Python version < 2.6
    ABCMeta = type
    abstractmethod = lambda f: f
    
from ndg.saml.utils import SAMLDateTime
from ndg.saml.saml2.core import Assertion

from ndg.security.common.utils import TypedList
from ndg.security.common.utils.configfileparsers import (     
                                                    CaseSensitiveConfigParser,)


class _CredentialWalletException(Exception):    
    """Generic Exception class for CredentialWallet module.  Overrides 
    Exception to enable writing to the log"""


class CredentialWalletError(_CredentialWalletException):    
    """Exception handling for NDG Credential Wallet class.  Overrides Exception
    to enable writing to the log"""


class CredentialContainer(object):
    """Container for cached credentials"""
    ID_ATTRNAME = 'id'
    ITEM_ATTRNAME = 'credentials'
    ISSUERNAME_ATTRNAME = 'issuerName'
    CREDENTIAL_TYPE_ATTRNAME = 'type'
    
    __ATTRIBUTE_NAMES = (
        ID_ATTRNAME,
        ITEM_ATTRNAME,
        ISSUERNAME_ATTRNAME,
        CREDENTIAL_TYPE_ATTRNAME
    )
    __slots__ = tuple(["__%s" % n for n in __ATTRIBUTE_NAMES])
    del n
    
    def __init__(self, _type=None):
        self.__type = None
        self.type = _type
        
        self.__id = -1
        self.__assertionsMap = None
        self.__issuerName = None

    def _getType(self):
        return self.__type

    def _setType(self, value):
        if not isinstance(value, type):
            raise TypeError('Expecting %r for "type" attribute; got %r' %
                            (type, type(value)))       
        self.__type = value

    type = property(_getType, _setType, 
                    doc="Type for credential - set to None for any type")

    def _getId(self):
        return self.__id

    def _setId(self, value):
        if not isinstance(value, int):
            raise TypeError('Expecting int type for "id" attribute; got %r' %
                            type(value))
        self.__id = value

    id = property(_getId, 
                  _setId, 
                  doc="Numbered identifier for credential - "
                      "set to -1 for new credentials")

    def _getCredentials(self):
        return self.__assertionsMap

    def _setCredentials(self, value):
        # Safeguard type attribute referencing for unpickling process - this
        # method may be called before type attribute has been set
        _type = getattr(self, 
                        CredentialContainer.CREDENTIAL_TYPE_ATTRNAME, 
                        None)
        
        if (_type is not None and 
            not isinstance(value, TypedList) and
            value.elementType != _type):
            raise TypeError('Expecting TypedList(%s) type for "credentials" '
                            'attribute; got %r' % (_type, type(value)))
        self.__assertionsMap = value

    credentials = property(_getCredentials, _setCredentials, 
                           doc="Credentials object")

    def _getIssuerName(self):
        return self.__issuerName

    def _setIssuerName(self, value):
        self.__issuerName = value

    issuerName = property(_getIssuerName, 
                          _setIssuerName, 
                          doc="Name of issuer of the credentials")

    def __getstate__(self):
        '''Enable pickling'''
        thisDict = dict([(attrName, getattr(self, attrName))
                         for attrName in CredentialContainer.__ATTRIBUTE_NAMES])
        
        return thisDict
        
    def __setstate__(self, attrDict):
        '''Enable pickling for use with beaker.session'''
        try:
            for attr, val in attrDict.items():
                setattr(self, attr, val)
        except Exception, e:
            pass
       

class CredentialWalletBase(object):
    """Abstract base class for Credential Wallet implementations
    """ 
    CONFIG_FILE_OPTNAMES = ("userId", )
    __metaclass__ = ABCMeta
    __slots__ = ("__userId", )
    
    def __init__(self):
        self.__userId = None

    @classmethod
    def fromConfig(cls, cfg, **kw):
        '''Alternative constructor makes object from config file settings
        @type cfg: basestring /ConfigParser derived type
        @param cfg: configuration file path or ConfigParser type object
        @rtype: ndg.security.common.credentialWallet.SAMLAssertionWallet
        @return: new instance of this class
        '''
        credentialWallet = cls()
        credentialWallet.parseConfig(cfg, **kw)
        
        return credentialWallet

    def parseConfig(self, cfg, prefix='', section='DEFAULT'):
        '''Virtual method defines interface to read config file settings
        @type cfg: basestring /ConfigParser derived type
        @param cfg: configuration file path or ConfigParser type object
        @type prefix: basestring
        @param prefix: prefix for option names e.g. "certExtApp."
        @type section: baestring
        @param section: configuration file section from which to extract
        parameters.
        '''
        raise NotImplementedError(CredentialWalletBase.parseConfig.__doc__)

    @abstractmethod
    def addCredentials(self, key, credentials):
        """Add a new credential to the list of credentials held.

        @type key: basestring
        @param key: key to use to retrieve the credential
        @type credentials: determined by derived class implementation e.g.
        list of SAML assertions
        @param credentials: new credentials to be added
        """
        raise NotImplementedError(CredentialWalletBase.addCredentials.__doc__)
            
    @abstractmethod
    def audit(self):
        """Check the credentials held in the wallet removing any that have
        expired or are otherwise invalid."""
        raise NotImplementedError(CredentialWalletBase.audit.__doc__)

    @abstractmethod
    def updateCredentialRepository(self, auditCred=True):
        """Copy over non-persistent credentials held by wallet into the
        perminent repository.
        
        @type auditCred: bool
        @param auditCred: filter existing credentials in the repository
        removing invalid ones"""
        raise NotImplementedError(
                    CredentialWalletBase.updateCredentialRepository.__doc__)
        
    @abstractmethod
    def retrieveCredentials(self, key):
        """Retrieve Credentials corresponding to the given key
        
        @rtype: list
        @return: cached credentials indexed by key"""
        return self.__credentials.get(key)
        
    def _getUserId(self):
        return self.__userId

    def _setUserId(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "userId"; got %r '
                            'instead' % type(value))
        self.__userId = value

    userId = property(_getUserId, _setUserId, 
                      doc="User Identity for this wallet")

    def __getstate__(self):
        '''Enable pickling for use with beaker.session'''
        _dict = {}
        for attrName in CredentialWalletBase.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_CredentialWalletBase" + attrName
                
            _dict[attrName] = getattr(self, attrName)
            
        return _dict
  
    def __setstate__(self, attrDict):
        '''Enable pickling for use with beaker.session'''
        for attrName, val in attrDict.items():
            setattr(self, attrName, val)


class SAMLAssertionWallet(CredentialWalletBase):
    """Wallet for Earth System Grid supporting caching of SAML Assertions
    """
    CONFIG_FILE_OPTNAMES = CredentialWalletBase.CONFIG_FILE_OPTNAMES + (
                           "clockSkewTolerance", )
    __slots__ = ("__clockSkewTolerance", "__assertionsMap")

    def __init__(self):
        super(SAMLAssertionWallet, self).__init__()
        self.__clockSkewTolerance = timedelta(seconds=0.)
        self.__assertionsMap = {}
    
    def _getClockSkewTolerance(self):
        return self.__clockSkewTolerance

    def _setClockSkewTolerance(self, value):
        if isinstance(value, (float, int, long)):
            self.__clockSkewTolerance = timedelta(seconds=value)
            
        elif isinstance(value, basestring):
            self.__clockSkewTolerance = timedelta(seconds=float(value))
            
        elif isinstance(value, timedelta):
            self.__clockSkewTolerance = value
            
        else:
            raise TypeError('Expecting timedelta, float, int, long or string '
                            'type for "clockSkewTolerance"; got %r' % 
                            type(value))

    clockSkewTolerance = property(_getClockSkewTolerance, 
                                  _setClockSkewTolerance, 
                                  doc="Allow a tolerance (seconds) for "
                                      "checking timestamps of the form: "
                                      "notBeforeTime - tolerance < now < "
                                      "notAfterTime + tolerance")

    def parseConfig(self, cfg, prefix='', section='DEFAULT'):
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
            if prefix and optName.startswith(prefix):
                optName = optName[prefixLen:]
                
            setattr(self, optName, val)
         
    def addCredentials(self, key, assertions, verifyCredentials=True):
        """Add a new assertion to the list of assertion credentials held.

        @type assertions: iterable
        @param assertions: list of SAML assertions for a given issuer
        @type key: basestring
        @param key: key by which these credentials should be referred to
        @type verifyCredential: bool
        @param verifyCredential: if set to True, test validity of credential
        by calling isValidCredential method.
        """        
        for assertion in assertions:
            if not isinstance(assertion, Assertion):
                raise TypeError("Input credentials must be %r type; got %r" %
                                (Assertion, assertion))
                
            elif verifyCredentials and not self.isValidCredential(assertion):
                raise CredentialWalletError("Validity time error with "
                                            "assertion %r" % assertion)
        
        # Any existing credentials are overwritten
        self.__assertionsMap[key] = assertions

    def retrieveCredentials(self, key):
        """Retrieve credentials for the given key
        
        @param key: key index to credentials to retrieve
        @type key: basestring
        @rtype: iterable / None type if none found for key
        @return: cached credentials indexed by input key
        """
        return self.__assertionsMap.get(key)
                        
    def audit(self):
        """Check the credentials held in the wallet removing any that have
        expired or are otherwise invalid."""

        log.debug("SAMLAssertionWallet.audit ...")
        
        for k, v in self.__assertionsMap.items():
            creds = [credential for credential in v
                     if self.isValidCredential(credential)]
            if len(creds) > 0:
                self.__assertionsMap[k] = creds
            else:
                del self.__assertionsMap[k]

    def isValidCredential(self, assertion):
        """Validate SAML assertion time validity"""
        utcNow = datetime.utcnow()
        if utcNow < assertion.conditions.notBefore - self.clockSkewTolerance:
            msg = ('The current clock time [%s] is before the SAML Attribute '
                   'Response assertion conditions not before time [%s] ' 
                   '(with clock skew tolerance = %s)' % 
                   (SAMLDateTime.toString(utcNow),
                    assertion.conditions.notBefore,
                    self.clockSkewTolerance))
            log.warning(msg)
            return False
            
        if (utcNow >= 
            assertion.conditions.notOnOrAfter + self.clockSkewTolerance):
            msg = ('The current clock time [%s] is on or after the SAML '
                   'Attribute Response assertion conditions not on or after '
                   'time [%s] (with clock skew tolerance = %s)' % 
                   (SAMLDateTime.toString(utcNow),
                    assertion.conditions.notOnOrAfter,
                    self.clockSkewTolerance))
            log.warning(msg)
            return False
            
        return True
    
    # Implement abstract method
    updateCredentialRepository = lambda self: None
    
    def __getstate__(self):
        '''Enable pickling for use with beaker.session'''
        _dict = super(SAMLAssertionWallet, self).__getstate__()
        
        for attrName in SAMLAssertionWallet.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_SAMLAssertionWallet" + attrName
                
            _dict[attrName] = getattr(self, attrName)
            
        return _dict
        
        
class CredentialRepositoryError(_CredentialWalletException):   
    """Exception handling for NDG Credential Repository class."""


class CredentialRepository(object):
    """CredentialWallet's abstract interface class to a Credential Repository. 
    The Credential Repository is abstract store of user currently valid user
    credentials.  It enables retrieval of attribute certificates from a user's
    previous session(s)"""
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def __init__(self, propFilePath=None, dbPPhrase=None, **prop):
        """Initialise Credential Repository abstract base class.  Derive from 
        this class to define Credentail Repository interface Credential
        Wallet 

        If the connection string or properties file is set a connection
        will be made

        @type dbPPhrase: string
        @param dbPPhrase: pass-phrase to database if applicable
        
        @type propFilePath: string
        @param propFilePath: file path to a properties file.  This could 
        contain configuration parameters for the repository e.g.  database 
        connection parameters
        
        @type **prop: dict
        @param **prop: any other keywords required
        """
        raise NotImplementedError(
            self.__init__.__doc__.replace('\n       ',''))

    @abstractmethod
    def addUser(self, userId, dn=None):
        """A new user to Credentials Repository
        
        @type userId: string
        @param userId: userId for new user
        @type dn: string
        @param dn: users Distinguished Name (optional)"""
        raise NotImplementedError(
            self.addUser.__doc__.replace('\n       ',''))
           
    @abstractmethod
    def auditCredentials(self, userId=None, **assertionValidKeys):
        """Check the attribute certificates held in the repository and delete
        any that have expired

        @type userId: basestring/list or tuple
        @param userId: audit credentials for the input user ID or list of IDs
        @type assertionValidKeys: dict
        @param **assertionValidKeys: keywords which set how to check the 
        assertion e.g. XML signature, version etc.  Default is check validity 
        time only
        """
        raise NotImplementedError(
            self.auditCredentials.__doc__.replace('\n       ',''))

    @abstractmethod
    def retrieveCredentials(self, userId):
        """Get the list of credentials for a given users DN
        
        @type userId: string
        @param userId: users userId, name or X.509 cert. distinguished name
        @rtype: list 
        @return: list of credentials"""
        raise NotImplementedError(
            self.getCredentials.__doc__.replace('\n       ',''))

    @abstractmethod        
    def addCredentials(self, userId, credentialsList):
        """Add credentials for a user.  The user must have
        been previously registered in the repository

        @type userId: string
        @param userId: users userId, name or X.509 cert. distinguished name
        @type credentialsList: list
        @param credentialsList: list of credentials
        """
        raise NotImplementedError(
            self.addCredentials.__doc__.replace('\n       ',''))


class NullCredentialRepository(CredentialRepository):
    """Implementation of Credential Repository interface with empty stubs.  
    Use this class in the case where no Credential Repository is required"""
    
    def __init__(self, propFilePath=None, dbPPhrase=None, **prop):
        """Null Credential Repository __init__ placeholder"""

    def addUser(self, userId):
        """Null Credential Repository addUser placeholder"""
                            
    def auditCredentials(self, **attCertValidKeys):
        """Null Credential Repository addUser placeholder"""

    def retrieveCredentials(self, userId):
        """Null Credential Repository getCredentials placeholder"""
        return []
       
    def addCredentials(self, userId, attCertList):
        """Null Credential Repository addCredentials placeholder"""