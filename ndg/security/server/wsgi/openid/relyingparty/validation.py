"""NDG Security OpenID Relying Party Provider Validation module

Based on the Earth System Grid IdPValidator interface for restricting
OpenID Providers that a Relying Party may connect to

An Identity Provider (IdP) is equivalent to an OpenID Provider

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "09/06/2009"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)
import os
import traceback
import re
 
# For SSL-based validation classes  
import urllib.request, urllib.error, urllib.parse
try:
    from M2Crypto import SSL
    from M2Crypto.m2urllib2 import build_opener
    _M2CRYPTO_NOT_INSTALLED = False
except ImportError:
    import warnings
    warnings.warn(
        "M2Crypto is not installed - IdP SSL-based validation is disabled")
    _M2CRYPTO_NOT_INSTALLED = True

try:
    from xml.etree import ElementTree
except ImportError as e:
    import warnings
    warnings.warn('xml.etree import failed with message %s, trying import from '
                  'elementtree site package instead...' % e)
    from elementtree import ElementTree
    
from openid.yadis.manager import Discovery

from ndg.security.common.openssl import m2_get_dn_field, m2_get_cert_ext_values
from ndg.security.common.utils.etree import QName
from ndg.security.common.utils.classfactory import instantiateClass


class _ConfigBase(object):
    """Base class for IdP Validator and Attribute Provider configuration
    """
    def __init__(self):
        self.__className = None
        self.__configFile = None
        self.__parameters = {}
    
    def _set_className(self, className):
        if not isinstance(className, str):
            raise TypeError('Expecting string type for className; got %r' %
                            type(className))
        self.__className = className
    
    def _get_className(self):
        return self.__className
    
    className = property(fget=_get_className,
                         fset=_set_className)

    def _get_configFile(self):
        return self.__configFile
    
    def _set_configFile(self, configFile):
        if not isinstance(configFile, str):
            raise TypeError('Expecting string type for configFile; got %r' %
                            type(configFile))
        self.__configFile = configFile

    configFile = property(fget=_get_configFile,
                          fset=_set_configFile)
    
    def _get_parameters(self):
        return self.__parameters
    
    def _set_parameters(self, parameters):    
        if not isinstance(parameters, dict):
            raise TypeError('Expecting string type for parameters; got %r' %
                            type(parameters))
        self.__parameters = parameters
    
    parameters = property(fget=_get_parameters,
                          fset=_set_parameters)

class IdPValidatorConfig(_ConfigBase):
    """Container for IdP validator configuration"""
    
class AttributeProviderConfig(_ConfigBase):
    """Container for Attribute Provider configuration"""
    
class XmlConfigReaderError(Exception):
    """Raise from XmlConfigReader"""
      
class XmlConfigReader(object):
    """Parser for IdP and Attribute Provider config
    """
    VALIDATOR_ELEMNAME = "validator"
    PARAMETER_ELEMNAME = "parameter"
    ATTRIBUTE_PROVIDER_ELEMNAME = "attributeprovider"
    NAME_ATTRNAME = "name"
    VALUE_ATTRNAME = "value"
    
    def getValidators(self, source):  
        """Retrieve IdP Validator objects from XML file
        @type source: basestring/file
        @param source: file path to XML file or file object
        """
        validators = None

        root = self.__parseConfigFile(source)
        if root is not None:
            validators = self.__extractValidatorConfigs(root)
        
        return validators
    
    def getAttrProviders(self, source):
        """
        @type source: basestring/file
        @param source: file path to XML file or file object
        """    
        attrProviders = None

        root = self.__parseConfigFile(source)
        if root is not None:
            attrProviders = self.__extractAttrProviderConfigs(root)
        
        return attrProviders
    
    def __parseConfigFile(self, source):
        """Read in the XML configuration file
        @type source: basestring/file
        @param source: file path to XML file or file object
        """
        elem = ElementTree.parse(source)
        root = elem.getroot()
        
        return root

    def __extractValidatorConfigs(self, root):
        """Parse Validator configuration from the XML config file
        @type root: ElementTree.Element
        @param root: root element of parsed XML config file
        """
        validators = []
        
        for elem in root:
            localName = QName.getLocalPart(elem.tag).lower()
            if localName == XmlConfigReader.VALIDATOR_ELEMNAME:    
                validatorConfig = IdPValidatorConfig()
                
                className = elem.attrib.get(XmlConfigReader.NAME_ATTRNAME)
                if className is None:
                    raise XmlConfigReaderError('No "%s" attribute found in '
                                               '"%s" tag' %
                                              (XmlConfigReader.NAME_ATTRNAME,
                                               elem.tag))
                   
                validatorConfig.className = className
                
                parameters = {}
                for el in elem:
                    if QName.getLocalPart(
                       el.tag).lower() == XmlConfigReader.PARAMETER_ELEMNAME:
                        
                        nameAttr = el.attrib.get(XmlConfigReader.NAME_ATTRNAME)
                        if nameAttr is None:
                            raise XmlConfigReaderError('No "%s" attribute '
                                                       'found in "%s" tag' %
                                                (XmlConfigReader.NAME_ATTRNAME,
                                                 el.tag))
                        if nameAttr in parameters:
                            raise XmlConfigReaderError('Duplicate parameter '
                                                       'name "%s" found' % 
                                                       el.attrib[
                                                XmlConfigReader.NAME_ATTRNAME])
                            
                        valAttr = el.attrib.get(XmlConfigReader.VALUE_ATTRNAME)
                        if valAttr is None:
                            raise XmlConfigReaderError('No "%s" attribute '
                                                       'found in "%s" tag' %
                                                (XmlConfigReader.VALUE_ATTRNAME,
                                                 el.tag))
                               
                        parameters[nameAttr] = os.path.expandvars(valAttr)
            
                validatorConfig.parameters = parameters
                validators.append(validatorConfig)
        
        return validators
    
    def __extractAttrProviderConfigs(self, root):
        """Parse Attribute Provider configurations from the XML tree
        @type root: ElementTree.Element
        @param root: root element of parsed XML config file
        """
        attrProviders = []
        validatorConfig = None
        parameters = {}

        for elem in root:
            localName = QName.getLocalPart(elem.tag).lower()
            if localName == XmlConfigReader.ATTRIBUTE_PROVIDER_ELEMNAME:
                if validatorConfig is not None:
                    validatorConfig.parameters = parameters
                    attrProviders.append(validatorConfig)
                
                validatorConfig = AttributeProviderConfig()
                nameAttr = elem.attrib.get(XmlConfigReader.NAME_ATTRNAME)
                if nameAttr is None:
                    raise XmlConfigReaderError('No "%s" attribute '
                                               'found in "%s" tag' %
                                               (XmlConfigReader.NAME_ATTRNAME,
                                                elem.tag))
                validatorConfig.className(nameAttr)
            
            elif localName == XmlConfigReader.PARAMETER_ELEMNAME:
                
                nameAttr = elem.attrib.get(XmlConfigReader.NAME_ATTRNAME)
                if nameAttr is None:
                    raise XmlConfigReaderError('No "%s" attribute '
                                               'found in "%s" tag' %
                                               (XmlConfigReader.NAME_ATTRNAME,
                                                elem.tag))
                       
                if nameAttr in parameters:
                    raise XmlConfigReaderError('Duplicate parameter name "%s" '
                                               'found' % nameAttr)
                    
                valAttr = elem.attrib.get(XmlConfigReader.VALUE_ATTRNAME)
                if valAttr is None:
                    raise XmlConfigReaderError('No "%s" attribute '
                                               'found in "%s" tag' %
                                               (XmlConfigReader.VALUE_ATTRNAME,
                                                elem.tag))
            
                parameters[nameAttr] = elem.attrib[valAttr]
            
        if validatorConfig != None:
            validatorConfig.parameters = parameters
            attrProviders.append(validatorConfig)
        
        return attrProviders


class IdPValidatorException(Exception):
    """Base class for IdPValidator exceptions"""
    
class IdPInvalidException(IdPValidatorException):
    """Raise from IdPValidator.validate if the IdP is not acceptable"""

class ConfigException(IdPValidatorException):
    """Problem with configuration for the IdP Validator class"""
 

class IdPValidator(object):
    '''Interface class for implementing OpenID Provider validators for a
    Relying Party to call'''
    
    def __init__(self):
        raise NotImplementedError()

    def initialize(self, **parameters):
        '''@raise ConfigException:''' 
        raise NotImplementedError()
       
    def validate(self, idpEndpoint, idpIdentity):
        '''@raise IdPInvalidException:
        @raise ConfigException:''' 
        raise NotImplementedError()
 

class SSLIdPValidator(object):
    '''Interface class for implementing OpenID Provider validators for a
    Relying Party to call'''
    __slots__ = ()
    
    def __init__(self):
        raise NotImplementedError()

    def initialize(self, **parameters):
        '''@raise ConfigException:''' 
        raise NotImplementedError()
       
    def validate(self, x509CertCtx):
        '''@type x509StoreCtx: M2Crypto.X509_Store_Context
        @param x509StoreCtx: context object containing peer certificate and
        certificate chain for verification
 
        @raise IdPInvalidException:
        @raise ConfigException:''' 
        raise NotImplementedError()


class SSLClientAuthNValidator(SSLIdPValidator):
    """HTTPS based validation with the addition that this client can provide
    a certificate to the peer enabling mutual authentication
    """
    PARAMETERS = {
        'configFilePath': str,
        'caCertDirPath': str,
        'certFilePath': str,
        'priKeyFilePath': str,
        'priKeyPwd': str
    }
    __slots__ = {}
    __slots__.update(PARAMETERS)
    __slots__.update({'validIdPNames': []})
    
    def __init__(self):
        """Set-up default SSL context for HTTPS requests"""
        self.validIdPNames = []
        
        for p in SSLClientAuthNValidator.PARAMETERS:
            setattr(self, p, '')

    def __setattr__(self, name, value):
        if (name in SSLClientAuthNValidator.PARAMETERS and 
            not isinstance(value, SSLClientAuthNValidator.PARAMETERS[name])):
            raise TypeError('Invalid type %r for parameter "%s" expecting '
                            '%r ' % 
                            (type(value), 
                             name, 
                             SSLClientAuthNValidator.PARAMETERS[name]))
        
        if name.endswith('Path'):
            value_ = os.path.expandvars(value)
        else:
            value_ = value
              
        super(SSLClientAuthNValidator, self).__setattr__(name, value_)
        
    def initialize(self, ctx, **parameters):
        '''@param ctx: SSL context
        @type ctx: M2Crypto.SSL.Context
        @param parameters: dictionary of parameters read from configuration
        file
        @type parameters: dict
        ''' 
        for name, val in list(parameters.items()):
            setattr(self, name, os.path.expandvars(val))
        
        if self.caCertDirPath:
            ctx.load_verify_locations(capath=self.caCertDirPath)
        else:
            log.warning('No CA certificate directory set for validator: %r; '
                        'OpenID Provider peer certificates verification may '
                        'fail during OpenID discovery stage.',
                        type(self)) 
            
        if self.certFilePath and self.priKeyFilePath:
            ctx.load_cert(self.certFilePath, 
                          keyfile=self.priKeyFilePath, 
                          callback=lambda *arg, **kw: self.priKeyPwd)
        else:
            log.info('No certificate/private key file set for validator: %r; '
                     'this relying party will not send authentication '
                     'credentials to OpenID Providers during OpenID discovery '
                     'stage.',
                     type(self))
               
        if not self.configFilePath:
            log.warning('No configuration file set for validator: %r; checking '
                        'of OpenID Provider hostnames is disabled',
                        type(self))
            self.validIdPNames = []
        else:
            # Simple file format - one IdP server name per line
            cfgFile = open(self.configFilePath)
            self.validIdPNames = [l.strip() for l in cfgFile.readlines()
                                  if not l.startswith('#')]
                          
    def validate(self, x509StoreCtx):
        '''Validate the peer certificate DN common name against a whitelist
        of acceptable IdP names
        
        @type x509StoreCtx: M2Crypto.X509.X509_Store_Context
        @param x509StoreCtx: locate the certificate to be verified and perform 
        additional verification steps as needed
        
        @raise IdPInvalidException: if none of the certificates in the chain
        have DN common names matching the list of valid IdPs'''
        if len(self.validIdPNames) == 0:
            return
        
        x509CertChain = x509StoreCtx.get1_chain()
        dnList = []
        for cert in x509CertChain:
            x509_subj = cert.get_subject()
            dn = x509_subj.as_text()
            
            log.debug("iterating over cert. chain dn = %s", dn)
            
            # Check for subject alternative names - this takes precedence over  
            # subject common name check
            cert_hostnames = m2_get_cert_ext_values(cert, 'subjectAltName', 
                                                    field_prefix="DNS:", 
                                                    field_sep=",")
            if cert_hostnames is not None:
                log.debug("Found subject alt name hosts = %r for dn %r", 
                          cert_hostnames, dn)
            else:       
                # Check for subject common name if no subject alt name was found
                cert_hostnames = m2_get_dn_field(dn, 'CN')
                log.debug("No subject alt name found, using subject common "
                          "name = %r for dn %r", cert_hostnames, dn)
            
            if cert_hostnames is None:
                log.warning("No hostname found in certificate subject alt "
                            "name field or DN common name for subject %r", dn)
            else:
                for hostname in cert_hostnames:
                    if hostname in self.validIdPNames:
                        # Match found - return
                        log.debug("Found peer certificate with CN matching "
                                  "list of valid OpenID Provider peer "
                                  "certificates %r", self.validIdPNames)
                        return
            
            dnList.append(dn)
            
        log.debug("Certificate chain yield certificates with DNs = %s", dnList)
        
        # No matching peer certificate was found
        raise IdPInvalidException("Peer certificate is not in list of valid "
                                  "OpenID Providers")


class FileBasedIdentityUriValidator(IdPValidator):
    """Validate OpenID identity URI against a list of regular expressions
    which specify the allowable identities.  The list is read from a simple
    flat file - one pattern per line
    """    
    PARAMETERS = {
        'configFilePath': str,
    }
    CONFIGFILE_COMMENT_CHAR = '#'
    
    def __init__(self):
        self.__configFilePath = None
        self.__identityUriPatterns = None

    def _setIdentityUriPatterns(self, value):
        if not isinstance(value, dict):
            raise TypeError('Expecting a dict of pattern objects keyed by '
                            'pattern string for "identityUriPatterns" object; '
                            'got %r' % type(value))
        self.__identityUriPatterns = value

    identityUriPatterns = property(fget=lambda self:self.__identityUriPatterns, 
                                   fset=_setIdentityUriPatterns, 
                                   doc="list of regular expression objects "
                                       "to match input identity URIs against")
        
    def _getConfigFilePath(self):
        return self.__configFilePath

    def _setConfigFilePath(self, value):
        if not isinstance(value, str):
            raise TypeError('Expecting string type for "configFilePath"; got '
                            '%r' % type(value))
        self.__configFilePath = value

    configFilePath = property(fget=_getConfigFilePath, 
                              fset=_setConfigFilePath, 
                              doc="Configuration file path for this validator")

    def initialize(self, **parameters):
        '''@raise ConfigException:''' 
        for name, val in list(parameters.items()):
            if name not in FileBasedIdentityUriValidator.PARAMETERS:
                raise AttributeError('Invalid parameter name "%s".  Valid '
                            'names are %r' % (name,
                            list(FileBasedIdentityUriValidator.PARAMETERS.keys())))
                
            if not isinstance(val, 
                              FileBasedIdentityUriValidator.PARAMETERS[name]):
                raise TypeError('Invalid type %r for parameter "%s" expecting '
                            '%r ' % 
                            (type(val), 
                             name, 
                             FileBasedIdentityUriValidator.PARAMETERS[name]))
        
            setattr(self, name, os.path.expandvars(val))

        self._parseConfigFile()
        
    def _parseConfigFile(self):
        """Read the configFile containing identity URI regular expressions
        """
        try:
            configFile = open(self.configFilePath)
        except IOError as e:
            raise ConfigException('Error parsing %r configuration file "%s": '
                                  '%s' % (self.__class__.__name__,
                                   e.filename, e.strerror))
        
        lines = re.split('\s', configFile.read().strip())
        self.identityUriPatterns = dict([
            (pat, re.compile(pat))
            for pat in lines if not pat.startswith(
                        FileBasedIdentityUriValidator.CONFIGFILE_COMMENT_CHAR)
        ])
       
    def validate(self, idpEndpoint, idpIdentity):
        '''Match user identity URI against list of acceptable patterns parsed
        from config file.  The idpEndpoint is ignored
        
        @type idpEndpoint: basestring
        @param idpEndpoint: endpoint for OpenID Provider service being 
        discovered
        @type idpIdentity: basestring
        @param idpIdentity: endpoint for OpenID Provider service being 
        @raise IdPInvalidException:
        ''' 
        for patStr, pat in list(self.identityUriPatterns.items()):
            if pat.match(idpIdentity) is not None:
                log.debug("Identity URI %r matches whitelist pattern %r" %
                          (idpIdentity, patStr))
                break # identity matches: return silently
        else:
            raise IdPInvalidException("OpenID identity URI %r doesn't match "
                                      "the whitelisted patterns" %
                                      idpIdentity)
    
    
class IdPValidationDriver(object):
    """Parse an XML Validation configuration containing XML Validators and 
    execute these against the Provider (IdP) input"""   
    IDP_VALIDATOR_BASE_CLASS = IdPValidator
    IDP_CONFIG_FILEPATH_ENV_VARNAME = "IDP_CONFIG_FILE"
    
    def __init__(self):
        self.__idPValidators = []
        
    def _get_idPValidators(self):
        return self.__idPValidators
    
    def _set_idPValidators(self, idPValidators):
        badValidators = [i for i in idPValidators 
                         if not isinstance(i, 
                                    self.__class__.IDP_VALIDATOR_BASE_CLASS)]
        if len(badValidators):
            raise TypeError("Input validators must be of IdPValidator derived "
                            "type")
                
        self.__idPValidators = idPValidators
        
    idPValidators = property(fget=_get_idPValidators,
                             fset=_set_idPValidators,
                             doc="list of IdP Validators")

    @classmethod
    def readConfig(cls, idpConfigFilePath=None):
        """Read IdP Validation configuration file.  This is an XML document
        containing a list of validator class names and their initialisation
        parameters
        """
        validators = []
        
        if idpConfigFilePath is None:
            idpConfigFilePath = os.environ.get(
                        IdPValidationDriver.IDP_CONFIG_FILEPATH_ENV_VARNAME)
            
        if idpConfigFilePath is None:
            log.warning("IdPValidationDriver.readConfig: No IdP "
                        "Configuration file was set")
            return validators
        
        configReader = XmlConfigReader()
        validatorConfigs = configReader.getValidators(idpConfigFilePath)

        for validatorConfig in validatorConfigs:
            try:
                validator = instantiateClass(validatorConfig.className,
                                             None, 
                                             objectType=IdPValidator)
                validator.initialize(**validatorConfig.parameters)
                validators.append(validator)
            
            except Exception as e:  
                log.error("Failed to initialise validator %s: %s", 
                          validatorConfig.className, traceback.format_exc())
                
        return validators
    
    def performIdPValidation(self, 
                             identifier, 
                             discoveries=(Discovery(None, None),)):
        """Perform all IdPValidation for all configured IdPValidators.  if
        the setIdPValidator method was used to initialise a list of
        IdPValidators before this method is called, the configurations
        are still checked each time this method is called and any valid
        IdPValidators found are appended to the initial list and run in
        addition.
        
        @param identifier: OpenID identity URL
        @type identifier: basestring
        @param discoveries: list of discovery instances.  Default to a single
        one with a provider URI of None
        @type discoveries: openid.yadis.discover.Discover
        """
        validators = self.readConfig()

        if self.idPValidators is not None:
            validators += self.idPValidators

        log.info("%d IdPValidators initialised", len(validators))

        # validate the discovered end points
        if len(validators) > 0:
        
            newDiscoveries = []
            for validator in validators:   
                for discoveryInfo in discoveries:
                    try:
                        validator.validate(discoveryInfo.url, identifier)

                        log.info("Whitelist Validator %r accepting endpoint: "
                                 "%s", validator, discoveryInfo.url)

                        newDiscoveries.append(discoveryInfo)
                    
                    except IdPInvalidException as e:
                        log.warning("Whitelist Validator %r rejecting "
                                    "identifier: %s: %s", validator, 
                                    identifier, e)
                                               
                    except Exception as e:        
                        log.warning("Error with Whitelist Validator %r "
                                    "rejecting identity: %s: %s", validator, 
                                    identifier, traceback.format_exc())
                        
            if len(newDiscoveries) > 0:
                discoveries = newDiscoveries
                log.info("Found %d valid endpoint(s)." % len(discoveries))
            else:      
                raise IdPInvalidException("No valid endpoints were found "
                                          "after validation.")
        else:
            log.warning("No IdP validation executed because no validators "
                        "were set")
            
        return discoveries


class SSLIdPValidationDriver(IdPValidationDriver):
    '''Validate an IdP using the certificate it returns from an SSL based
    request'''
    IDP_VALIDATOR_BASE_CLASS = SSLIdPValidator
    
    def __init__(self, idpConfigFilePath=None, installOpener=False):
        if _M2CRYPTO_NOT_INSTALLED:
            raise ImportError("M2Crypto is required for SSL-based IdP "
                              "validation but it is not installed.")

        super(SSLIdPValidationDriver, self).__init__()
        
        # Context object determines what validation is applied against the
        # peer's certificate in the SSL connection
        self.ctx = SSL.Context()
        
        # Enforce peer cert checking via this classes' __call__ method
        self.ctx.set_verify(SSL.verify_peer|SSL.verify_fail_if_no_peer_cert, 
                            9, 
                            callback=self)

        if installOpener:
            urllib.request.install_opener(build_opener(ssl_context=self.ctx))
        
        if idpConfigFilePath is not None:
            self.idPValidators += \
                self.readConfig(idpConfigFilePath=idpConfigFilePath)
            
        log.info("%d IdPValidator(s) initialised", len(self.idPValidators))
        
    def readConfig(self, idpConfigFilePath):
        """Read and initialise validators set in a config file"""  
        validators = []
        
        if idpConfigFilePath is None:
            idpConfigFilePath = os.environ('SSL_IDP_VALIDATION_CONFIG_FILE')
            
        if idpConfigFilePath is None:
            log.warning("SSLIdPValidationDriver.readConfig: No IdP "
                        "Configuration file was set")
            return validators
        
        configReader = XmlConfigReader()
        validatorConfigs = configReader.getValidators(idpConfigFilePath)

        for validatorConfig in validatorConfigs:
            try:
                validator = instantiateClass(validatorConfig.className,
                                             None, 
                                             objectType=SSLIdPValidator)
                
                # Validator has access to the SSL context object in addition
                # to custom settings set in parameters
                validator.initialize(self.ctx, **validatorConfig.parameters)
                validators.append(validator)
            
            except Exception as e: 
                raise ConfigException("Validator class %r initialisation "
                                      "failed with %s exception: %s" %
                                      (validatorConfig.className, 
                                       e.__class__.__name__,
                                       traceback.format_exc()))
                
        return validators
           
    def __call__(self, preVerifyOK, x509StoreCtx):
        '''@type preVerifyOK: int
        @param preVerifyOK: If a verification error is found, this parameter 
        will be set to 0
        @type x509StoreCtx: M2Crypto.X509_Store_Context
        @param x509StoreCtx: context object containing peer certificate and
        certificate chain for verification
        '''
        if preVerifyOK == 0:
            # Something is wrong with the certificate don't bother proceeding
            # any further
            log.info("No custom Validation executed: a previous verification "
                     "error has occurred")
            return preVerifyOK

        # validate the discovered end points
        for validator in self.idPValidators:   
            try:
                validator.validate(x509StoreCtx)
                log.info("Whitelist Validator %s succeeded", 
                         validator.__class__.__name__)
            
            except Exception as e:
                log.error("Whitelist Validator %r caught %s exception with "
                          "peer certificate context: %s", 
                          validator.__class__.__name__, 
                          e.__class__.__name__,
                          traceback.format_exc())       
                return 0
            
        if len(self.idPValidators) == 0:
            log.warning("No IdP validation executed because no validators "
                        "were set")
            
        return 1
        