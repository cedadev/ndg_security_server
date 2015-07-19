"""OpenID IdP Validation unit test package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "16/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)

import os
import unittest
from ndg.security.server.test.base import BaseTestCase, mk_data_dirpath
from ndg.security.server.wsgi.openid.relyingparty.validation import (
    IdPValidator, IdPValidationDriver, IdPInvalidException, 
    SSLIdPValidationDriver, SSLClientAuthNValidator)
    
    
class ProviderWhitelistValidator(IdPValidator):
    """Test stub for Whitelist validator"""
    def __init__(self):
        pass
    
    def initialize(self, **parameters):
        '''@raise ConfigException:''' 
        assert('config-file' in parameters)
        
    def validate(self, idpEndpoint, idpIdentity):
        '''@raise IdPInvalidException:
        @raise ConfigException:''' 
        pass


class ProviderIdentifierTestValidator(IdPValidator):
    """Test stub for identifier validator - fixed to reject all IdPs"""
    def __init__(self):
        pass

    def initialize(self, **parameters):
        '''@raise ConfigException:''' 
        assert('config-file' in parameters)
       
    def validate(self, idpEndpoint, idpIdentity):
        '''Test method hard wired to raise an invalid IdP exception
        @raise IdPInvalidException:
        @raise ConfigException:''' 
        raise IdPInvalidException("%s is invalid" % idpEndpoint)


class DiscoveryInfoPlaceHolder(object):
    getOPEndpoint = lambda self: 'https://localhost/openid/provider'

 
class IdentifierPlaceHolder(object):
    getIdentifier = lambda self: 'myid'

try:
    from M2Crypto import X509
    m2crypto_installed = True
    
    class X509StoreCtxPlaceHolder(object):
        x509CertFilePath = mk_data_dirpath(os.path.join('pki', 'localhost.crt'))
        
        def get1_chain(self):
            return [X509.load_cert(X509StoreCtxPlaceHolder.x509CertFilePath)]

except ImportError:
    m2crypto_installed = False
    

class IdPValidationTestCase(BaseTestCase):
    thisDir = os.path.dirname(os.path.abspath(__file__))
    IDP_CONFIG_FILEPATH = os.path.join(thisDir, 'idpvalidator.xml')
    os.environ['NDGSEC_UNITTEST_IDPVALIDATION_DIR'] = thisDir
    
    
    def test01IdPConfigFileEnvVarNotSet(self):
        identifier = IdentifierPlaceHolder()
        discoveries = [DiscoveryInfoPlaceHolder()]
        
        idPValidationDriver = IdPValidationDriver()
        validDiscoveries = idPValidationDriver.performIdPValidation(identifier,
                                                                discoveries)
        # Expect no discoveries returned because the IDP_CONFIG_FILE 
        # environment variable is not set
        self.assert_(len(validDiscoveries) == 1)
        
    def test02WithIdPConfigFile(self):
        identifier = 'https://pjk.badc.rl.ac.uk'
        
        os.environ[IdPValidationDriver.IDP_CONFIG_FILEPATH_ENV_VARNAME
            ] = IdPValidationTestCase.IDP_CONFIG_FILEPATH
            
        idPValidationDriver = IdPValidationDriver()
        validDiscoveries = idPValidationDriver.performIdPValidation(identifier)
        self.assert_(len(validDiscoveries) == 2)
        
    @unittest.skipIf(not m2crypto_installed, "Skipping IdPValidationTestCase "
                     "M2Crypto is not installed.")
    def test03SSLValidation(self):
        idpConfigFilePath = os.path.join(IdPValidationTestCase.thisDir, 
                                         'ssl-idp-validator.xml')
        idPValidationDriver = SSLIdPValidationDriver(
                                        idpConfigFilePath=idpConfigFilePath)
        
        # preVerifyOK set to 1 to indicate all is otherwise OK with 
        # verification
        idPValidationDriver(1, X509StoreCtxPlaceHolder())
        
        
if __name__ == "__main__":
    unittest.main()        
