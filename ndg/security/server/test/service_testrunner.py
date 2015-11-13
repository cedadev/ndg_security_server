"""WSGI service test runner for use with client test calls to services.

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/07/15"
__copyright__ = "(C) 2015 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
from os import path, environ
import logging

from OpenSSL import SSL

from ndg.security.server.test.base import BaseTestCase, TEST_CONFIG_DIR
from ndg.security.server.utils.paste_utils import PasteDeployAppServer

log = logging.getLogger(__name__)


class ServiceTestRunner(object):    
    '''Start an Attribute Authority Service thread for use with client calls
    in unit tests
    '''
    # Provide capability to disable the test runner.  This is convenient for the
    # test suite should you wish to provide the services independently e.g.
    # as a way of testing the paster templates
    DISABLE_SERVICE_ENVVAR_NAME = 'NDGSEC_DISABLE_SRVC_TEST_RUNNER'
    DISABLE_SERVICE = environ.get(DISABLE_SERVICE_ENVVAR_NAME, False)
    
    @property
    def service_disabled(self):
        return self.__class__.DISABLE_SERVICE
    
    def __init__(self, config_filepath, with_ssl=True, port=None):
        if self.service_disabled:
            log.debug('Service for ini file %r is disabled.  Unset %r '
                      'environment variable to re-enable.', config_filepath,
                      self.__class__.DISABLE_SERVICE_ENVVAR_NAME)
            return
        
        if with_ssl:
            ssl_context = SSL.Context(SSL.TLSv1_METHOD)
            ssl_context.set_options(SSL.OP_NO_SSLv2|SSL.OP_NO_SSLv3)
        
            priKeyFilePath = BaseTestCase.SSL_PRIKEY_FILEPATH
            certFilePath = BaseTestCase.SSL_CERT_FILEPATH
            
            ssl_context.use_privatekey_file(priKeyFilePath)
            ssl_context.use_certificate_file(certFilePath)
        else:
            ssl_context = None
        
        self._srvc = PasteDeployAppServer(
                                    cfgFilePath=path.abspath(config_filepath), 
                                    port=port,
                                    ssl_context=ssl_context) 
        
    def start_service(self):
        if self.service_disabled:
            return

        self._srvc.startThread()
        
    def stop_service(self):
        if self.service_disabled:
            return

        self._srvc.terminateThread()
        

class AttributeAuthorityTestRunner(ServiceTestRunner):    
    '''Start an Attribute Authority Service thread for use with client calls
    in unit tests
    '''
    CONFIG_FILE_PATH = path.join(TEST_CONFIG_DIR, 'attributeauthority', 'sitea',
                                 'attribute-service.ini')
    
    def __init__(self, config_filepath=CONFIG_FILE_PATH, 
                 port=BaseTestCase.SITEA_SSL_ATTRIBUTEAUTHORITY_PORTNUM, **kw):
        super(AttributeAuthorityTestRunner, self).__init__(config_filepath, 
                                                           port=port, **kw)
        

class AuthorisationServiceTestRunner(ServiceTestRunner):    
    '''Start an Attribute Authority Service thread for use with client calls
    in unit tests
    '''
    CONFIG_FILE_PATH = path.join(TEST_CONFIG_DIR, 'authorisationservice', 
                                 'authorisation-service.ini')
    
    def __init__(self, config_filepath=CONFIG_FILE_PATH, 
                 port=BaseTestCase.AUTHORISATION_SERVICE_PORTNUM, **kw):
        super(AuthorisationServiceTestRunner, self).__init__(config_filepath, 
                                                             port=port, **kw)
  
