"""WSGI service test runner for use with client test calls to services.

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/07/15"
__copyright__ = "(C) 2015 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
from os import path

from OpenSSL import SSL

from ndg.security.server.test.base import BaseTestCase, TEST_CONFIG_DIR
from ndg.security.server.utils.paste_utils import PasteDeployAppServer


class ServiceTestRunner(object):    
    '''Start an Attribute Authority Service thread for use with client calls
    in unit tests
    '''
    def __init__(self, config_filepath, with_ssl=True, port=None):
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
        self._srvc.startThread()
        
    def stop_service(self):
        self._srvc.terminateThread()
        

class AttributeAuthorityTestRunner(ServiceTestRunner):    
    '''Start an Attribute Authority Service thread for use with client calls
    in unit tests
    '''
    CONFIG_FILE_PATH = path.join(TEST_CONFIG_DIR,'attributeauthority', 'sitea',
                                 'attribute-service.ini')
    
    def __init__(self, config_filepath=CONFIG_FILE_PATH, 
                 port=BaseTestCase.SITEA_SSL_ATTRIBUTEAUTHORITY_PORTNUM, **kw):
        super(AttributeAuthorityTestRunner, self).__init__(config_filepath, 
                                                           port=port, **kw)
  
