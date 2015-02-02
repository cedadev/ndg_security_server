"""NDG Security test generic system variables

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "22/12/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import unittest
import logging

logging.basicConfig()
log = logging.getLogger(__name__)

import os
from os.path import join, dirname, abspath

    
TEST_CONFIG_DIR = join(abspath(dirname(__file__)), 'config')
TEST_INTEGRATION_DIR = join(abspath(dirname(__file__)), 'integration')
CONFIG_DIR_ENVVARNAME = 'NDGSEC_TEST_CONFIG_DIR'
INTEGRATION_DIR_ENVVARNAME = 'NDGSEC_INTEGRATION_TEST_DIR'
NDGSEC_TEST_CONFIG_DIR = os.environ.get(CONFIG_DIR_ENVVARNAME, TEST_CONFIG_DIR)
mk_data_dirpath = lambda file_:join(TEST_CONFIG_DIR, file_)

def set_config_dir_envvar():
    if CONFIG_DIR_ENVVARNAME not in os.environ:
        os.environ[CONFIG_DIR_ENVVARNAME] = TEST_CONFIG_DIR

def set_integration_dir_envvar():
    if INTEGRATION_DIR_ENVVARNAME not in os.environ:
        os.environ[INTEGRATION_DIR_ENVVARNAME] = TEST_INTEGRATION_DIR
    
        
class BaseTestCase(unittest.TestCase):
    '''Convenience base class from which other unit tests can extend.  Its
    sets the generic data directory path'''
    
    AUTHORISATION_SERVICE_PORTNUM = 9443
    AUTHORISATION_SERVICE_URI = 'https://localhost:%s/authorisation-service' % \
                                AUTHORISATION_SERVICE_PORTNUM
                         
    SITEA_ATTRIBUTEAUTHORITY_PORTNUM = 5000
    SITEA_ATTRIBUTEAUTHORITY_URI = 'http://localhost:%s/AttributeAuthority' % \
                                    SITEA_ATTRIBUTEAUTHORITY_PORTNUM
                                    
    SITEA_SSL_ATTRIBUTEAUTHORITY_PORTNUM = 5443
    SITEA_SSL_ATTRIBUTEAUTHORITY_URI = \
        'https://localhost:%d/AttributeAuthority' % \
                                    SITEA_SSL_ATTRIBUTEAUTHORITY_PORTNUM
    SSL_CERT_DN = "/O=NDG/OU=Security/CN=localhost"
                                    
    SITEA_SAML_ISSUER_NAME = "/O=Site A/CN=Attribute Authority"

    
    PKI_DIR = os.path.join(NDGSEC_TEST_CONFIG_DIR, 'pki')
    CACERT_DIR = os.path.join(PKI_DIR, 'ca')
    SSL_CERT_FILEPATH = os.path.join(PKI_DIR, 'localhost.crt')
    SSL_PRIKEY_FILEPATH = os.path.join(PKI_DIR, 'localhost.key')
    
    VALID_REQUESTOR_IDS = (
        "/O=Site A/CN=Authorisation Service", 
        "/O=Site B/CN=Authorisation Service",
        '/CN=test/O=NDG/OU=BADC',
        '/O=NDG/OU=Security/CN=localhost'
    )
    
    SSL_PEM_FILENAME = 'localhost.pem'
    SSL_PEM_FILEPATH = mk_data_dirpath(os.path.join('pki', SSL_PEM_FILENAME))
    
    def __init__(self, *arg, **kw):
        '''Enable setting of default test directory on start-up of unit tests'''
        self.__class__.set_config_dir_envvar()
                
        unittest.TestCase.__init__(self, *arg, **kw)

