"""NDG Security unit test package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "14/05/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import unittest
import logging

logging.basicConfig()
log = logging.getLogger(__name__)

import os
from os.path import join, dirname, abspath

try:
    from hashlib import md5
except ImportError:
    # Allow for < Python 2.5
    from md5 import md5


TEST_CONFIG_DIR = join(abspath(dirname(dirname(__file__))), 'config')

mkDataDirPath = lambda file_:join(TEST_CONFIG_DIR, file_)

from ndg.security.common.saml_utils.esgf import ESGFGroupRoleAttributeValue
    
    
class BaseTestCase(unittest.TestCase):
    '''Convenience base class from which other unit tests can extend.  Its
    sets the generic data directory path'''
    configDirEnvVarName = 'NDGSEC_TEST_CONFIG_DIR'
    
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
    
    
    NDGSEC_TEST_CONFIG_DIR = os.environ.get(configDirEnvVarName, 
                                            TEST_CONFIG_DIR)
    
    PKI_DIR = os.path.join(NDGSEC_TEST_CONFIG_DIR, 'pki')
    CACERT_DIR = os.path.join(PKI_DIR, 'ca')
    SSL_CERT_FILEPATH = os.path.join(PKI_DIR, 'localhost.crt')
    SSL_PRIKEY_FILEPATH = os.path.join(PKI_DIR, 'localhost.key')
    
    # Test database set-up
    DB_FILENAME = 'user.db'
    DB_FILEPATH = join(NDGSEC_TEST_CONFIG_DIR, DB_FILENAME)
    DB_CONNECTION_STR = 'sqlite:///%s' % DB_FILEPATH
    
    USERNAME = 'pjk'
    PASSWORD = 'testpassword'
    MD5_PASSWORD = md5(PASSWORD).hexdigest()
    
    OPENID_URI_STEM = 'https://localhost:7443/openid/'
    OPENID_IDENTIFIER = 'philip.kershaw'
    OPENID_URI = OPENID_URI_STEM + OPENID_IDENTIFIER
    
    FIRSTNAME = 'Philip'
    LASTNAME = 'Kershaw'
    EMAILADDRESS = 'pjk@somewhere.ac.uk'
    
    # Add a second test user
    USERNAME2 = 'another'
    PASSWORD2 = 'testpassword'
    MD5_PASSWORD2 = md5(PASSWORD).hexdigest()
    
    OPENID_IDENTIFIER2 = 'a.n.other'
    OPENID_URI2 = OPENID_URI_STEM + OPENID_IDENTIFIER
    
    FIRSTNAME2 = 'Anne'
    LASTNAME2 = 'Other'
    EMAILADDRESS2 = 'ano@somewhere.ac.uk'
     
    ATTRIBUTE_NAMES = (
        "urn:siteA:security:authz:1.0:attr",
        "urn:siteA:security:authz:1.0:attr",
        "urn:siteA:security:authz:1.0:attr",
        "urn:siteA:security:authz:1.0:attr",
        "urn:siteA:security:authz:1.0:attr",
        "urn:siteA:security:authz:1.0:attr",
        "urn:esg:sitea:grouprole",
    )

    ATTRIBUTE_VALUES = (
        'postdoc',
        'staff', 
        'undergrad', 
        'coapec',
        'rapid',
        'admin',
        'siteagroup:default'
    )
    N_ATTRIBUTE_VALUES = len(ATTRIBUTE_VALUES)
    
    VALID_REQUESTOR_IDS = (
        "/O=Site A/CN=Authorisation Service", 
        "/O=Site B/CN=Authorisation Service",
        '/CN=test/O=NDG/OU=BADC',
        '/O=NDG/OU=Security/CN=localhost'
    )
    
    SSL_PEM_FILENAME = 'localhost.pem'
    SSL_PEM_FILEPATH = mkDataDirPath(os.path.join('pki', SSL_PEM_FILENAME))
    
    def __init__(self, *arg, **kw):
        if BaseTestCase.configDirEnvVarName not in os.environ:
            os.environ[BaseTestCase.configDirEnvVarName] = TEST_CONFIG_DIR
                
        unittest.TestCase.__init__(self, *arg, **kw)


def dbAttr2ESGFGroupRole(attrVal):
    """Callback for SQLAlchemyAttributeInterface class to convert attribute 
    value as stored in the SQLite Db defined here to an ESGF Group/Role 
    Attribute Value type
    """
    groupRoleAttrValue = ESGFGroupRoleAttributeValue()
    
    # The group/role is stored in a single field in the database with a colon
    # separator
    groupRoleAttrValue.value = attrVal.split(':')
    
    return groupRoleAttrValue

