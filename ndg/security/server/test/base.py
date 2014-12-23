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

try:
    from hashlib import md5
except ImportError:
    # Allow for < Python 2.5
    from md5 import md5

try:
    from sqlalchemy import (create_engine, MetaData, Table, Column, Integer, 
                            String)
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker
    
    sqlAlchemyInstalled = True
except ImportError:
    sqlAlchemyInstalled = False
    
TEST_CONFIG_DIR = join(abspath(dirname(__file__)), 'config')

mk_data_dirpath = lambda file_:join(TEST_CONFIG_DIR, file_)
    
    
class BaseTestCase(unittest.TestCase):
    '''Convenience base class from which other unit tests can extend.  Its
    sets the generic data directory path'''
    CONFIG_DIR_ENVVARNAME = 'NDGSEC_TEST_CONFIG_DIR'
    
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
    
    
    NDGSEC_TEST_CONFIG_DIR = os.environ.get(CONFIG_DIR_ENVVARNAME, 
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
    SSL_PEM_FILEPATH = mk_data_dirpath(os.path.join('pki', SSL_PEM_FILENAME))
    
    def __init__(self, *arg, **kw):
        '''Enable setting of default test directory on start-up of unit tests'''
        if BaseTestCase.CONFIG_DIR_ENVVARNAME not in os.environ:
            os.environ[BaseTestCase.CONFIG_DIR_ENVVARNAME] = TEST_CONFIG_DIR
                
        unittest.TestCase.__init__(self, *arg, **kw)

 
    @classmethod
    def init_db(cls):
        """Wrapper to _create_db - Create database only if it doesn't already 
        exist"""
        if not os.path.isfile(cls.DB_FILEPATH):
            cls._create_db()
        
    @classmethod  
    def _create_db(cls):
        """Create a test SQLite database with SQLAlchemy for use with unit 
        tests
        """
        log.debug("Creating database for %r ..." % cls.__name__)
        
        if not sqlAlchemyInstalled:
            raise NotImplementedError("SQLAlchemy must be installed in order "
                                      "for this method to be implemented")
            
        db = create_engine(cls.DB_CONNECTION_STR)
        
        metadata = MetaData()
        usersTable = Table('users', metadata,
                           Column('id', Integer, primary_key=True),
                           Column('username', String),
                           Column('md5password', String),
                           Column('openid', String),
                           Column('openid_identifier', String),
                           Column('firstname', String),
                           Column('lastname', String),
                           Column('emailaddress', String))
        
        attributesTable = Table('attributes', metadata,
                                Column('id', Integer, primary_key=True),
                                Column('openid', String),
                                Column('attributename', String),
                                Column('attributetype', String))
        metadata.create_all(db)
        
        class User(declarative_base()):
            __tablename__ = 'users'
        
            id = Column(Integer, primary_key=True)
            username = Column('username', String(40))
            md5password = Column('md5password', String(64))
            openid = Column('openid', String(128))
            openid_identifier = Column('openid_identifier', String(40))
            firstname = Column('firstname', String(40))
            lastname = Column('lastname', String(40))
            emailAddress = Column('emailaddress', String(40))
        
            def __init__(self, username, md5password, openid, openid_identifier, 
                         firstname, lastname, emailaddress):
                self.username = username
                self.md5password = md5password
                self.openid = openid
                self.openid_identifier = openid_identifier
                self.firstname = firstname
                self.lastname = lastname
                self.emailAddress = emailaddress
        
        class Attribute(declarative_base()):
            __tablename__ = 'attributes'
        
            id = Column(Integer, primary_key=True)
            openid = Column('openid', String(128))
            attributename = Column('attributename', String(40))
            attributetype = Column('attributetype', String(40))
        
            def __init__(self, openid, attributetype, attributename):
                self.openid = openid
                self.attributetype = attributetype
                self.attributename = attributename

        Session = sessionmaker(bind=db)
        session = Session()
        
        attributes = [Attribute(cls.OPENID_URI, attrType, attrVal)
                      for attrType, attrVal in zip(cls.ATTRIBUTE_NAMES, 
                                                   cls.ATTRIBUTE_VALUES)]
        session.add_all(attributes)
           
        user = User(cls.USERNAME, 
                    cls.MD5_PASSWORD,
                    cls.OPENID_URI,
                    cls.OPENID_IDENTIFIER,
                    cls.FIRSTNAME,
                    cls.LASTNAME,
                    cls.EMAILADDRESS)
        
        session.add(user)
           
        # Add a second user entry
        user2 = User(cls.USERNAME2, 
                     cls.MD5_PASSWORD2,
                     cls.OPENID_URI2,
                     cls.OPENID_IDENTIFIER2,
                     cls.FIRSTNAME2,
                     cls.LASTNAME2,
                     cls.EMAILADDRESS2)
        
        session.add(user2)

        session.commit() 
