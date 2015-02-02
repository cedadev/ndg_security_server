"""NDG Security test utilities module - use to initialise and add content to
test user database

"""
__author__ = "P J Kershaw"
__date__ = "02/02/15"
__copyright__ = "(C) 2015 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from hashlib import md5
import os
import logging

from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
    
from ndg.security.server.test.base import NDGSEC_TEST_CONFIG_DIR

logging.basicConfig()
log = logging.getLogger(__name__)


# Tables for database
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
            

class TestUserDatabase(object):
    '''Simple collections of routines to make and add to user database'''
    
    # Test database set-up
    DB_FILENAME = 'user.db'
    DB_FILEPATH = os.path.join(NDGSEC_TEST_CONFIG_DIR, DB_FILENAME)
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
    OPENID_URI2 = OPENID_URI_STEM + OPENID_IDENTIFIER2
    
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
       
    @classmethod
    def init_db(cls):
        """Wrapper to _create_db - Create database only if it doesn't already 
        exist"""
        if not os.path.isfile(cls.DB_FILEPATH):
            db = cls._create_db()
            return db
        else:
            return None
            
    @classmethod
    def add_user(cls, username, password, openid_uri, first_name, last_name,
                 email_address):
        '''Add a user to the test database'''
        db = cls.init_db()
        if db is None:
            db = create_engine(cls.DB_CONNECTION_STR)
        
        Session = sessionmaker(bind=db)
        session = Session()
        
        # Get the last part of the OpenID path as the id
        openid_identifier = openid_uri.rsplit('/')[-1]

        md5_password = md5(password).hexdigest()
        
        user = User(username, md5_password, openid_uri, openid_identifier,
                    first_name, last_name, email_address)
        
        session.add(user)

        session.commit()         
        
    @classmethod  
    def _create_db(cls):
        """Create a test SQLite database with SQLAlchemy for use with unit 
        tests
        """
        log.debug("Creating database for %r ..." % cls.__name__)
                    
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
        
        return db
    
if __name__ == "__main__":
    import sys
    
    prog_name = os.path.basename(__file__)
    n_args = len(sys.argv)
    if n_args < 2:
        raise SystemExit('Usage: %s [init|add_user]' % prog_name)
    
    arg = sys.argv[1]
    
    if arg == 'init':
        TestUserDatabase.init_db()
    elif arg == 'add_user':
        if n_args < 8:
            raise SystemExit('Usage: %s add_user ' 
                             '<username> <password> <openid_uri> <first_name> '
                             '<last_name> <email_address>' % prog_name)
        TestUserDatabase.add_user(*sys.argv[2:])
    else:
        raise SystemExit('Usage: %s [init|add_user]' % prog_name)