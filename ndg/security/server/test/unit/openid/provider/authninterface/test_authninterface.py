"""OpenID Provider Authentication Interface unit tests

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "12/11/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from os import path
import unittest
      
from ndg.security.server.test.base import BaseTestCase
from ndg.security.server.wsgi.openid.provider.authninterface import (
                                                    AuthNInterfaceConfigError)
from ndg.security.server.wsgi.openid.provider.authninterface.sqlalchemy_authn \
    import SQLAlchemyAuthnInterface


class SQLAlchemyAuthnInterfaceTestCase(BaseTestCase):
    LOGON_SQLQUERY = ("select count(*) from users where username = "
                      "'${username}' and md5password = '${password}'")
    
    USERNAME2USERIDENTIFIER_SQLQUERY = ("select openid_identifier from users "
                                        "where username = '${username}'")
    
    def __init__(self, *arg, **kw):
        super(SQLAlchemyAuthnInterfaceTestCase, self).__init__(*arg, **kw)
        self.__interface = None
        
        self.init_db()
         
    def setUp(self):
        self.__interface = SQLAlchemyAuthnInterface(
            connectionString=SQLAlchemyAuthnInterfaceTestCase.DB_CONNECTION_STR,
            logonSqlQuery=SQLAlchemyAuthnInterfaceTestCase.LOGON_SQLQUERY,
            username2UserIdentifierSqlQuery=\
            SQLAlchemyAuthnInterfaceTestCase.USERNAME2USERIDENTIFIER_SQLQUERY,
            isMD5EncodedPwd=True
        )
                  
    def test01Logon(self):
        self.__interface.logon({}, 
                               None, 
                               SQLAlchemyAuthnInterfaceTestCase.USERNAME, 
                               SQLAlchemyAuthnInterfaceTestCase.PASSWORD)

    def test02Username2UserIdentifier(self):
        self.__interface.username2UserIdentifiers({}, 
                               SQLAlchemyAuthnInterfaceTestCase.USERNAME)
        
                                                        
if __name__ == "__main__":
    unittest.main()
