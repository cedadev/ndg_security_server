"""OpenID Provider AX Interface unit tests

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "11/11/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from os import path

from openid.extensions.ax import FetchRequest, FetchResponse, AttrInfo
        
from ndg.security.server.test.base import BaseTestCase
from ndg.security.server.wsgi.openid.provider.axinterface import (
                                                        AXInterfaceConfigError)
from ndg.security.server.wsgi.openid.provider.axinterface.sqlalchemy_ax import (
                                                        SQLAlchemyAXInterface)



class SQLAlchemyAXInterfaceTestCase(BaseTestCase):    
    def __init__(self, *arg, **kw):
        super(SQLAlchemyAXInterfaceTestCase, self).__init__(*arg, **kw)
        self.init_db()
            
    def test01InvalidQueryUsernameKey(self):
        interface = SQLAlchemyAXInterface()
        interface.connectionString = \
            SQLAlchemyAXInterfaceTestCase.DB_CONNECTION_STR
            
        interface.sqlQuery = ("select firstname from users where username = "
                              "'${invalidUsernameKey}'")
        
        axReq = FetchRequest()
        axResp = FetchResponse()
        
        authnCtx = {
            SQLAlchemyAXInterface.USERNAME_SESSION_KEYNAME: 
                SQLAlchemyAXInterfaceTestCase.USERNAME
        }
        
        try:
            interface(axReq, axResp, None, authnCtx)
            
        except AXInterfaceConfigError:
            pass
        else:
            self.fail("Expected AXInterfaceConfigError exception")
        
    def test02(self):
        interface = SQLAlchemyAXInterface()
        interface.connectionString = \
            SQLAlchemyAXInterfaceTestCase.DB_CONNECTION_STR
            
        interface.attributeNames = ('firstName', 'lastName', 'emailAddress')
        
        interface.sqlQuery = ("select firstname, lastname, emailAddress from "
                              "users where username = '${username}'")
        
        axReq = FetchRequest()
        
        for typeURI in interface.attributeNames:
            axReq.add(AttrInfo(typeURI, required=True))
            
        axResp = FetchResponse()
        
        authnCtx = {
            SQLAlchemyAXInterface.USERNAME_SESSION_KEYNAME: 
                SQLAlchemyAXInterfaceTestCase.USERNAME
        }
        
        interface(axReq, axResp, None, authnCtx)
        axData = axResp.getExtensionArgs()
        self.assert_(len(axData.keys()) > 0)
        print(axData)
                              