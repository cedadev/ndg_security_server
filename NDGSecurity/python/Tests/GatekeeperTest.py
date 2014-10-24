#!/usr/bin/env python

"""Test harness for NDG Gatekeeper

NERC Data Grid Project

P J Kershaw 15/05/06


Copyright (C) 2009 Science and Technology Facilities Council

"""
import unittest
import os

from ndg.security.Gatekeeper import *


class GkResrcinterface(GatekeeperResrc):
    """Gatekeeper interface test class"""
    
    def __init__(self, **kwargs):
        self.__roleLUT = {'acsoe':          ('r', 'w'), 
                          'government':     ('r',),
                          'nextmap':        ('r', 'w', 'x')}
    
    def getPermissions(self, role):
        """Serve dummy roles and permissions"""
        try:
            return self.__roleLUT[role]
        except:
            return ()
        
        
class GatekeeperTestCase(unittest.TestCase):
    
    def setUp(self):
        try:
            self.gk = Gatekeeper(resrcID='somewhere',
                                 resrcModFilePath='./GatekeeperTest.py',
                                 resrcModName='GatekeeperTest',
                                 resrcClassName='GkResrcinterface') 
        except Exception, e:
            self.fail(str(e))
            
            
    def tearDown(self):
        pass


    def testGetPermissionsRoleInput(self):
        
        try:
            print "Role Permissions: %s" % self.gk('acsoe')
            
        except Exception, e:
            self.fail(str(e))


    def testGetPermissionsRoleListInput(self):

        import pdb
        pdb.set_trace()
        try:
            self.gk.readProperties('gatekeeperProperties.xml')
            self.gk.initResrcinterface()
            
            print "Role List Permissions: %s" % self.gk(['nextmap', 'synop'])
            
        except Exception, e:
            self.fail(str(e))

  
    def testGetPermissionsAttCertInput(self):
        
        try:
            ac = AttCertRead('./ac-y_i5fI.xml')
            print "AC Permissions: %s" % self.gk.getPermissions(ac)
            
        except Exception, e:
            self.fail(str(e))
            
#_____________________________________________________________________________       
class GatekeeperTestSuite(unittest.TestSuite):
    
    def __init__(self):
        logTestMap = map(GatekeeperTestCase,
                  (
                    "testGetPermissionsRoleInput",
                    "testGetPermissionsRoleListInput",
                    "testGetPermissionsAttCertInput"
                  ))
        unittest.TestSuite.__init__(self, logTestMap)
            
                                                    
if __name__ == "__main__":
    unittest.main()        
