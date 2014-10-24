#!/bin/env python

import unittest
from ndg.security.AttCert import *


class attCertTestCase(unittest.TestCase):
    
    def setUp(self):
        self.attCert = AttCert()
        self.attCert['provenance'] = 'original'
        self.attCert.setValidityTime(lifeTime=60*60*8.)
        self.attCert.addRoles(['government', 'acsoe', 'atsr'])
        
    def tearDown(self):
        pass


            
    def testAttCert2Sign(self):
        certFilePathList = [ "./Junk-cert.pem",
                             "/usr/local/NDG/conf/certs/cacert.pem"]
                             
        signingPriKeyFilePath = "./Junk-key.pem"
        priKeyPwd = open("./tmp2").read().strip()
        
        import pdb
        pdb.set_trace()
                    
        # Digitally sign certificate using Attribute Authority's
        # certificate and private key
        self.attCert.sign(certFilePathList=certFilePathList,
                          signingKeyFilePath=signingPriKeyFilePath,
                          signingKeyPwd=priKeyPwd)
        
        # Check the certificate is valid
        self.attCert.isValid(raiseExcep=True)
        print "Signature is valid\n"
        
        print "AttCert.asString()...\n"
        print self.attCert.asString()
            
            
    def testAttCert4NonZero(self):
        
        try:
            if not self.attCert:
                self.fail("AttCert instance yields 0")
            
        except Exception, e:
            self.fail(str(e))
        

class attCertTestSuite(unittest.TestSuite):
    def __init__(self):
        map = map(attCertTestCase,
                  (
                    "test1AttCertAddRoles",
                    "test2AttCertSign",
                    "test3AttCertAsString",
                    "test4AttCertNonZero",
                  ))
        unittest.TestSuite.__init__(self, map)
 
                                       
if __name__ == "__main__":
    unittest.main()