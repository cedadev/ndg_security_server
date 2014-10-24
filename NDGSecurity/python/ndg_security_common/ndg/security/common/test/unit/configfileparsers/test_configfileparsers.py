#!/usr/bin/env python
"""Unit tests for Credential Wallet class

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "03/10/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import unittest
import os, sys, getpass, re
import traceback

from ndg.security.common.utils.configfileparsers import \
    CaseSensitiveConfigParser, INIPropertyFile, readAndValidateProperties
from ConfigParser import SafeConfigParser

from os.path import expandvars as xpdVars
from os.path import join as jnPath
mkPath=lambda file: jnPath(os.environ['NDGSEC_CONFIGFILEPARSERS_UNITTEST_DIR'],
                           file)

import logging
logging.basicConfig(level=logging.DEBUG)


class ConfigFileParsersTestCase(unittest.TestCase):
    """Unit test case for ndg.security.common.utils.configfileparsers
    module.
    """
    
    def setUp(self):
        
        if 'NDGSEC_INT_DEBUG' in os.environ:
            import pdb
            pdb.set_trace()
        
        if 'NDGSEC_CONFIGFILEPARSERS_UNITTEST_DIR' not in os.environ:
            os.environ['NDGSEC_CONFIGFILEPARSERS_UNITTEST_DIR'] = \
                os.path.abspath(os.path.dirname(__file__))
        
        self.cfg = CaseSensitiveConfigParser()
        self.configFilePath = mkPath("test.cfg")      

    def test1CaseSensitiveConfigParser(self):
        caseSensitiveCfg = CaseSensitiveConfigParser()
        caseSensitiveCfg.read(self.configFilePath)
        
        cfg = SafeConfigParser()
        cfg.read(self.configFilePath)
        cfgVal = cfg.getboolean('test1CaseSensitiveConfigParser', 
                                'CaseSensitiveOption')
        caseSensitiveVal=caseSensitiveCfg.getboolean(
                                            'test1CaseSensitiveConfigParser', 
                                            'CaseSensitiveOption')
        assert(caseSensitiveVal != cfgVal)
        
    def test2INIPropertyFile(self):
        cfgFile = INIPropertyFile()
        validKeys = {'name': NotImplemented, 'useSSL': NotImplemented,
                     'attCertLifetime': 2000}
        prop = cfgFile(self.configFilePath, validKeys,
                       sections=('test2INIPropertyFile',),
                       prefix='attributeAuthority')
        print "properties ..."
        print prop
        print("prop['test2INIPropertyFile']['name']=%s"%
                                        prop['test2INIPropertyFile']['name'])
            
        print("prop['test2INIPropertyFile']['useSSL']"
              "=%s" % prop['test2INIPropertyFile']['useSSL'])
        print("prop['test2INIPropertyFile']['attCertLifetime']=%s" % 
              prop['test2INIPropertyFile']['attCertLifetime'])
        
        assert(isinstance(prop['test2INIPropertyFile']['attCertLifetime'], 
                          float))
        
        assert(isinstance(prop['test2INIPropertyFile']['useSSL'], bool))
            
    def test3ReadAndValidateProperties(self):
        
        # keys set to NotImplemented must be present in the config, others
        # accept defaults as given.  A key set to a populated dict denotes
        # a subcomponent.
        validKeys = {
            'sslCertFile': NotImplemented,
            'sslKeyFile': NotImplemented,
            'sslCACertFilePathList': [],
            'credentialWallet': {
                'attributeAuthorityURI': 'A DEFAULT VALUE',
                'caCertFilePathList': [],
                'mapFromTrustedHosts': False,
                'attCertRefreshElapse': -1
            }
        }

        prop = readAndValidateProperties(self.configFilePath, validKeys,
                               sections=('test3ReadAndValidateProperties',),
                               prefix='sessionManager')
        print "properties ..."
        print prop
        assert(prop.keys()==['test3ReadAndValidateProperties'])
        
        assert(prop['test3ReadAndValidateProperties']['sslCertFile'])
        assert('credentialWallet' in prop['test3ReadAndValidateProperties'])
        
        # attributeAuthorityURI is not present in the config so it should be 
        # set to its default value
        assert(prop['test3ReadAndValidateProperties']
            ['credentialWallet']['attributeAuthorityURI']=='A DEFAULT VALUE')
        
if __name__ == "__main__":
    unittest.main()        
