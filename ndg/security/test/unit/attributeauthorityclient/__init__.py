"""Attribute Authority SOAP client unit test package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "23/11/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from os import path, environ

from ndg.security.test.unit import BaseTestCase
from ndg.security.common.X509 import X509Cert
from ndg.security.common.utils.configfileparsers import (
    CaseSensitiveConfigParser)


class AttributeAuthorityClientBaseTestCase(BaseTestCase):
    """Base class for NDG and SAML Attribute Authority client interfaces"""
    CONFIG_FILENAME = 'attAuthorityClientTest.cfg'
    
    def __init__(self, *arg, **kw):
        super(AttributeAuthorityClientBaseTestCase, self).__init__(*arg, **kw)

        if 'NDGSEC_AACLNT_UNITTEST_DIR' not in environ:
            environ['NDGSEC_AACLNT_UNITTEST_DIR'
                                        ] = path.abspath(path.dirname(__file__))

        self.cfgParser = CaseSensitiveConfigParser()
        self.cfgFilePath = path.join(environ['NDGSEC_AACLNT_UNITTEST_DIR'],
                                     self.__class__.CONFIG_FILENAME)
        self.cfgParser.read(self.cfgFilePath)
        
        self.cfg = {}
        for section in self.cfgParser.sections():
            self.cfg[section] = dict(self.cfgParser.items(section))

        try:
            self.sslCACertList = [X509Cert.Read(xpdVars(caFile)) 
                                  for caFile in self.cfg['setUp'][
                                            'sslcaCertFilePathList'].split()]
        except KeyError:
            self.sslCACertList = []
       
