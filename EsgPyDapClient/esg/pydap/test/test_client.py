"""Unit tests for Secured PyDAP client 
"""
__author__ = "P J Kershaw"
__date__ = "12/05/10"
__copyright__ = ""
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:$'
import logging
logging.basicConfig(level=logging.DEBUG)
import unittest
from os import path
from ConfigParser import SafeConfigParser

import pydap.client
from esg.pydap.client import DapClient


def make_cert():

    # Get a proxy certificate from the CEDA MyProxy instance
    mp = MyProxyClient(hostname='<CEDA MyProxy Service>', serverCNPrefix='')
    username = getpass.getuser()
    password = getpass.getpass()
    cert, key = mp.logon(username, password)

    # Save the certificate
    cert_fh = open(cert_file, 'w')
    cert_fh.write(key)
    cert_fh.write(cert)
    cert_fh.close()
    
    
class PyDapClientUnitTestCase(unittest.TestCase):
    HERE_DIR = path.dirname(__file__)
    CFG_FILEPATH = path.join(HERE_DIR, 'test_client.ini')
    
    def __init__(self, *arg, **kw):
        super(PyDapClientUnitTestCase, self).__init__(*arg, **kw)
        self.cfg = SafeConfigParser(defaults={'here': self.__class__.HERE_DIR})
        self.cfg.optionxform = str
        self.cfg.read(self.__class__.CFG_FILEPATH)

    def test01(self):
        certFilePath = self.cfg.get('DEFAULT', 'certFilePath')
        priKeyFilePath = self.cfg.get('DEFAULT', 'priKeyFilePath')
        url = self.cfg.get('DEFAULT', 'url')
        
        from pydap.util.http import request
        
        client = DapClient(certFilePath, priKeyFilePath)
        
        from pydap.util.http import request
        
        dat = client.open_url(url)
        self.assert_(dat)
