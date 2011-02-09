#!/usr/bin/env python
"""NDG Security test harness for security web services middleware stack

NERC DataGrid Project

"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: securityservicesapp.py 7847 2011-01-26 16:40:54Z pjkersha $"
from os import path
import optparse 
     
from OpenSSL import SSL

from ndg.security.server.utils.paste_utils import PasteDeployAppServer
from ndg.security.test.unit import BaseTestCase

INI_FILENAME = 'securityservices.ini'

# To start run 
# $ paster serve services.ini or run this file as a script, see
# $ ./securityservicesapp.py -h
if __name__ == '__main__':    
    cfgFilePath = path.join(path.dirname(path.abspath(__file__)), INI_FILENAME) 
     
    defCertFilePath = path.join(BaseTestCase.NDGSEC_TEST_CONFIG_DIR, 
                                'pki', 
                                'localhost.crt')
    defPriKeyFilePath = path.join(BaseTestCase.NDGSEC_TEST_CONFIG_DIR, 
                                  'pki', 
                                  'localhost.key')
        
    parser = optparse.OptionParser()
    parser.add_option("-p",
                      "--port",
                      dest="port",
                      default=7443,
                      type='int',
                      help="port number to run under")

    parser.add_option("-s",
                      "--with-ssl",
                      dest="withSSL",
                      default='True',
                      help="Run with SSL")

    parser.add_option("-c",
                      "--cert-file",
                      dest='certFilePath',
                      default=defCertFilePath,
                      help="SSL Certificate file")

    parser.add_option("-k",
                      "--private-key-file",
                      default=defPriKeyFilePath,
                      dest='priKeyFilePath',
                      help="SSL private key file")

    parser.add_option("-f",
                      "--conf",
                      dest="configFilePath",
                      default=cfgFilePath,
                      help="Configuration file path")
    
    opt = parser.parse_args()[0]
    
    if opt.withSSL.lower() == 'true':
        
        ssl_context = SSL.Context(SSL.SSLv23_METHOD)
        ssl_context.set_options(SSL.OP_NO_SSLv2)
    
        ssl_context.use_privatekey_file(opt.priKeyFilePath)
        ssl_context.use_certificate_file(opt.certFilePath)
    else:
        ssl_context = None

    server = PasteDeployAppServer(cfgFilePath=path.abspath(opt.configFilePath), 
                                  port=opt.port,
                                  ssl_context=ssl_context) 
    server.start()
