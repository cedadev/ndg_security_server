#!/usr/bin/env python
"""NDG Security test harness for OpenID Provider service

NERC DataGrid Project

"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from os import path 
      
from OpenSSL import SSL

from ndg.security.server.utils.paste_utils import PasteDeployAppServer
from ndg.security.server.test.test_util import TestUserDatabase
from ndg.security.server.test.base import NDGSEC_TEST_CONFIG_DIR

INI_FILENAME = 'openidprovider.ini'
INI_FILEPATH = path.join(path.dirname(path.abspath(__file__)), INI_FILENAME)
DEFAULT_PORT = 7443

import optparse

# To start run:
#
# $ paster serve openidprovider.ini 
#
# or run this file as a script, see:
#
# $ ./openidprovider.py -h
if __name__ == '__main__':       
    defCertFilePath = path.join(NDGSEC_TEST_CONFIG_DIR, 
                                'pki', 
                                'localhost.crt')
    defPriKeyFilePath = path.join(NDGSEC_TEST_CONFIG_DIR, 
                                  'pki', 
                                  'localhost.key')
    
    parser = optparse.OptionParser()
    parser.add_option("-p",
                      "--port",
                      dest="port",
                      default=DEFAULT_PORT,
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
                      dest='priKeyFilePath',
                      default=defPriKeyFilePath,
                      help="SSL private key file")

    parser.add_option("-f",
                      "--conf",
                      dest="configFilePath",
                      default=INI_FILEPATH,
                      help="Configuration file path")
    
    # Initialise test user database
    TestUserDatabase.init_db()
    
    opt = parser.parse_args()[0]
    
    if opt.withSSL.lower() == 'true':        
        ssl_context = SSL.Context(SSL.TLSv1_METHOD)
    
        ssl_context.use_privatekey_file(opt.priKeyFilePath)
        ssl_context.use_certificate_file(opt.certFilePath)
    else:
        ssl_context = None

    server = PasteDeployAppServer(cfgFilePath=path.abspath(opt.configFilePath), 
                                  port=opt.port,
                                  ssl_context=ssl_context) 
    server.start()
