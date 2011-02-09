#!/usr/bin/env python
"""NDG Security Attribute Authority test harness for unit test site 'A'

NERC Data Grid Project

"""
__author__ = "P J Kershaw"
__date__ = "24/09/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: attributeauthorityapp.py 7844 2011-01-25 11:24:53Z pjkersha $"
from os import path
import optparse
from ndg.security.server.utils.paste_utils import PasteDeployAppServer

INI_FILENAME = 'attribute-service.ini'


# To start the Site A Attribute Authority run 
# $ paster serve attribute-service.ini or run this file as a script
# $ ./sitea_attributeauthority.py [--port #][--conf <config file path>]
if __name__ == '__main__':
    cfgFilePath = path.join(path.dirname(path.abspath(__file__)), INI_FILENAME)  
        
    parser = optparse.OptionParser()
    parser.add_option("-p",
                      "--port",
                      dest="port",
                      default=5443,
                      type='int',
                      help="port number to run under")

    parser.add_option("-c",
                      "--cert-file",
                      dest='certFilePath',
                      help="SSL Certificate file")

    parser.add_option("-k",
                      "--private-key-file",
                      dest='priKeyFilePath',
                      help="SSL private key file")

    parser.add_option("-f",
                      "--conf",
                      dest="configFilePath",
                      default=cfgFilePath,
                      help="Configuration file path")
    
    opt = parser.parse_args()[0]        
    
    if opt.certFilePath:    
        from OpenSSL import SSL
        
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