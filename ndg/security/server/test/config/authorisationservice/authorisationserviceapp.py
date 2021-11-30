#!/usr/bin/env python
"""NDG Security test harness for authorisation service

NERC DataGrid Project

"""
__author__ = "P J Kershaw"
__date__ = "25/01/11"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from os import path
import optparse 

from paste.script.util.logging_config import fileConfig    
from paste.deploy import loadapp

from ndg.security.server.utils.wsgi_utils import GunicornServerApp
from ndg.security.server.test.base import NDGSEC_TEST_CONFIG_DIR

INI_FILENAME = 'authorisation-service.ini'
CFG_FILEPATH = path.join(path.dirname(path.abspath(__file__)), INI_FILENAME)


if __name__ == '__main__':    
    def_cert_filepath = path.join(NDGSEC_TEST_CONFIG_DIR, 
                                  'pki', 
                                  'localhost.crt')
    def_prikey_filepath = path.join(NDGSEC_TEST_CONFIG_DIR, 
                                   'pki', 
                                   'localhost.key')
    
    parser = optparse.OptionParser()
    parser.add_option("-p",
                      "--port",
                      dest="port",
                      default=9443,
                      type='int',
                      help="port number to run under")

    parser.add_option("-c",
                      "--cert-file",
                      dest='cert_filepath',
                      default=def_cert_filepath,
                      help="SSL Certificate file")

    parser.add_option("-k",
                      "--private-key-file",
                      dest='prikey_filepath',
                      default=def_prikey_filepath,
                      help="SSL private key file")

    parser.add_option("-f",
                      "--conf",
                      dest="config_filepath",
                      default=CFG_FILEPATH,
                      help="Configuration file path")

    parser.add_option("-t",
                      "--timeout",
                      dest="timeout",
                      default=3,
                      type='int',
                      help="timeout in seconds")  
      
    opt = parser.parse_args()[0]

    dir_name = path.dirname(__file__)
    options = {
        'bind': '{}:{}'.format('127.0.0.1', opt.port),
        'keyfile': opt.prikey_filepath,
        'certfile': opt.cert_filepath,
        'timeout': opt.timeout
    }
    fileConfig(opt.config_filepath)
    app = loadapp('config:%s' % opt.config_filepath)
    
    gunicorn_server_app = GunicornServerApp(app, options)
    gunicorn_server_app.run()

