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

from paste.script.util.logging_config import fileConfig    
from paste.deploy import loadapp

from ndg.security.server.utils.wsgi_utils import GunicornServerApp
from ndg.security.server.test.test_util import TestUserDatabase
from ndg.security.server.test.base import NDGSEC_TEST_CONFIG_DIR

INI_FILENAME = 'openidprovider.ini'
INI_FILEPATH = path.join(path.dirname(path.abspath(__file__)), INI_FILENAME)
DEFAULT_PORT = '7443'

import optparse


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
                      default=DEFAULT_PORT,
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
                      default=INI_FILEPATH,
                      help="Configuration file path")
    
    # Initialise test user database
    TestUserDatabase.init_db()
    
    opt = parser.parse_args()[0]

    dir_name = path.dirname(__file__)
    options = {
        'bind': '{}:{}'.format('127.0.0.1', opt.port),
        'keyfile': opt.prikey_filepath,
        'certfile': opt.cert_filepath
    }
    fileConfig(opt.config_filepath)
    app = loadapp('config:%s' % opt.config_filepath)
    
    gunicorn_server_app = GunicornServerApp(app, options)
    gunicorn_server_app.run()