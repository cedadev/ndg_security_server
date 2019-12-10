#!/usr/bin/env python
"""NDG Security test harness for authentication and authorisation

NERC DataGrid Project

"""
__author__ = "P J Kershaw"
__date__ = "25/01/11"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
import os
from os.path import dirname, abspath
import optparse

from paste.script.util.logging_config import fileConfig    
from paste.deploy import loadapp

from ndg.security.server.utils.wsgi_utils import GunicornServerApp


CFG_FILEPATH = os.path.join(dirname(abspath(__file__)), 'securedapp.ini')


class TestOpenIDRelyingPartyMiddleware(object):
    '''Test Application for the Authentication handler to protect'''
    response = "Test Authentication redirect application"
       
    def __init__(self, app_conf, **local_conf):
        self.beakerSessionKeyName = app_conf['beakerSessionKeyName']
    
    def __call__(self, environ, start_response):
        
        username = environ[self.beakerSessionKeyName].get('username')
        if username:
            response = b"""<html>
    <head/>
    <body>
        <p>Authenticated!</p>
        <p><a href="/logout">logout</a></p>
    </body>
</html>"""
            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = b"Trigger OpenID Relying Party..."
            start_response('401 Unauthorized', 
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
        return [response]
    

if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    fileConfig(CFG_FILEPATH)
    parser = optparse.OptionParser()
    parser.add_option("-p",
                      "--port",
                      dest="port",
                      default=6080,
                      type='int',
                      help="port number to run under")

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

    options = {
        'bind': '{}:{}'.format('127.0.0.1', opt.port),
        'timeout': opt.timeout
    }
    fileConfig(opt.config_filepath)
    app = loadapp('config:%s' % opt.config_filepath)
    
    gunicorn_server_app = GunicornServerApp(app, options)
    gunicorn_server_app.run()
