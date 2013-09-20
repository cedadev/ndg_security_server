#!/usr/bin/env python
"""NDG Security test harness for securing an application with OpenID middleware

NERC DataGrid Project

"""
__author__ = "P J Kershaw"
__date__ = "26/02/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - See top-level directory for LICENSE file."
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

class TestOpenIDMiddleware(object):
    '''Test Application for the Authentication handler to protect'''
    response = "Test OpenID application"
       
    def __init__(self, app_conf, **local_conf):
        pass
    
    def __call__(self, environ, start_response):
        
        if 'REMOTE_USER' in environ:
            response = """<html>
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
            response = "Trigger OpenID Relying Party..."
            start_response('401 Unauthorized', 
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
        return [response]
    
# To start run 
# $ paster serve services.ini or run this file as a script
# $ ./securedapp.py [port #]
if __name__ == '__main__':
    import sys
    import os
    from os.path import dirname, abspath
    import logging
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5080
        
    cfgFilePath = os.path.join(dirname(abspath(__file__)), 'securedapp.ini')
        
    from paste.httpserver import serve
    from paste.deploy import loadapp
    from paste.script.util.logging_config import fileConfig
    
    fileConfig(cfgFilePath)
    app = loadapp('config:%s' % cfgFilePath)
    serve(app, host='0.0.0.0', port=port)