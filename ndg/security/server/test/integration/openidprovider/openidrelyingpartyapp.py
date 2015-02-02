#!/usr/bin/env python
"""NDG Security test harness for authorisation middleware used to secure an
application

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - See top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from os import path
import optparse

from ndg.security.server.test import base
from ndg.security.server.utils.paste_utils import PasteDeployAppServer

   
def app_factory(globalConfig, **localConfig):
    '''OpenIdTestHarnessApp factory for Paste app pattern'''
    return OpenIdRelyingPartyTestHarnessApp(None, globalConfig, **localConfig)

def filter_app_factory(app, globalConfig, **localConfig):
    '''OpenIdTestHarnessApp factory for Paste filter app pattern'''
    return OpenIdRelyingPartyTestHarnessApp(app, globalConfig, **localConfig)

class OpenIdRelyingPartyTestHarnessApp(object):
    """This class simulates the application to be secured by the NDG Security
    OpenID Relying Party middleware
    """
    method = {
"/": 'default',
"/test_securedURI": "test_securedURI",
"/test_publicURI": "test_publicURI"
    }
    header = """        <h1>OpenID Provider Integration Tests:</h1>
        <p>These tests require the OpenID Provider application to be
        running.  See openidprovider.py and openidprovider.ini in the 
        ndg/security/test/integration/openidprovider/ integration test 
        directory.</p>
        <h2>To Run:</h2>
        <p>Try any of the links below.  When prompt for username and password,
        enter one of the sets of credentials:
        </p>
        <p>pjk/testpassword</p>
        <p>another/testpassword</p>
"""

    def __init__(self, app, globalConfig, **localConfig):
        self.app = app
            
    def __call__(self, environ, start_response):
        
        methodName = self.method.get(environ['PATH_INFO'], '').rstrip()
        if methodName:
            action = getattr(self, methodName)
            return action(environ, start_response)
        elif environ['PATH_INFO'] == '/logout':
            return self.default(environ, start_response)
        
        elif self.app is not None:
            return self.app(environ, start_response)
        else:
            start_response('404 Not Found', [('Content-type', 'text/plain')])
            return "Authorisation integration tests: invalid URI"
            
    def default(self, environ, start_response):
        if 'REMOTE_USER' in environ:
            response = """<html>
    <head/>
    <body>
        %s
        <ul>%s</ul>
        <p>You are logged in with OpenID [%s].  <a href="/logout">Logout</a></p>
    </body>
</html>
""" % (self.__class__.header,
       '\n'.join(['<li><a href="%s">%s</a></li>' % (link, name) 
                 for link,name in self.method.items() if name != 'default']),
       environ['REMOTE_USER'])
        
            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = """<html>
    <head/>
    <body>
        %s
        <ul>%s</ul>
    </body>
</html>
""" % (self.__class__.header,
       '\n'.join(['<li><a href="%s">%s</a></li>' % (link, name) 
                 for link,name in self.method.items() if name != 'default'])
       )

            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        return response

    def test_securedURI(self, environ, start_response):
        if 'REMOTE_USER' in environ:
            response = """<html>
    <head/>
    <body>
        <h1>Authenticated!</h1>
        <ul>%s</ul>
        <p>You are logged in.  <a href="/logout">Logout</a></p>
    </body>
</html>
""" % '\n'.join(['<li><a href="%s">%s</a></li>' % (link, name) 
                 for link,name in self.method.items() if name != 'default'])

            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = "Trigger OpenID Relying Party..."
            start_response('401 Unauthorized', 
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
        return response

    def test_publicURI(self, environ, start_response):
        """This URI is expected NOT to match the interceptUriPat attribute
        setting of AuthenticationEnforcementFilter
        """
        if 'REMOTE_USER' in environ:
            response = """<html>
    <head/>
    <body>
        <h1>Public path [%s], no authentication required</h1>
        <ul>%s</ul>
        <p>You are logged in with OpenID [%s].  <a href="/logout">Logout</a></p>
    </body>
</html>
""" % (environ['PATH_INFO'],
       '\n'.join(['<li><a href="%s">%s</a></li>' % (link, name) 
                 for link,name in self.method.items() if name != 'default']),
       environ['REMOTE_USER'])


            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
        else:
            response = ("Public URI no authentication required to access it")
            start_response('200 OK', 
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
        return response
   
    @classmethod
    def app_factory(cls, globalConfig, **localConfig):
        return cls(None, globalConfig, **localConfig)
    
    @classmethod
    def filter_app_factory(cls, app, globalConfig, **localConfig):
        return cls(app, globalConfig, **localConfig)
   
    
INI_FILENAME = 'openidrelyingparty.ini'
INI_FILEPATH = path.join(path.dirname(path.abspath(__file__)), INI_FILENAME)
DEFAULT_PORT = 7080

# To start run 
#
# $ paster serve openidrelyingparty.ini 
#
# or run this file as a script, see:
#
# $ ./openidrelyingparty.py -h
if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-p",
                      "--port",
                      dest="port",
                      default=DEFAULT_PORT,
                      type='int',
                      help="port number to run under")

    parser.add_option("-c",
                      "--conf",
                      dest="configFilePath",
                      default=INI_FILEPATH,
                      help="Configuration file path")
    
    opt = parser.parse_args()[0]
    
    base.set_config_dir_envvar()
    base.set_integration_dir_envvar()
        
    server = PasteDeployAppServer(cfgFilePath=path.abspath(opt.configFilePath), 
                                  port=opt.port) 
    server.start()
