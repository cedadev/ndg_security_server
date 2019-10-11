"""Paste related helper utilities (moved from ndg.security.test.unit.wsgi)

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "25/01/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:$'
import select
from os import path
from threading import Thread

import paste.httpserver
from paste.deploy import loadapp
from paste.script.util.logging_config import fileConfig


class PasteDeployAppServer(object):
    """Wrapper to paste.httpserver to enable background threading"""
    
    def __init__(self, app=None, cfgFilePath=None, port=7443, host='0.0.0.0',
                 ssl_context=None):
        """Load an application configuration from cfgFilePath ini file and 
        instantiate Paste server object
        """       
        self.__thread = None
        
        if cfgFilePath:
            if app:
                raise KeyError('Set either the "cfgFilePath" or "app" keyword '
                               'but not both')
            
            fileConfig(cfgFilePath, defaults={'here':path.dirname(cfgFilePath)})
            app = loadapp('config:%s' % cfgFilePath)
            
        elif app is None:
            raise KeyError('Either the "cfgFilePath" or "app" keyword must be '
                           'set')
                       
        self.__pasteServer = paste.httpserver.serve(app, host=host, port=port, 
                                                    start_loop=False, 
                                                    ssl_context=ssl_context)
    
    @property
    def pasteServer(self):
        return self.__pasteServer
    
    @property
    def thread(self):
        return self.__thread
    
    def start(self):
        """Start server"""
        try:
            self.pasteServer.serve_forever()
        except select.error:
            # File descriptor error can be raised if a test fails - no need to
            # take any further action
            pass
        
    def startThread(self):
        """Start server in a separate thread"""
        self.__thread = Thread(target=PasteDeployAppServer.start, args=(self,))
        self.thread.start()
        
    def terminateThread(self):
        self.pasteServer.server_close()

from os import path
import sys

from paste.script.util.logging_config import fileConfig    
from paste.deploy import loadapp
  
import multiprocessing

import gunicorn.app.base
import gunicorn.arbiter

from ndg.security.server.test.base import BaseTestCase

def number_of_workers():
    return (multiprocessing.cpu_count() * 2) + 1


class GunicornServerApp(gunicorn.app.base.BaseApplication):

    @classmethod
    def from_config(cls, cfgFilePath, port=7443, host='127.0.0.1',
                    certfile=BaseTestCase.SSL_CERT_FILEPATH, 
                    keyfile=BaseTestCase.SSL_PRIKEY_FILEPATH):
        """Load an application configuration from cfgFilePath ini file"""
        options = {
            'bind': '%s:%s' % (host, str(port)),
            'workers': number_of_workers(),
            'keyfile': keyfile,
            'certfile': certfile
            }
        
        fileConfig(cfgFilePath, defaults={'here':path.dirname(cfgFilePath)})
            
        app = loadapp('config:%s' % cfgFilePath)

        obj = cls(app, options)
        app._app._app.gunicorn_server_app = obj
        
        return obj
        
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        self.arbiter = None
        super().__init__()

    def load_config(self):
        config = dict([(key, value) for key, value in self.options.items()
                       if key in self.cfg.settings and value is not None])
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application
    
    def run(self):
        '''Extend in order to save arbiter reference'''
        try:
            self.arbiter = gunicorn.arbiter.Arbiter(self)
            self.arbiter.run()
            
        except RuntimeError as e:
            print("\nError: {}\n".format(e), file=sys.stderr)
            sys.stderr.flush()
            sys.exit(1)
            
    def kill_workers(self, sig):
        self.arbiter.kill_workers(sig)


if __name__ == '__main__':
    dir_name = path.dirname(__file__)
    options = {
        'bind': '%s:%s' % ('127.0.0.1', '5443'),
        'workers': number_of_workers(),
        'keyfile': path.join(dir_name, 'localhost.key'),
        'certfile': path.join(dir_name, 'localhost.crt')
    }
    cfgFilePath = path.join(dir_name, "attribute-interface.ini")
    fileConfig(cfgFilePath)
    app = loadapp('config:%s' % cfgFilePath)
    
    gunicorn_server_app = GunicornServerApp(app, options)
    app._app._app.gunicorn_server_app = gunicorn_server_app
    gunicorn_server_app.run()
