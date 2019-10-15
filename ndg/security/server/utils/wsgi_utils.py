"""Paste related helper utilities (moved from ndg.security.test.unit.wsgi)

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "25/01/11"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:$'
from os import path
import sys

from paste.script.util.logging_config import fileConfig    
from paste.deploy import loadapp
  
import multiprocessing

import gunicorn.app.base
import gunicorn.arbiter

from ndg.security.server.test.base import BaseTestCase


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

    @property
    def number_of_workers(self):
        return (multiprocessing.cpu_count() * 2) + 1
            
    def __init__(self, app, options=None):
        self.options = options or {}
        
        if not 'workers' in options:
            self.options['workers'] = self.number_of_workers
            
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
        'keyfile': path.join(dir_name, 'localhost.key'),
        'certfile': path.join(dir_name, 'localhost.crt')
    }
    cfgFilePath = path.join(dir_name, "attribute-interface.ini")
    fileConfig(cfgFilePath)
    app = loadapp('config:%s' % cfgFilePath)
    
    gunicorn_server_app = GunicornServerApp(app, options)
    app._app._app.gunicorn_server_app = gunicorn_server_app
    gunicorn_server_app.run()
