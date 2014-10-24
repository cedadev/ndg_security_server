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

import paste.httpserver
from threading import Thread
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
        self.pasteServer.serve_forever()
        
    def startThread(self):
        """Start server in a separate thread"""
        self.__thread = Thread(target=PasteDeployAppServer.start, args=(self,))
        self.thread.start()
        
    def terminateThread(self):
        self.pasteServer.server_close()

