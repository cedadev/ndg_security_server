import logging
log = logging.getLogger(__name__)

class TestLoggingApp(object):
    '''Test logging with Paste'''
    RESPONSE = __doc__
     
    @classmethod  
    def app_factory(cls, app_conf, **local_conf):
        log.debug("Creating app ...")
        logging.debug("Creating app ...")
        return cls()
    
    def __call__(self, environ, start_response):
        log.debug("Returning response ...")
        logging.debug("Returning response ...")
        start_response('200 OK', 
                       [('Content-type', 'text/plain'),
                        ('Content-length', str(len(TestLoggingApp.RESPONSE)))])
        return [TestLoggingApp.RESPONSE]
    
# To start run 
# $ paster serve services.ini or run this file as a script
# $ ./app.py [port #]
if __name__ == '__main__':
    import sys
    import os
    from os.path import dirname, abspath

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 6080
        
    cfgFilePath = os.path.join(dirname(abspath(__file__)), 'app.ini')
        
    from paste.httpserver import serve
    from paste.deploy import loadapp
    from paste.script.util.logging_config import fileConfig
    
    fileConfig(cfgFilePath)
    app = loadapp('config:%s' % cfgFilePath)
    serve(app, host='0.0.0.0', port=port)