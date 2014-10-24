import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)
import base64
import os
from authkit.permissions import UserIn
from authkit.authorize import authorize

def app1(environ, start_response):
    log.info("app1 ...")
    start_response('200 OK', [('Content-type', 'text/html')])
    return 'Hello'

redirectURL = "http://gabriel.badc.rl.ac.uk/richClient/resource"

class InfoApp(object):
        
    @authorize(UserIn(users=['bob']))
    def __call__(self, environ, start_response):
        if environ.get('PATH_INFO', '').endswith('/resource'):
            return self.resource(environ, start_response)
        else:
            start_response('301 Redirect', 
                           [('Content-type', 'text/html'),
                            ('Location', redirectURL)])
            return []

    def resource(self, environ, start_response):
        start_response("200 OK", [('Content-type', 'text/html')])
        return "Secured Resource"
    
    @staticmethod
    def valid(environ, username, password):
        """validation function"""
        return username == 'bob' and password == 'secret'


def app_factory(global_config, **local_conf):
    return InfoApp()



# To start the Site A Attribute Authority run 
# $ paster serve attribute-service.ini or run this file as a script
# $ ./siteAServerApp.py [port #]
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 40000
                   
    cfgFilePath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'test.ini')
        
    from paste.httpserver import serve
    from paste.deploy import loadapp
    from authkit.authenticate import middleware
    
    appCfg = loadapp('config:%s' % cfgFilePath)
    app = middleware(appCfg,
                     setup_method='basic',
                     basic_realm='Test Realm',
                     basic_authenticate_function=InfoApp.valid)
    serve(app, host='0.0.0.0', port=port)