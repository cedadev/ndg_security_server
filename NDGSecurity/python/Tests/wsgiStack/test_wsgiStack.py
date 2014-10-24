import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

class App3(object):
    def __init__(self, app):
        self.app = app
        
    def __call__(self, environ, start_response):
        log.info("App3 ...")
        def app3_start_response(status, header, exc_info=None):
            log.info("app3_start_response...")
            return start_response(status, header, exc_info=exc_info)
        
        return self.app(environ, app3_start_response)
    
class App2(object):
    def __init__(self, app):
        self.app = app
        
    def __call__(self, environ, start_response):
        log.info("App2 ...")
        def app2_start_response(status, header, exc_info=None):
            log.info("app2_start_response...")
            return start_response(status, header, exc_info=exc_info)
        
        return self.app(environ, app2_start_response)
    
def app1(environ, start_response):
    log.info("app1 ...")
    start_response('200 OK', [('Content-type', 'text/html')])
    return 'Hello'

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5000
        
    from paste.httpserver import serve
    from paste.deploy import loadapp

    app3 = App3(App2(app1))
    serve(app3, host='0.0.0.0', port=port)