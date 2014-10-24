'''
Created on 27 Sep 2010

@author: pjkersha
'''
import logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)
from webob import Request
    
class QueryArgFilter(object):
    def __init__(self, app):
        self.app = app
        
    def __call__(self, environ, start_response):
        log.info("QueryArgFilter called ...")
        request = Request(environ)
        if environ.get('QUERY_STRING'):
            response = 'Application response was filtered'
            start_response('200 OK', 
                           [('Content-type', 'text/html'),
                            ('Content-length', str(len(response)))])
            return [response]
        else:   
            return self.app(environ, start_response)
    
    
def hello_application(environ, start_response):
    log.info("hello_application called ...")
    response = 'Hello'
    start_response('200 OK', 
                   [('Content-type', 'text/html'),
                    ('Content-length', str(len(response)))])
    return [response]


if __name__ == '__main__':
    from paste.httpserver import serve

    app = QueryArgFilter(hello_application)
    serve(app, host='0.0.0.0', port=5000)
