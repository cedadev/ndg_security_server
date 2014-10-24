"""Test module to illustrate the AuthKit Multihandler based security 
middleware upon which NDG Security is based
 
NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "04/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

from authkit.authenticate.multi import MultiHandler

def myApp(environ, start_response):
    """Test application to be secured"""
    
    if environ['PATH_INFO'] == "/test_401":
        status = "401 Unauthorized"
        response = status
        
    elif environ['PATH_INFO'] == "/test_403":
        status = "403 Forbidden"
        response = status
        
    elif environ['PATH_INFO'] == "/test_secured":
        status = "200 OK"
        response = "Secured URI"
        
    else:
        status = "404 Not Found"
        response = status
        
    log.info("Application is setting [%s] response..." % status)
    start_response(status,
                   [('Content-type', 'text/plain'),
                    ('Content-length', str(len(response)))])
        
    return [response]


class AuthenticationHandlerMiddleware(object):
    """Handler for HTTP 401 Unauthorized responses"""

    TRIGGER_HTTP_STATUS_CODE = "401 Unauthorized"
    
    def __init__(self, global_conf, **app_conf):
        pass
    
    def __call__(self, environ, start_response):
        log.info("AuthenticationHandlerMiddleware access denied response ...")
        response = "HTTP 401 Unauthorised response intercepted"
        start_response('200 OK', [('Content-type', 'text/plain'),
                                  ('Content-length', str(len(response)))])
        return [response]
       
    @classmethod
    def trigger(cls, environ, status, headers):
        if status == cls.TRIGGER_HTTP_STATUS_CODE:
            log.info("Authentication Trigger caught status [%s]", 
                     cls.TRIGGER_HTTP_STATUS_CODE)
            return True
        else:
            return False


class AuthorisationHandlerMiddleware(object):
    """Handler for HTTP 403 Forbidden responses"""
    
    TRIGGER_HTTP_STATUS_CODE = "403 Forbidden"
    
    def __init__(self, global_conf, **app_conf):
        pass
    
    def __call__(self, environ, start_response):
        log.info("AuthorisationHandlerMiddleware access denied response ...")
        response = "HTTP 403 Forbidden response intercepted"
        start_response('200 OK', [('Content-type', 'text/plain'),
                                  ('Content-length', str(len(response)))])
        return [response]
       
    @classmethod
    def trigger(cls, environ, status, headers):
        if status == cls.TRIGGER_HTTP_STATUS_CODE:
            log.info("Authorisation Trigger caught status [%s]", 
                     cls.TRIGGER_HTTP_STATUS_CODE)
            return True
        else:
            return False


class AuthorisationPolicyMiddleware(object):
    """Apply a security policy based on the URI requested"""
    
    def __init__(self, app):
        self.securedURIs = ['/test_secured']
        self.app = app
    
    def __call__(self, environ, start_response):
        if environ['PATH_INFO'] in self.securedURIs:
            log.info("Path [%s] is restricted by the Authorisation policy" %
                     environ['PATH_INFO'])
            status = "403 Forbidden"
            response = status
            start_response(status, [('Content-type', 'text/plain'),
                                    ('Content-length', str(len(response)))])
            return [response]
        else:
            return self.app(environ, start_response)
        
        
if __name__ == "__main__":
    app = AuthorisationPolicyMiddleware(myApp)
    
    app = MultiHandler(app)    
    app.add_method("checkerID", AuthenticationHandlerMiddleware)
    app.add_checker("checkerID", AuthenticationHandlerMiddleware.trigger)

    app = MultiHandler(app)
    app.add_method("checkerID", AuthorisationHandlerMiddleware)
    app.add_checker("checkerID", AuthorisationHandlerMiddleware.trigger)

    from paste.httpserver import serve
    from paste.deploy import loadapp

    serve(app, host='0.0.0.0', port=9080)
    