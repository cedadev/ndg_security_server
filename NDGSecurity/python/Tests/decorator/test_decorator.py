
def initCall(__call__):
    '''Decorator to __call__ to enable convenient attribute initialisation
    '''
    def __call__wrapper(self, environ, start_response):
        self._initCall(environ)
        return __call__(self, environ, start_response)

    return __call__wrapper

class TestDecoratorWSGI(object):
    
    def _initCall(self, environ):
        print "Initialising..."
        
    @initCall
    def __call__(self, environ, start_response):
        x = "__call__"
        return x

from ndg.security.server.wsgi import NDGSecurityMiddlewareBase

class TestNDGSecurityMiddleware(NDGSecurityMiddlewareBase):
    @NDGSecurityMiddlewareBase.initCall
    def __call__(self, environ, start_response):
        return self.environ
        
if __name__ == "__main__":
    t = TestDecoratorWSGI()
    print t.__call__(None, None)
    
    n = TestNDGSecurityMiddleware(None, {}, **{})
    print n({'PATH_INFO': '/here'}, None)