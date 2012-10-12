'''
Created on Oct 12, 2012

@author: philipkershaw
'''
from paste.httpexceptions import HTTPUnauthorized


class AuthenticationFuncMiddleware(object):
    AUTH_FUNC_ENVIRON_KEYNAME_OPTNAME = 'auth_func_environ_keyname'
    CREDENTIALS_OPTNAME = 'credentials'
    def __init__(self, app):
        self._app = app
        self.auth_func_environ_keyname = None
        self.credentials = {}
        
    @classmethod
    def filter_app_factory(cls, app, global_conf, prefix='', **app_conf):
        obj = cls(app)
        obj.auth_func_environ_keyname = app_conf[prefix + \
                                        cls.AUTH_FUNC_ENVIRON_KEYNAME_OPTNAME]
        
        credentials = app_conf[prefix + cls.CREDENTIALS_OPTNAME]
        for i in credentials.split(','):
            username, passwd = i.strip().split(':')
            obj.credentials[username] = passwd
        
        return obj
    
    def __call__(self, environ, start_response):
        def auth_func(environ, start_response, username, password):
            if self.credentials.get(username) == password:
                environ['REMOTE_USER'] = username
            else:
                raise HTTPUnauthorized()
            
        environ[self.auth_func_environ_keyname] = auth_func
        return self._app(environ, start_response)
