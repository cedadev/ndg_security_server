'''
Created on May 13, 2011

@author: philipkershaw
'''
import unittest
import logging
logging.basicConfig(level=logging.DEBUG)

from beaker.middleware import SessionMiddleware
import paste.fixture
from ndg.security.test.unit.base import BaseTestCase
from ndg.security.server.wsgi.client_proxy.middleware import (NDGSecurityProxy,
                                        MyProxyProvisionedSessionMiddleware)


class SecurityProxyTestCase(BaseTestCase):
    '''Test Security HTTP(S) proxy'''

    def test01hardWired(self):
        app = NDGSecurityProxy('http://localhost:7080/test_securedURI')
        local_conf = {
            'myproxy_provision_session.myProxyClientSSLCertFile':
                self.__class__.SSL_CERT_FILEPATH,
            'myproxy_provision_session.myProxyClientSSLKeyFile':
                self.__class__.SSL_PRIKEY_FILEPATH,
            'myproxy_provision_session.caCertDir':
                self.__class__.CACERT_DIR
                      
        }
        app = MyProxyProvisionedSessionMiddleware(app)
        app.initialise({}, **local_conf)
        app = SessionMiddleware(app, environ_key='ndg.security.session')
        extra_environ = {
            'REMOTE_USER': BaseTestCase.OPENID_URI 
        }
        app = paste.fixture.TestApp(app, extra_environ=extra_environ)
        
        response = app.get('/')
        self.assert_(response)
        print(response)
    
#    def test02fromIniFile(self):
#        here_dir = os.path.dirname(os.path.abspath(__file__))
#        app = loadapp('config:test.ini', relative_to=here_dir)
#        self.app = paste.fixture.TestApp(app)
#        
#        response = self.app.get('/')
#        self.assert_(response) 
#        print(response)      


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()