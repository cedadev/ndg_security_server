from ndg.security.server.sso.sso.tests import *

class TestTest1Controller(TestController):

    def test_index(self):
        response = self.app.get(url_for(controller='test1'))
        # Test response...
