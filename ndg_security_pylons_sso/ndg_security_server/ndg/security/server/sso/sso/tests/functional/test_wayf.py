from ndg.security.server.sso.sso.tests import *

class TestWayfController(TestController):

    def test_index(self):
        response = self.app.get(url_for(controller='wayf'))
        # Test response...
