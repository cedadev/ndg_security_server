from ndg.security.server.sso.sso.tests import *

class TestOpenidsigninController(TestController):

    def test_index(self):
        response = self.app.get(url_for(controller='openidsignin'))
        # Test response...
