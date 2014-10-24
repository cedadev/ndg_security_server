from authtest.tests import *

class TestRedirectController(TestController):

    def test_index(self):
        response = self.app.get(url_for(controller='redirect'))
        # Test response...
