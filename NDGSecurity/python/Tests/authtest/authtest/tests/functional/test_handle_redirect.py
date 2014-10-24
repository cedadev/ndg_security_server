from authtest.tests import *

class TestHandleRedirectController(TestController):

    def test_index(self):
        response = self.app.get(url_for(controller='handle_redirect'))
        # Test response...
