from authtest.tests import *

class TestTest2Controller(TestController):

    def test_index(self):
        response = self.app.get(url_for(controller='test2'))
        # Test response...
