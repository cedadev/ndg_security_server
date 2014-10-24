from authtest.tests import *

class TestError2Controller(TestController):

    def test_index(self):
        response = self.app.get(url_for(controller='error2'))
        # Test response...
