from authtest.tests import *

class TestMytestController(TestController):

    def test_index(self):
        response = self.app.get(url_for(controller='mytest'))
        # Test response...
