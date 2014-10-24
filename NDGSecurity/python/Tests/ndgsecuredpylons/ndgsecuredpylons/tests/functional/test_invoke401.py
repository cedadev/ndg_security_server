from ndgsecuredpylons.tests import *

class TestInvoke401Controller(TestController):

    def test_index(self):
        response = self.app.get(url_for(controller='invoke401'))
        # Test response...
