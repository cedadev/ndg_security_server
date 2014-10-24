from ndgsecurity.tests import *

class TestAttributeauthorityController(TestController):

    def test_index(self):
        response = self.app.get(url_for(controller='AttributeAuthority'))
        # Test response...
