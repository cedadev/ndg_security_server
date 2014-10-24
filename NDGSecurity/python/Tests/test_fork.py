import unittest

from ndg.security.test.unit.base import BaseTestCase


class TestCase(BaseTestCase):
    def __init__(self, *arg, **kw):
        super(TestCase, self).__init__(*arg, **kw)
        
        # Run
        self.startSiteAAttributeAuthority()
        
    def test01(self):
        pass
    
    
if __name__ == '__main__':
    unittest.main()
