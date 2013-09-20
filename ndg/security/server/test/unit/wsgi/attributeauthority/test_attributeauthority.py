"""WSGI Middleware to set an Attribute Authority instance in tyhe WSGI environ

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "19/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)
import os
import unittest

import paste.fixture
from paste.deploy import loadapp

from ndg.security.server.wsgi.attributeauthority import \
    AttributeAuthorityMiddleware

class TestAttributeAuthorityApp(object):
    '''Test harness for Attribute Authority'''
    response = "Attribute Authority environ key: environ['%s']=%r"
       
    def __init__(self, app_conf, **local_conf):
        pass
    
    def __call__(self, environ, start_response):
        assert('myAttributeAuthority' in environ)
        
        response = TestAttributeAuthorityApp.response %('myAttributeAuthority',
                                            environ['myAttributeAuthority'])
        strReponseLen = str(len(response))
        start_response("200 OK",
                       [('Content-length', strReponseLen),
                        ('Content-type', 'text/plain')])
        return [response]


class AttributeAuthorityMiddlewareTestCase(unittest.TestCase):

    def test01CheckForEnvironKey(self):
        here_dir = os.path.dirname(os.path.abspath(__file__))
        app = loadapp('config:test.ini', relative_to=here_dir)
        self.app = paste.fixture.TestApp(app)
        
        response = self.app.get('/')
        self.assert_(response) 
        print(response)      
        
if __name__ == "__main__":
    unittest.main()