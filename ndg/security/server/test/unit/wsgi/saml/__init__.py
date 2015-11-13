"""Test SAML Attribute Query Interface

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import os
import paste.fixture
from paste.deploy import loadapp

from ndg.security.server.test.base import BaseTestCase


class TestApp(object):
    """Dummy application to terminate middleware stack containing SAML service
    """
    def __init__(self, global_conf, **app_conf):
        pass
    
    def __call__(self, environ, start_response):
        response = "404 Not Found"
        start_response(response,
                       [('Content-length', str(len(response))),
                        ('Content-type', 'text/plain')])
                            
        return [response]


class SoapSamlInterfaceMiddlewareTestCase(BaseTestCase):
    HERE_DIR = os.path.dirname(os.path.abspath(__file__))
    CONFIG_FILENAME = 'test.ini'
    
    def __init__(self, *args, **kwargs):
        wsgiapp = loadapp('config:%s' % self.__class__.CONFIG_FILENAME, 
                          relative_to=self.__class__.HERE_DIR)
        
        self.app = paste.fixture.TestApp(wsgiapp)
         
        BaseTestCase.__init__(self, *args, **kwargs)