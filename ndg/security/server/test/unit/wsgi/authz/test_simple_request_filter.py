#!/usr/bin/env python
"""Unit tests for WSGI Authorization handler

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "12/12/14"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
import unittest

from ndg.security.server.wsgi.authz.pep import SamlPepFilter


class SimpleRequestFilterTestCase(unittest.TestCase):
    '''Validate file ignore filtering functionality for SAML-based Policy 
    Enforcement Point authorisation WSGI filter.  The file ignore setting
    allows files to be ignored from the usual authorisation process.  This is
    convenient for web content and styling files which don't need to be
    governed by a formal authorisation policy'''

    def setUp(self):
        self.policy_enforcement_point = SamlPepFilter(None)
        self.policy_enforcement_point.ignore_file_list_pat = [
            'http://localhost/static/.*',
            'http://localhost/css/.*',
            'http://localhost/.*\.js$'
            ]

    def test01_ignore_list(self):

        resource_uri_ignore_list = [
            'http://localhost/css/style.css',
            'http://localhost/static/logo.png',
            'http://localhost/combo.js'
        ]
            
        for resource_uri in resource_uri_ignore_list:
            self.assertFalse(
                self.policy_enforcement_point.isApplicableRequest(resource_uri),
                'Expecting False result for %r' % resource_uri)

    def test02_apply_list(self):

        resource_uri_apply_list = [
            'http://localhost/style.css',
            'http://localhost/img/logo.png',
            'http://localhost/combo.jpg'
        ]
            
        for resource_uri in resource_uri_apply_list:
            self.assertTrue(
                self.policy_enforcement_point.isApplicableRequest(resource_uri),
                'Expecting True result for %r' % resource_uri)

if __name__ == "__main__":
    unittest.main()