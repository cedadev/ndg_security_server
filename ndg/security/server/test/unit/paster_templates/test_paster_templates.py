#!/usr/bin/env python
"""Unit tests for NDG Security paster templates

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "18/11/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

import unittest
from os import path, listdir, environ
import shutil
from paste.script.create_distro import CreateDistroCommand

_HERE_DIR = path.dirname(path.abspath(__file__))
_NDGSEC_UNITTEST_KEEP_PASTER_CONF_DIRS = environ.get(
    'NDGSEC_UNITTEST_KEEP_PASTER_CONF_DIRS')


class ServiceProviderTemplateTestCase(unittest.TestCase):
    """Test create configuration for an application secured with NDG Security
    filters
    """
    HERE_DIR = _HERE_DIR
    SERVICE_TMPL_NAME = 'ndgsecurity_securedapp'
    SERVICE_CONF_DIR = 'securedapp'
    SERVICE_CONF_DIRPATH = path.join(HERE_DIR, SERVICE_CONF_DIR)
    SERVICE_CONF_DIR_FILES = (
        'pki', 'request-filter.xml', 'service.ini', 'pep_result_handler',
        'securedapp.py'
    )

    def test01Run(self):
        log.debug("_"*80)
        log.debug("Creating Secured application template ...")
        log.debug("_"*80)
        cmd = CreateDistroCommand(None)
        cmd.default_interactive = False
        cmd.run([self.__class__.SERVICE_CONF_DIR,
                 '-t',
                 self.__class__.SERVICE_TMPL_NAME,
                 '-o',
                 self.__class__.HERE_DIR])

        createdFiles = listdir(self.__class__.SERVICE_CONF_DIRPATH)

        for _file in self.__class__.SERVICE_CONF_DIR_FILES:
            self.assert_(_file in createdFiles, "Missing file %r" % _file)

    def tearDown(self):
        if _NDGSEC_UNITTEST_KEEP_PASTER_CONF_DIRS:
            return

        shutil.rmtree(self.__class__.SERVICE_CONF_DIRPATH, True)


class AttributeServiceTemplateTestCase(unittest.TestCase):
    """Test creation of ini file and basic configuration settings for NDG
    Security Attribute Service
    """
    HERE_DIR = _HERE_DIR
    ATTRIBUTE_SERVICE_TMPL_NAME = 'ndgsecurity_attribute_service'
    ATTRIBUTE_SERVICE_CONF_DIR = 'attribute-service'
    ATTRIBUTE_SERVICE_CONF_DIRPATH = path.join(HERE_DIR,
                                               ATTRIBUTE_SERVICE_CONF_DIR)
    ATTRIBUTE_SERVICE_CONF_DIR_FILES = (
        'pki', 'attribute-service.ini', 'user.db'
    )

    def test01Run(self):
        log.debug("_"*80)
        log.debug("Creating Attribute Service template ...")
        log.debug("_"*80)
        cmd = CreateDistroCommand(None)
        cmd.default_interactive = False
        cmd.run([self.__class__.ATTRIBUTE_SERVICE_CONF_DIR,
                 '-t',
                 self.__class__.ATTRIBUTE_SERVICE_TMPL_NAME,
                 '-o',
                 self.__class__.HERE_DIR])

        createdFiles = listdir(
                            self.__class__.ATTRIBUTE_SERVICE_CONF_DIRPATH)

        for _file in self.__class__.ATTRIBUTE_SERVICE_CONF_DIR_FILES:
            self.assert_(_file in createdFiles, "Missing file %r" % _file)

    def tearDown(self):
        if _NDGSEC_UNITTEST_KEEP_PASTER_CONF_DIRS:
            return

        shutil.rmtree(self.__class__.ATTRIBUTE_SERVICE_CONF_DIRPATH, True)


class AuthorisationServiceTemplateTestCase(unittest.TestCase):
    """Test creation of ini file and basic configuration settings for NDG
    Security Authorisation Service
    """
    HERE_DIR = _HERE_DIR
    AUTHORISATION_SERVICE_TMPL_NAME = 'ndgsecurity_authorisation_service'
    AUTHORISATION_SERVICE_CONF_DIR = 'authorisation-service'
    AUTHORISATION_SERVICE_CONF_DIRPATH = path.join(HERE_DIR,
                                                AUTHORISATION_SERVICE_CONF_DIR)
    AUTHORISATION_SERVICE_CONF_DIR_FILES = (
        'pki', 'pip-mapping.txt', 'authorisation-service.ini', 'policy.xml'
    )

    def test01Run(self):
        log.debug("_"*80)
        log.debug("Creating Authorisation Service template ...")
        log.debug("_"*80)
        cmd = CreateDistroCommand(None)
        cmd.default_interactive = False
        cmd.run([self.__class__.AUTHORISATION_SERVICE_CONF_DIR,
                 '-t',
                 self.__class__.AUTHORISATION_SERVICE_TMPL_NAME,
                 '-o',
                 self.__class__.HERE_DIR])

        createdFiles = listdir(
                            self.__class__.AUTHORISATION_SERVICE_CONF_DIRPATH)

        for _file in self.__class__.AUTHORISATION_SERVICE_CONF_DIR_FILES:
            self.assert_(_file in createdFiles, "Missing file %r" % _file)

    def tearDown(self):
        if _NDGSEC_UNITTEST_KEEP_PASTER_CONF_DIRS:
            return

        shutil.rmtree(self.__class__.AUTHORISATION_SERVICE_CONF_DIRPATH, True)


class OpenIdProviderTemplateTestCase(unittest.TestCase):
    """Test creation of ini file and basic configuration settings for NDG
    Security OpenID Provider Service
    """
    HERE_DIR = _HERE_DIR
    OP_SERVICE_TMPL_NAME = 'ndgsecurity_openidprovider'
    OP_SERVICE_CONF_DIR = 'openidprovider'
    OP_SERVICE_CONF_DIRPATH = path.join(HERE_DIR, OP_SERVICE_CONF_DIR)
    OP_SERVICE_CONF_DIR_FILES = (
        'pki', 'service.ini', 'user.db', 'templates', 'public'
    )

    def test01Run(self):
        log.debug("_"*80)
        log.debug("Creating OpenID Provider Service template ...")
        log.debug("_"*80)
        cmd = CreateDistroCommand(None)
        cmd.default_interactive = False
        cmd.run([self.__class__.OP_SERVICE_CONF_DIR,
                 '-t',
                 self.__class__.OP_SERVICE_TMPL_NAME,
                 '-o',
                 self.__class__.HERE_DIR])

        createdFiles = listdir(
                            self.__class__.OP_SERVICE_CONF_DIRPATH)

        for _file in self.__class__.OP_SERVICE_CONF_DIR_FILES:
            self.assert_(_file in createdFiles, "Missing file %r" % _file)

    def tearDown(self):
        if _NDGSEC_UNITTEST_KEEP_PASTER_CONF_DIRS:
            return

        shutil.rmtree(self.__class__.OP_SERVICE_CONF_DIRPATH, True)


if __name__ == "__main__":
    unittest.main()
