#!/usr/bin/env python

"""Distribution Utilities setup program for NDG SOAP Package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "01/07/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

import os, sys

# Packages needed for NDG Security
# Note commented out ones fail with PyPI - use explicit link instead
# TODO: subdivide these into server and client specific and comon dependencies
_pkgDependencies = [
    ]

_longDescription = """\
A simple SOAP interface developed to support the ndg_saml package SOAP binding
code.

It uses ElementTree for its XML handling and urllib2 for its HTTP library.
"""

setup(
    name =           		'ndg_soap',
    version =        		'0.1',
    description =           'NERC DataGrid Simple SOAP library',
    long_description =		_longDescription,
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    license =               'BSD - See LICENCE file for details',
    install_requires =		_pkgDependencies,
    extras_require = {
        'zsi_middleware':  ["ZSI"],
    },
    packages =       		find_packages(),
    namespace_packages =	['ndg'],
    entry_points =         None,
    test_suite =		   'ndg.soap.test',
    zip_safe =             False
)
