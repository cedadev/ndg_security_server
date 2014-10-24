#!/usr/bin/env python
"""Distribution Utilities setup program for ESG PyDAP Client Package

"""
__author__ = "P J Kershaw"
__date__ = "12/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - See LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

import os

setup(
    name =            	'EsgPyDapClient',
    version =         	'0.1.0',
    description =     	'ESG Secured PyDAP Client',
    long_description = 	'''Extended PyDAP client to support authentication 
system devised for Earth System Grid DAP services.  Unauthenticated client
requests are redirected to SSL authentication endpoint for SSL client based
authentication.  On successful authentication, the client is redirected back to
the DAP service for the data access request to proceed.  A session cookie is
used to set the authenticated state for subsequent requests.
    ''',
    author =          	'Philip Kershaw',
    author_email =    	'Philip.Kershaw@stfc.ac.uk',
    maintainer =        'Philip Kershaw',
    maintainer_email =  'Philip.Kershaw@stfc.ac.uk',
    url =             	'',
    platforms =         ['POSIX', 'Linux', 'Windows'],
    install_requires =  ['PyDAP', 'M2Crypto'],
    license =           __license__,
    test_suite =        'esg.pydap.test',
    packages =          find_packages(),
    package_data =      {
        'esg.pydap.test': ['*.ini']
    },
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU Library or Lesser General Public License (BSD)',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    zip_safe = False
)
