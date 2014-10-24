#!/usr/bin/env python
"""Distribution Utilities setup program for MyProxy Client Package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "12/12/08"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = """BSD - See LICENSE file in top-level directory

Software adapted from myproxy_logon.  - For myproxy_logon see Access Grid 
Toolkit Public License (AGTPL)

This product includes software developed by and/or derived from the Access 
Grid Project (http://www.accessgrid.org) to which the U.S. Government retains 
certain rights."""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

# Bootstrap setuptools if necessary.
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

setup(
    name =            	'MyProxyClient',
    version =         	'1.3.1',
    description =     	'MyProxy Client',
    long_description = 	'''\
MyProxy Client Package
======================
This a pure* Python implementation of a client to the MyProxy Credential
Management Server (http://grid.ncsa.uiuc.edu/myproxy/)

* i.e. MyProxy C client libraries are not required for this package. 

It uses pyOpenSSL to make an SSL connection to the server following the
messaging interface as outlined in: http://grid.ncsa.uiuc.edu/myproxy/protocol/

The code is based on an original program myproxy_logon by Tom Uram of ANL.

Releases
========
1.3.1
-----
 * Fix to MyProxyClient.writeProxyFile and MyProxyClient.readProxyFile to correctly pick-up overridden file setting.  Thanks to Nicolas Carenton, IPSL.

Tests
=====
Unit test module with test files is in test/.  See the README in that directory.
This package has been tested on Linux Ubuntu Gutsy Gibbon, and Windows XP
Professional SP2

Documentation
=============
Epydoc generated documentation is available in documentation/.  run the 
Makefile to regenerate if required.

Thanks
======
 * to OMII-UK for funding development of NDG Security (2007-2008)
 * Tom Uram who wrote the myproxy_logon program on which this package is based.
''',
    author =          	'Philip Kershaw',
    author_email =    	'Philip.Kershaw@stfc.ac.uk',
    maintainer =        'Philip Kershaw',
    maintainer_email =  'Philip.Kershaw@stfc.ac.uk',
    url =             	'http://proj.badc.rl.ac.uk/ndg/wiki/Security/MyProxyClient',
    platforms =         ['POSIX', 'Linux', 'Windows'],
    install_requires =  ['PyOpenSSL'],
    license =           __license__,
    test_suite =        'myproxy.test',
    packages =          find_packages(),
    package_data =      {
        'myproxy.test': ['*.cfg', '*.conf', '*.crt', '*.key', 'README']
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
    zip_safe = False,
    entry_points = {
        'console_scripts': ['myproxyclient = myproxy.script:main',
                            ],
        }
)
