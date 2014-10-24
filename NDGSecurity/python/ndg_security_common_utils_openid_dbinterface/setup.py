#!/usr/bin/env python
"""Distribution Utilities setup program for OpenID Database Interface Package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "17/09/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
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
    name =           		'openid_dbinterface',
    version =        		'0.1.1',
    description =    		'NDG Security OpenID Database Interface Package',
    long_description = \
'''Contains utilities for creating OpenIDs based on existing user account
details in a Postgres database and also for querying for a the existing of 
a given user account
''',
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    license =               'BSD - See LICENCE file for details',
    packages =			    find_packages(),
    namespace_packages =	['ndg', 
                             'ndg.security', 
                             'ndg.security', 
                             'ndg.security.common',
                             'ndg.security.common.utils'],
    include_package_data =  True,
    entry_points = """
    [console_scripts] 
    openid_dbinterface=ndg.security.common.utils.openid.dbinterface:Main.run
    """,
    zip_safe =              False
)
