#!/usr/bin/env python
"""Distribution Utilities setup program for NDG Security Package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/04/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:setup.py 4746 2009-01-06 08:25:37Z pjkersha $'

# Bootstrap setuptools if necessary.
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

import os

_longDescription = """\
NDG Security is the security system for the UK Natural Environment Research
Council funded NERC DataGrid.  NDG Security has been developed to 
provide users with seamless federated access to secured resources across NDG 
participating organisations whilst at the same time providing an underlying 
system which is easy to deploy around organisation's pre-existing systems. 

Over the past two years the system has been developed in collaboration with the 
US DoE funded Earth System Grid project for the ESG Federation an infrastructure
under development in support of CMIP5 (Coupled Model Intercomparison Project 
Phase 5), a framework for a co-ordinated set of climate model experiments 
which will input into the forthcoming 5th IPCC Assessment Report.

NDG and ESG use a common access control architecture.  OpenID and MyProxy are 
used to support single sign on for browser based and HTTP rich client based 
applications respectively.  SAML is used for attribute query and authorisation
decision interfaces.  XACML is used as the policy engine.  NDG Security has been
re-engineered to use a filter based architecture based on WSGI enabling other 
Python WSGI based applications to be protected in a flexible manner without the 
need to modify application code.
"""
setup(
    name =            		'ndg_security',
    version =         		'2.3.0',
    description =     		'NERC DataGrid Security Utilities',
    long_description = 		_longDescription,
    author =          		'Philip Kershaw',
    author_email =    		'Philip.Kershaw@stfc.ac.uk',
    maintainer =          	'Philip Kershaw',
    maintainer_email =    	'Philip.Kershaw@stfc.ac.uk',
    url =             	    'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    install_requires =      ['ndg_security_client', 'ndg_security_server'],
    dependency_links =      ["http://ndg.nerc.ac.uk/dist"],
    zip_safe = False
)
