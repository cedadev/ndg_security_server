#!/usr/bin/env python
"""Distribution Utilities setup program for NDG Security Server Package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/04/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()

from setuptools import setup, find_packages

import os

# Other packages needed by this server package
_pkgDependencies = [
    'ndg_security_common',
    'Paste',
    'AuthKit',
    'MyProxyClient'
]

_entryPoints = """
    [console_scripts] 
    myproxy-saml-assertion-cert-ext-app=ndg.security.server.myproxy.certificate_extapp.saml_attribute_assertion:CertExtConsoleApp.run

    [paste.app_factory]
    main=ndg.security.server.pylons.container.config.middleware:make_app
    [paste.app_install]
    main=pylons.util:PylonsInstaller
    [paste.paster_create_template]
    ndgsecurity_services=ndg.security.server.paster_templates.template:DefaultDeploymentTemplate
    ndgsecurity_services_with_sso=ndg.security.server.paster_templates.template:FullDeploymentTemplate
    """
   
_longDescription = """\
NDG Security is the security system for the UK Natural Environment Research
Council funded NERC DataGrid.  NDG Security has been developed to 
provide users with seamless access to secured resources across NDG 
participating organisations whilst at the same time providing an underlying 
system which is easy to deploy around organisation's pre-existing systems. 
NDG Security is designed around a Role Based Access Control mechanism. Cross 
organisational access to resources is enabled through bilateral trust 
agreements between participating organisations expressed through a system for 
single sign and role mapping.

NDG Security employs a web services based architecture enabling different 
combinations of components to be deployed according to a participating site's 
needs and requirements.  Resources are secured using a system of Policy
Enforcement Point (Gatekeeper) and Policy Decision Point components.  An 
Attribute Authority provides a service to query a given users attributes used
for gaining access to resources.  Session Manager and MyProxy services can be 
used for management of credentials.  NDG Security supports OpenID for Single
Sign On and can integrate into both web based and non-web based application 
client interfaces.
"""

setup(
    name =           		'ndg_security_server',
    version =        		'1.4',
    description =    		'Server side components for running NERC DataGrid '
                            'Security Services',
    long_description =		_longDescription,
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    license =               'BSD - See LICENCE file for details',
    install_requires =		_pkgDependencies,
   
    # Set ndg.security.common dependency
    dependency_links =      ["http://ndg.nerc.ac.uk/dist"],
    packages =			    find_packages(),
    namespace_packages =	['ndg', 'ndg.security'],
    include_package_data =  True,
    package_data = {
        'ndg.security.server.sso.sso': [
            'i18n/*/LC_MESSAGES/*.mo'
        ],
        'ndg.security.server.conf': [
            '*.xml', '*.py', '*.cfg', '*.conf'
        ],
        'ndg.security.server.share': ['*'],
        'ndg.security.server.sso': ['*.ini', '*.cfg', '*.txt'],
        'ndg.security.server.sso.sso': ['public/*.*', 'public/layout/*.*'],
        'ndg.security.server.sso.sso.badc_site': [
            'public/*.*', 
            'public/layout/*.*',
            'public/layout/logos/*.*',
            'public/layout/styles/*.*',
            'public/layout/tabs/*.*'
        ],
        'ndg.security.server.sso.sso.templates.ndg.security': ['*.kid'],
        'ndg.security.server.sso.sso.badc_site.templates.ndg.security': ['*.kid'],
        'ndg.security.server.pylons': ['*.ini', '*.cfg', '*.txt'],
        'ndg.security.server.pylons.container': [
            'public/*.*', 
            'public/layout/*.*',
            'public/js/*.*',
            'public/js/img/*.*',
            'public/js/theme/*.*',
            'public/js/yui/*.*'],
        'ndg.security.server.pylons.container.templates.ndg.security': [
            '*.kid'
        ],
        # See MANIFEST.in for ndg.security.server.paster_templates files
    },
    entry_points =           _entryPoints,
    test_suite =		    'ndg.security.test',
    zip_safe =              False
)
