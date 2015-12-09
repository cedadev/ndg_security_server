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
import os

# Bootstrap setuptools if necessary.
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup

_ENTRY_POINTS = """
    [console_scripts] 
    myproxy-saml-assertion-cert-ext-app=ndg.security.server.myproxy.certificate_extapp.saml_attribute_assertion:CertExtConsoleApp.run

    [paste.app_factory]
    main=ndg.security.server.pylons.container.config.middleware:make_app
    
    [paste.app_install]
    main=pylons.util:PylonsInstaller
    [paste.paster_create_template]
    ndgsecurity_securedapp=ndg.security.server.paster_templates.template:ServiceProviderTemplate
    ndgsecurity_services=ndg.security.server.paster_templates.template:ServicesTemplate
    ndgsecurity_attribute_service=ndg.security.server.paster_templates.template:AttributeServiceTemplate
    ndgsecurity_authorisation_service=ndg.security.server.paster_templates.template:AuthorisationServiceTemplate
    ndgsecurity_openidprovider=ndg.security.server.paster_templates.template:OpenIDProviderTemplate
"""

# Read succeeds for sdist creation but fails for build with pip install.  Added
# catch here for latter case.
THIS_DIR = os.path.dirname(__file__)
try:
    LONG_DESCR = open(os.path.join(THIS_DIR, 'README.rst')).read()
except IOError:
    LONG_DESCR = """\
NDG Security Server-side components package
===========================================

NDG Security is the security system for the UK Natural Environment Research
Council funded NERC DataGrid.  NDG Security has been developed to 
provide users with seamless federated access to secured resources across NDG 
participating organisations whilst at the same time providing an underlying 
system which is easy to deploy around organisation's pre-existing systems. 

More recently, the system has been developed in collaboration with the 
US DoE funded Earth System Grid project for the ESG Federation an infrastructure
under development in support of CMIP5 (Coupled Model Intercomparison Project 
Phase 5), a framework for a co-ordinated set of climate model experiments 
which will input into the forthcoming 5th IPCC Assessment Report.

NDG and ESG use a common access control architecture.  OpenID and MyProxy are 
used to support single sign on for browser based and HTTP rich client based 
applications respectively.  SAML is used for attribute query and authorisation
decision interfaces.  NDG Security uses a XACML based policy engine from the 
package ndg_xacml.  NDG Security has been re-engineered to use a filter based 
architecture based on WSGI enabling other Python WSGI based applications to be 
protected in a flexible manner without the need to modify application code. 
"""

setup(
    name =           		'ndg_security_server',
    version =        		'2.6.0',
    description =    		'Server side components for running NERC DataGrid '
                                'Security Services',
    long_description =		LONG_DESCR,
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'http://github.com/cedadev/ndg_security_server',
    license =                   'BSD - See LICENCE file for details',
    install_requires =		[
        'ndg_security_common',
        'Paste',
        'WebOb',
        'beaker',
        'AuthKit',
        'SQLAlchemy'
    ],
    extras_require = {
        'xacml':  ["ndg_xacml"],
        'myproxy-saml-assertion-cert-ext-app': ['MyProxyClient'],
        'integration-tests': ['pyOpenSSL'],
        'openid-services': ['Genshi==0.6'],
        'ceda-site-services': ['crypto-cookie']
    },
    # Set ndg.security.common dependency
    dependency_links =          ["http://dist.ceda.ac.uk/pip/"],
    packages =			find_packages(),
    namespace_packages =	['ndg', 'ndg.security'],
    package_data={
        'ndg.security.server': [
            'paster_templates/attributeservice/*.py',
            'paster_templates/attributeservice/pki/localhost.*',
            'paster_templates/attributeservice/pki/ca/*.0',
            'paster_templates/attributeservice/public/index.html',
            'paster_templates/attributeservice/public/AttributeAuthority/index.html',
            'paster_templates/attributeservice/*_tmpl',
            'paster_templates/attributeservice/user.db',
            'paster_templates/authorisationservice/*.py',
            'paster_templates/authorisationservice/pki/localhost.*',
            'paster_templates/authorisationservice/pki/ca/*.0',
            'paster_templates/authorisationservice/*_tmpl',
            'paster_templates/authorisationservice/public/index.html',
            'paster_templates/openidprovider/*.py',
            'paster_templates/openidprovider/log/',
            'paster_templates/openidprovider/pki/localhost.*',
            'paster_templates/openidprovider/pki/ca/*.0',
            'paster_templates/openidprovider/*_tmpl',
            'paster_templates/openidprovider/public/*/*.*',
            'paster_templates/openidprovider/public/*/*/*.*',
            'paster_templates/openidprovider/templates/*.html',
            'paster_templates/openidprovider/templates/*_tmpl',
            'paster_templates/openidprovider/user.db',
            'paster_templates/securedapp/openidrelyingparty/pki/ca/*.0',
            'paster_templates/securedapp/openidrelyingparty/pki/localhost.*',
            'paster_templates/securedapp/openidrelyingparty/public/static/css/*',
            'paster_templates/securedapp/openidrelyingparty/public/static/img/*',
            'paster_templates/securedapp/openidrelyingparty/public/static/js/*',
            'paster_templates/securedapp/openidrelyingparty/public/static/mf54/*.*',
            'paster_templates/securedapp/openidrelyingparty/public/static/mf54/css/*',
            'paster_templates/securedapp/openidrelyingparty/public/static/mf54/img/*',
            'paster_templates/securedapp/openidrelyingparty/*_tmpl',
            'paster_templates/securedapp/openidrelyingparty/*.py',
            'paster_templates/securedapp/openidrelyingparty/*.xml',
            'paster_templates/securedapp/openidrelyingparty/*.cfg',
            'paster_templates/securedapp/openidrelyingparty/templates/*.html',
            'paster_templates/securedapp/pep_result_handler/layout/*.*',
            'paster_templates/securedapp/pep_result_handler/layout/icons/*',
            'paster_templates/securedapp/pki/localhost.*',
            'paster_templates/securedapp/pki/ca/*.0',
            'paster_templates/securedapp/public/*.*',
            'paster_templates/securedapp/public/js/*',
            'paster_templates/securedapp/public/layout/*.*',
            'paster_templates/securedapp/public/layout/icons/*.*',
            'paster_templates/securedapp/*_tmpl',
            'paster_templates/securedapp/*.py'
        ]
    },
    entry_points =              _ENTRY_POINTS,
    test_suite =		'ndg.security.server.test',
    zip_safe =                  False
)
