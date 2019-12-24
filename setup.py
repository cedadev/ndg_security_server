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

    [paste.composite_factory]
    cascade_ = ndg.security.server.utils.paste_port:make_cascade
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
    version =        		'2.7.3',
    description =    		'Server side components for running NERC DataGrid '
                                'Security Services',
    long_description =      LONG_DESCR,
    author =                'Philip Kershaw',
    author_email =          'Philip.Kershaw@stfc.ac.uk',
    maintainer =            'Philip Kershaw',
    maintainer_email =      'Philip.Kershaw@stfc.ac.uk',
    url =                   'http://github.com/cedadev/ndg_security_server',
    license =               'BSD - See LICENCE file for details',
    install_requires = [
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
        'openid-services': ['Genshi>=0.6'],
        'openid-relyingparty': ['ndg_httpsclient'],
        'ceda-site-services': ['crypto-cookie']
    },
    # Set ndg.security.common dependency
    dependency_links = ["http://dist.ceda.ac.uk/pip/"],
    packages = find_packages(),
    package_data={
        'ndg.security.server.paster_templates': [
            'attributeservice/*.py',
            'attributeservice/pki/localhost.*',
            'attributeservice/pki/ca/*.0',
            'attributeservice/public/index.html',
            'attributeservice/public/AttributeAuthority/index.html',
            'attributeservice/*_tmpl',
            'attributeservice/user.db',
            'authorisationservice/*.py',
            'authorisationservice/pki/localhost.*',
            'authorisationservice/pki/ca/*.0',
            'authorisationservice/*_tmpl',
            'authorisationservice/public/index.html',
            'openidprovider/*.py',
            'openidprovider/pki/localhost.*',
            'openidprovider/pki/ca/*.0',
            'openidprovider/*_tmpl',
            'openidprovider/public/*/*.*',
            'openidprovider/public/*/*/*.*',
            'openidprovider/templates/*.html',
            'openidprovider/templates/*_tmpl',
            'openidprovider/user.db',
            'securedapp/openidrelyingparty/pki/ca/*.0',
            'securedapp/openidrelyingparty/pki/localhost.*',
            'securedapp/openidrelyingparty/public/static/css/*',
            'securedapp/openidrelyingparty/public/static/img/*',
            'securedapp/openidrelyingparty/public/static/js/*',
            'securedapp/openidrelyingparty/public/static/mf54/*.*',
            'securedapp/openidrelyingparty/public/static/mf54/css/*',
            'securedapp/openidrelyingparty/public/static/mf54/img/*',
            'securedapp/openidrelyingparty/*_tmpl',
            'securedapp/openidrelyingparty/*.py',
            'securedapp/openidrelyingparty/*.xml',
            'securedapp/openidrelyingparty/*.cfg',
            'securedapp/openidrelyingparty/templates/*.html',
            'securedapp/pep_result_handler/layout/*.*',
            'securedapp/pep_result_handler/layout/icons/*',
            'securedapp/pki/localhost.*',
            'securedapp/pki/ca/*.0',
            'securedapp/public/*.*',
            'securedapp/public/js/*',
            'securedapp/public/layout/*.*',
            'securedapp/public/layout/icons/*.*',
            'securedapp/*_tmpl',
            'securedapp/*.py'
        ],
        'ndg.security.server.wsgi.authz.result_handler.genshi': [
            'templates/*.*',
            'layout/*.*',
            'layout/icons/*.*',
        ],
        'ndg.security.server.wsgi.openid.provider.renderinginterface.genshi': [
            'templates/*.*',
            'layout/*.*',
            'layout/icons/*.*',
            'js/*.*',
        ],
        'ndg.security.server.wsgi.openid.relyingparty.signin_interface.genshi': [
            'templates/*.*',
            'public/layout/*.*',
            'public/layout/icons/*.*',
            'public/js/*.*',
        ],
    },
    entry_points =              _ENTRY_POINTS,
    test_suite =		'ndg.security.server.test',
    zip_safe =                  False
)
