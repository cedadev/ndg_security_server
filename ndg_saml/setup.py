#!/usr/bin/env python
"""SAML 2.0 Package

NERC DataGrid Project

This implementation is adapted from the Java OpenSAML implementation.  The 
copyright and licence information are included here:

Copyright [2005] [University Corporation for Advanced Internet Development, 
Inc.]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
__author__ = "P J Kershaw"
__date__ = "10/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

# Bootstrap setuptools if necessary.
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages
   
_longDescription = """\
SAML 2.0 implementation for use with the Earth System Grid Federation Attribute 
and Authorisation Query interfaces.  The implementation is based on the Java 
OpenSAML libraries.  An implementation is provided with ElementTree but it can 
easily be extended to use other Python XML parsers.

0.7.0 - add command line script for making attribute and authorisation decision
        query client calls.
        
0.6.0 - added support for SAML 2.0 profile of XACML v2.0 (http://docs.oasis-open.org/xacml/2.0/access_control-xacml-2.0-saml-profile-spec-os.pdf),
        specifically the SAML request extensions: XACMLAuthzDecisionQuery and 
        XACMLAuthzDecisionStatement.  This an alternative to the SAML defined
        AuthzDecisionQuery.  It enables a richer functionality for expressing
        queries and authorisation decisions taking advantage of the full
        capabilities of a XACML PDP.
      - fixed bug in SAML SOAP binding code: RequestBaseSOAPBinding and derived 
        classes to act as a query factory, instead of container, for thread 
        safety.
        
        Thanks to Richard Wilkinson for these contributions.
        
0.5.5 - allow passing a client certificate chain in client HTTPS requests

0.5.4 - fix for ndg.saml.saml2.binding.soap.server.wsgi.queryinterface.SOAPQueryInterfaceMiddleware:
bug in issuerFormat property setter - setting issuerName value

0.5.3 - fix for ndg.soap.utils.etree.prettyPrint for undeclared Nss.

0.5.2 - fix for applying clock skew property in queryinterface WSGI middleware,
and various minor fixes for classfactory module and m2crytpo utilities.

0.5.1 - fix for date time parsing where no seconds fraction is present, fixed
error message for InResponseTo ID check for Subject Query.

0.5 - adds WSGI middleware and clients for SAML SOAP binding and assertion
query/request profile.

It is not a complete implementation of SAML 2.0.  Only those components required
for the NERC DataGrid have been provided (Attribute and AuthZ Decision Query/
Response).  Where possible, stubs have been provided for other classes.
"""

setup(
    name =           		'ndg_saml',
    version =        		'0.7.0',
    description =    		('SAML 2.0 implementation for the NERC DataGrid '
                             'based on the Java OpenSAML library'),
    long_description =		_longDescription,
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/Security/SAML2.0',
    license =               'http://www.apache.org/licenses/LICENSE-2.0',
    packages =			    find_packages(),
    namespace_packages =	['ndg'],
    extras_require = {
        # These additional packages are needed if you wish to use the SOAP 
        # binding
        'soap_binding':  ["M2Crypto", "PyOpenSSL", "Paste", "PasteDeploy", 
                          "PasteScript"],
        # Required for the SAML profile to XACML - enables richer functionality
        # for expressing authorisation queries and decisions.
        'xacml_profile': ['ndg_xacml'],
    },
    entry_points = {
    'console_scripts': [
        'ndg_saml_client = ndg.saml.utils.command_line_client:SamlSoapCommandLineClient.main',
        ],
    },
    include_package_data =  True,
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
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
    zip_safe =              False
)
