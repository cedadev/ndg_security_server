"""NDG Security Paster template classes

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/10/2010"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import os
import socket
import base64
import string
from urlparse import urlunsplit, urlparse
from paste.script.templates import Template, var

try:
    # Get first alias from list if present
    _hostname = socket.getfqdn()
except Exception:
    # ... or default to hostname
    _hostname = 'localhost'
    
from ndg.saml.saml2.core import Issuer    


class DoublePercentTemplate(string.Template):
    """Alternative template uses '%%' instead of '$' to denote template
    variables.  This is used because some NDG Security templates contain
    '$' variables used for other purposes."""
    delimiter = "%%"
    
    
class TemplateBase(Template):
    """Base Paste Template class sets a custom renderer"""
    
    def template_renderer(self, content, vars_, filename=None):
        """Alternative renderer defined to enable use of '%%' prefix for template
        variables.  NDG Security ini files already use '$' for other variables
        
        @param content: template content
        @type content: string
        @param vars_: variables to substituted into the template
        @type vars_: dict
        @return: content with all variables substituted for
        @rtype: string
        """
        tmpl = DoublePercentTemplate(content)
        return tmpl.substitute(**vars_)

    def pre(self, command, output_dir, vars_):
        '''Extend to fix log file path setting in ini file
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars_: variables to be substituted into template
        @type vars_: dict
        '''  
        vars_['outputDir'] = os.path.abspath(output_dir)
        
        
"""@var _MYPROXY_SERVER_LOCALID_XRD_ENTRY_TMPL: Yadis XRDS entry for a MyProxy
server endpoint.  This entry also include a localID $user_url which the OpenID
Provider application code will fill out at runtime.
@type _MYPROXY_SERVER_LOCALID_XRD_ENTRY_TMPL: ndg.security.server.paster_templates.template.DoublePercentTemplate
"""
_MYPROXY_SERVER_LOCALID_XRD_ENTRY_TMPL = DoublePercentTemplate(
"""        <Service priority="10">
            <Type>urn:esg:security:myproxy-service</Type>
            <URI>%%{myproxyServerURI}</URI>
            <LocalID>$user_url</LocalID>
        </Service>
""")

"""@var _ATTRIBUTE_SERVICE_LOCALID_XRD_ENTRY_TMPL: Yadis XRDS entry for an
Attribute Service endpoint.  This entry also include a localID $user_url which 
the OpenID Provider application code will fill out at runtime.
@type _ATTRIBUTE_SERVICE_LOCALID_XRD_ENTRY_TMPL: ndg.security.server.paster_templates.template.DoublePercentTemplate
"""
_ATTRIBUTE_SERVICE_LOCALID_XRD_ENTRY_TMPL = DoublePercentTemplate(
"""<Service priority="20">
            <Type>urn:esg:security:attribute-service</Type>
            <URI>%%{attributeServiceURI}</URI>
            <LocalID>$user_url</LocalID>
        </Service>
""")

"""@var _MYPROXY_SERVER_NONLOCALID_XRD_ENTRY_TMPL: Yadis XRDS entry for a 
MyProxy server endpoint.  No localID entry is included as this template is for 
use with the serveryadis.xml_tmpl which applies to requests where the specific 
identity is not provided.
@type _MYPROXY_SERVER_NONLOCALID_XRD_ENTRY_TMPL: ndg.security.server.paster_templates.template.DoublePercentTemplate
"""
_MYPROXY_SERVER_NONLOCALID_XRD_ENTRY_TMPL = DoublePercentTemplate(
"""        <Service priority="10">
            <Type>urn:esg:security:myproxy-service</Type>
            <URI>%%{myproxyServerURI}</URI>
        </Service>
""")

"""@var _ATTRIBUTE_SERVICE_NONLOCALID_XRD_ENTRY_TMPL: Yadis XRDS entry for an
Attribute Service endpoint.  No localID entry is included as this template is 
for use with the serveryadis.xml_tmpl which applies to requests where the 
specific identity is not provided.
@type _ATTRIBUTE_SERVICE_NONLOCALID_XRD_ENTRY_TMPL: ndg.security.server.paster_templates.template.DoublePercentTemplate
"""
_ATTRIBUTE_SERVICE_NONLOCALID_XRD_ENTRY_TMPL = DoublePercentTemplate(
"""<Service priority="20">
            <Type>urn:esg:security:attribute-service</Type>
            <URI>%%{attributeServiceURI}</URI>
        </Service>
""")
   

class AttributeServiceTemplate(TemplateBase):
    """Paster template for the SAML attribute service"""
    
    DEFAULT_PORT = 5000
    DEFAULT_MOUNT_PATH = '/AttributeService'
    DEFAULT_ISSUER_NAME = 'O=NDG, OU=Security, CN=localhost'
    DEFAULT_ISSUER_FORMAT = Issuer.X509_SUBJECT
    
    _template_dir = 'attributeservice'
    summary = 'NDG Security SAML Attribute Service template'
    vars = [
        var('portNumber',
            'Port number for service to listen on [applies to running with '
            'paster ONLY]',
            default=DEFAULT_PORT),
            
        var('mountPath', 
            ('URI path to mount service i.e. "https://myhost/<mountPath>" ['
             'Nb. for mod_wsgi path may be e.g. "https://myhost/<script alias '
             'path><mountPath>" !]'),
            default=DEFAULT_MOUNT_PATH),

        var('issuerName', 
            ('ID of this service used in SAML queries and responses'),
            default=DEFAULT_ISSUER_NAME),

        var('issuerFormat', 
            ('Format of issuerName string; if using the default, ensure that '
             'the issuerName value is a correctly formatted X.509 Subject '
             'Name'),
            default=DEFAULT_ISSUER_FORMAT)
    ]

    def pre(self, command, output_dir, vars_):
        '''Extend to fix log file path setting and check mount point setting
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars_: variables to be substituted into template
        @type vars_: dict
        '''  
        # Fix for mount point in case leading slash was omitted.
        if not vars_['mountPath'].startswith('/'):
            vars_['mountPath'] = '/' + vars_['mountPath']
            
        super(AttributeServiceTemplate, self).pre(command, output_dir, vars_)
            

class AuthorisationServiceTemplate(TemplateBase):
    """Paster template for the SAML authorisation service"""
    
    DEFAULT_PORT = 5100
    DEFAULT_MOUNT_PATH = '/AuthorisationService'
    DEFAULT_ISSUER_NAME = 'O=NDG, OU=Security, CN=localhost'
    DEFAULT_ISSUER_FORMAT = Issuer.X509_SUBJECT
    DEFAULT_RESOURCE_BASE_URI = 'http://localhost:7080/'
    DEFAULT_ATTRIBUTE_SERVICE_URI = 'http://localhost:%d%s' % (
                                    AttributeServiceTemplate.DEFAULT_PORT, 
                                    AttributeServiceTemplate.DEFAULT_MOUNT_PATH)
    
    _template_dir = 'authorisationservice'
    summary = 'NDG Security Authorisation Service template'
    
    vars = [
        var('portNumber',
            'Port number for service to listen on [applies to running with '
            'paster ONLY]',
            default=DEFAULT_PORT),

        var('mountPath', 
            ('URI path to mount service i.e. "https://myhost/<mountPath>" ['
             'Nb. for mod_wsgi path may be e.g. "https://myhost/<script alias '
             'path><mountPath>" !]'),
            default=DEFAULT_MOUNT_PATH),

        var('issuerName', 
            ('ID of this service used in SAML queries and responses'),
            default=DEFAULT_ISSUER_NAME),

        var('issuerFormat', 
            ('Format of issuerName string; if using the default, ensure that '
             'the issuerName value is a correctly formatted X.509 Subject '
             'Name'),
            default=DEFAULT_ISSUER_FORMAT),
            
        var('resourceBaseURI',
            'Base URI for resources to be secured in the policy.  The policy '
            'assumes all resources are secured on the same server given by '
            'base path',
            default=DEFAULT_RESOURCE_BASE_URI),
            
        var('attributeServiceURI',
            'Address for SAML Attribute Service.  The Authorisation Service '
            'can call out to this service to make an additional check '
            'for user attribute entitlements',
            default=DEFAULT_ATTRIBUTE_SERVICE_URI)
    ]

    def pre(self, command, output_dir, vars_):
        '''Extend to fix log file path setting and check mount point setting
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars_: variables to be substituted into template
        @type vars_: dict
        '''  
        vars_['outputDir'] = os.path.abspath(output_dir)
        
        # Fix for mount point in case leading slash was omitted.
        if not vars_['mountPath'].startswith('/'):
            vars_['mountPath'] = '/' + vars_['mountPath']
                

class OpenIDProviderTemplate(TemplateBase):
    """Paster template for OpenID Provider service"""
    _template_dir = 'openidprovider'
    summary = 'NDG Security OpenID Provider template'
    
    DEFAULT_URI = urlunsplit(('https', _hostname, '', None, None))
    
    vars = [
        var('baseURI',
            'Base URI for the service [with no trailing slash]',
            default=DEFAULT_URI),

        var('beakerSessionCookieSecret', 
            'Secret for securing the OpenID Provider and SSL Client '
            'authentication session cookie',
            default=base64.b64encode(os.urandom(32))[:32]),
            
        var('myproxyServerURI',
            'MyProxy Server address to advertise in OpenID Provider Yadis '
            'document - defaults to omit this entry',
            default=''),
            
        var('attributeServiceURI',
            'Attribute Service address to advertise in OpenID Provider Yadis '
            'document - defaults to omit this entry',
            default='')
        ]

    def pre(self, command, output_dir, vars_):
        '''Extend to enable substitutions for OpenID Provider Yadis templates,
        port number and fix log file path setting
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars_: variables to be substituted into template
        @type vars_: dict
        '''  
        # Cut out port number from base URI
        uri_parts = urlparse(vars_['baseURI'])
        netloc_last_elem = uri_parts.netloc.split(':')[-1]
        if netloc_last_elem.isdigit():
            vars_['portNumber'] = netloc_last_elem
        else:
            vars_['portNumber'] = ''

        # Set Yadis XRDS entries
        vars_['yadisExtraServiceEndpoints'] = ''
        vars_['serveryadisExtraServiceEndpoints'] = ''
        
        # Attribute Service entry added if an endpoint was specified
        if vars_['attributeServiceURI']:
            # yadis.xml_tmpl entry
            vars_['yadisExtraServiceEndpoints'
                 ] += _ATTRIBUTE_SERVICE_LOCALID_XRD_ENTRY_TMPL.substitute(
                        attributeServiceURI=vars_['attributeServiceURI'])

            # serveryadis.xml_tmpl entry
            vars_['serveryadisExtraServiceEndpoints'
                 ] += _ATTRIBUTE_SERVICE_NONLOCALID_XRD_ENTRY_TMPL.substitute(
                        attributeServiceURI=vars_['attributeServiceURI'])

        del vars_['attributeServiceURI']
        
        if vars_['myproxyServerURI']:
            # yadis.xml_tmpl entry
            vars_['yadisExtraServiceEndpoints'
                 ] += _MYPROXY_SERVER_LOCALID_XRD_ENTRY_TMPL.substitute(
                            myproxyServerURI=vars_['myproxyServerURI'])        
            
            vars_['serveryadisExtraServiceEndpoints'
                 ] += _MYPROXY_SERVER_NONLOCALID_XRD_ENTRY_TMPL.substitute(
                        myproxyServerURI=vars_['myproxyServerURI'])
                         
        del vars_['myproxyServerURI']  
         
        super(OpenIDProviderTemplate, self).pre(command, output_dir, vars_)


class ServiceProviderTemplate(TemplateBase):
    '''Template for secured application including Relying Party functionality
    '''
    
    summary = (
        'NDG Security template for securing an application with '
        'authentication and authorisation filters.')
    
    DEFAULT_URI = 'http://localhost:7080/'
    DEFAULT_RELYING_PARTY_PORT_NUM = 6443
    DEFAULT_RELYING_PARTY_BASE_URI = 'https://%s' + ':%d' % \
                                                DEFAULT_RELYING_PARTY_PORT_NUM
    RELYING_PARTY_URI_PATH = '/verify'
    DEFAULT_AUTHZ_SERVICE_URI = 'http://localhost:%d%s' % (
                                AuthorisationServiceTemplate.DEFAULT_PORT,
                                AuthorisationServiceTemplate.DEFAULT_MOUNT_PATH)

    DEFAULT_ISSUER_NAME = 'O=NDG, OU=Security, CN=localhost'
    DEFAULT_ISSUER_FORMAT = Issuer.X509_SUBJECT
    DEFAULT_ACCESS_DENIED_HEADING = 'Access Denied'

    DEFAULT_OPENID_PROVIDER_URI = 'https://ceda.ac.uk/openid/'
    
    summary = ('NDG Security Relying Party Authentication Services template '
               'includes, OpenID Relying Party and SSL client authentication '
               'services.  Use this template alongside the SecuredApp template')
    vars = [

        var('securedAppBaseURI',
            'Base URI for the service [sets default return to address '
            'following logout]',
            default=DEFAULT_URI),

        var('openIDProviderIDSelectURI',
            ('Initial OpenID displayed in OpenID Relying Party interface '
             'text box.  This can be a partial URL representing a default '
             'OpenID Provider rather than an individual user\'s OpenID'),
             default=DEFAULT_OPENID_PROVIDER_URI),
             
        var('authkitCookieSecret', 
            ('Cookie secret for AuthKit authentication middleware.'),
            default=base64.b64encode(os.urandom(32))[:32]),
            
        var('authzServiceURI', 
            ('endpoint for authorisation service - this app calls this to make '
             'access control decisions'),
            default=DEFAULT_AUTHZ_SERVICE_URI),
            
        var('authzDecisionQueryIssuerName', 
            ('ID of this service used in SAML authorisation queries'),
            default=DEFAULT_ISSUER_NAME),

        var('authzDecisionQueryIssuerFormat', 
            ('Format of authzDecisionQueryIssuerName string; if using the '
             'default, ensure that the issuerName value is a correctly '
             'formatted X.509 Subject Name'),
            default=DEFAULT_ISSUER_FORMAT)
    ]

    def __init__(self, name):
        '''Override base class to make a template dir instance var
        '''
        super(ServiceProviderTemplate, self).__init__(name)
        self.template_dir_ = os.path.abspath(
                                    os.path.join(os.path.dirname(__file__),
                                                 'securedapp')
                                             )
        
    def template_dir(self):
        '''Override base class so that instance variable rather than class
        variable is used
        
        @rtype: basetring
        @return: template directory path
        '''
        return self.template_dir_
    
    def pre(self, command, output_dir, vars_):
        '''Extend to enable substitutions for port number and fix log file path 
        setting
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars_: variables to be substituted into template
        @type vars_: dict
        '''  
        # Cut out port number from base URI
        uri_parts = urlparse(vars_['securedAppBaseURI'])
        hostname, netloc_last_elem = uri_parts.netloc.split(':')
        if netloc_last_elem.isdigit():
            vars_['securedAppPortNumber'] = netloc_last_elem
        else:
            vars_['securedAppPortNumber'] = ''
        
        # Fix for baseURI in case trailing slash was omitted.
        if not vars_['securedAppBaseURI'].endswith('/'):
            vars_['securedAppBaseURI'] += '/'
            
        # URI for Relying Party
        vars_['relyingPartyBaseURI'
            ] = self.__class__.DEFAULT_RELYING_PARTY_BASE_URI % hostname

        vars_['relyingPartyURI'] = vars_['relyingPartyBaseURI'
                                    ] + self.__class__.RELYING_PARTY_URI_PATH
            
        vars_['relyingPartyPortNumber'
            ] = self.__class__.DEFAULT_RELYING_PARTY_PORT_NUM
        
        vars_['beakerSessionCookieSecret'
            ] = base64.b64encode(os.urandom(32))[:32]
           
        vars_['openidRelyingPartyCookieSecret'
            ] = base64.b64encode(os.urandom(32))[:32]
                         
        # This sets the log file path
        super(ServiceProviderTemplate, self).pre(command, output_dir, vars_)

