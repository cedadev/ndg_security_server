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
    
    def template_renderer(self, content, vars, filename=None):
        """Alternative renderer defined to enable use of '%%' prefix for template
        variables.  NDG Security ini files already use '$' for other variables
        
        @param content: template content
        @type content: string
        @param vars: variables to substituted into the template
        @type vars: dict
        @return: content with all variables substituted for
        @rtype: string
        """
        tmpl = DoublePercentTemplate(content)
        return tmpl.substitute(**vars)

    def pre(self, command, output_dir, vars):
        '''Extend to fix log file path setting in ini file
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars: variables to be substituted into template
        @type vars: dict
        '''  
        vars['outputDir'] = os.path.abspath(output_dir)
        
        
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


class ServicesTemplate(TemplateBase):
    """Make a template containing all the Security Services available with
    NDG Security.  These are provided together in one template but deployers
    should consider adapting this and dividing up into separate WSGI apps
    to suit
    """
    DEFAULT_URI = urlunsplit(('https', _hostname, '', None, None))
    
    ATTRIBUTE_SERVICE_DEFAULT_MOUNT_PATH = '/AttributeService'
    ATTRIBUTE_SERVICE_DEFAULT_ISSUER_NAME = '/O=Site A/CN=Attribute Authority'
    ATTRIBUTE_SERVICE_DEFAULT_ISSUER_FORMAT = Issuer.X509_SUBJECT
    
    AUTHORISATION_SERVICE_DEFAULT_ISSUER_NAME = \
        '/O=Site A/CN=Authorisation Service'
    AUTHORISATION_SERVICE_DEFAULT_ISSUER_FORMAT = Issuer.X509_SUBJECT
    AUTHORISATION_SERVICE_DEFAULT_MOUNT_PATH = '/AuthorisationService'    
    
    _template_dir = 'services'
    summary = ('NDG Security services full deployment template '
               'including the SAML Attribute and Authorisation Services, '
               'OpenID Provider application, OpenID Relying Party and SSL '
               'client authentication services')
    vars = [
        var('baseURI',
            'Base URI for the service(s) [with no trailing slash]',
            default=DEFAULT_URI),
            
        var('attributeServiceMountPath',
            'Mount path for Attribute Service',
            ATTRIBUTE_SERVICE_DEFAULT_MOUNT_PATH),
            
        var('authorisationServiceMountPath',
            'Mount path for Authorisation Service',
            AUTHORISATION_SERVICE_DEFAULT_MOUNT_PATH),
            
        var('attributeServiceIssuerName',
            'SAML Issuer Name field for Attribute Service SAML responses',
            ATTRIBUTE_SERVICE_DEFAULT_ISSUER_NAME),
            
        var('attributeServiceIssuerFormat',
            'SAML Issuer Name field for Attribute Service SAML responses',
            ATTRIBUTE_SERVICE_DEFAULT_ISSUER_FORMAT),
            
        var('authorisationServiceIssuerName',
            'SAML Issuer Name field for Authorisation Service SAML responses',
            AUTHORISATION_SERVICE_DEFAULT_ISSUER_NAME),
            
        var('authorisationServiceIssuerFormat',
            'SAML Issuer Name field for Authorisation Service SAML responses',
            AUTHORISATION_SERVICE_DEFAULT_ISSUER_FORMAT),

        var('authkitCookieSecret', 
            ('Cookie secret for AuthKit authentication middleware.  This value '
             '*MUST* agree with the one used for the ini file of the '
             'application to be secured - see ndgsecurity_securedapp template'),
            default=base64.b64encode(os.urandom(32))[:32]),

        var('beakerSessionCookieSecret', 
            'Secret for securing the OpenID Provider and SSL Client '
            'authentication session cookie',
            default=base64.b64encode(os.urandom(32))[:32]),
            
        var('openidRelyingPartyCookieSecret',
            'Secret for securing OpenID Relying Party session cookie',
            default=base64.b64encode(os.urandom(32))[:32]),
            
        var('myproxyServerURI',
            'MyProxy Server address to advertise in OpenID Provider Yadis '
            'document - defaults to omit this entry',
            default=''),
            
        var('includeAttributeServiceInYadis',
            'Include Attribute Service address in OpenID Provider Yadis '
            'document',
            default=True)
        ]
    
    def pre(self, command, output_dir, vars):
        '''Extend to enable substitutions for OpenID Provider Yadis templates,
        port number and fix log file path setting
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars: variables to be substituted into template
        @type vars: dict
        '''  
        
        # Fix for baseURI in case trailing slash was included.  In THIS template
        # it should not be there
        if vars['baseURI'].endswith('/'):
            vars['baseURI'] = vars['baseURI'].rstrip('/')

        # Fix for mount paths in case leading slash was omitted.
        if not vars['attributeServiceMountPath'].startswith('/'):
            vars['attributeServiceMountPath'] = '/' + vars[
                                                'attributeServiceMountPath']

        if not vars['authorisationServiceMountPath'].startswith('/'):
            vars['authorisationServiceMountPath'] = '/' + vars[
                                            'authorisationServiceMountPath']
            
        # Cut out port number from base URI
        uriParts = urlparse(vars['baseURI'])
        netlocLastElem = uriParts.netloc.split(':')[-1]
        if netlocLastElem.isdigit():
            vars['portNumber'] = netlocLastElem
        else:
            vars['portNumber'] = ''
            
        vars['yadisExtraServiceEndpoints'] = ''
        vars['serveryadisExtraServiceEndpoints'] = ''
        
        attributeServiceURI = vars['baseURI'] + vars[
                                'attributeServiceMountPath']
        
        # Attribute Service entry added if flag was set
        if vars['includeAttributeServiceInYadis']:
            # yadis.xml_tmpl entry
            vars['yadisExtraServiceEndpoints'
                 ] += _ATTRIBUTE_SERVICE_LOCALID_XRD_ENTRY_TMPL.substitute(
                        attributeServiceURI=attributeServiceURI)

            # serveryadis.xml_tmpl entry
            vars['serveryadisExtraServiceEndpoints'
                 ] += _ATTRIBUTE_SERVICE_NONLOCALID_XRD_ENTRY_TMPL.substitute(
                        attributeServiceURI=attributeServiceURI)

        del vars['includeAttributeServiceInYadis']
        
        # MyProxy Server entry added if an endpoint was specified
        if vars['myproxyServerURI']:
            # yadis.xml_tmpl entry
            vars['yadisExtraServiceEndpoints'
                 ] += _MYPROXY_SERVER_LOCALID_XRD_ENTRY_TMPL.substitute(
                            myproxyServerURI=vars['myproxyServerURI'])        
            
            vars['serveryadisExtraServiceEndpoints'
                 ] += _MYPROXY_SERVER_NONLOCALID_XRD_ENTRY_TMPL.substitute(
                        myproxyServerURI=vars['myproxyServerURI'])
        del vars['myproxyServerURI']   
        
        # This sets the log file path
        super(ServicesTemplate, self).pre(command, output_dir, vars)


class RelyingPartyAuthnServicesTemplate(TemplateBase):
    """Template to create authentication services for a Relying Party.  This 
    includes an OpenID Relying Party App fronted with an SSL client
    authentication filter.  Nb. it does not include an OpenID Provider 
    application.  For this, see the generic services template or the specific
    OpenID Provider template.
    """
    DEFAULT_PORT = 6443
    DEFAULT_URI = urlunsplit(('https', '%s:%d' % (_hostname, DEFAULT_PORT), '',
                              None, None))
    DEFAULT_OPENID_PROVIDER_URI = 'https://ceda.ac.uk/openid/'
    
    summary = ('NDG Security Relying Party Authentication Services template '
               'includes, OpenID Relying Party and SSL client authentication '
               'services.  Use this template alongside the SecuredApp template')
    vars = [
        var('baseURI',
            'Base URI for the service(s) [with no trailing slash]',
            default=DEFAULT_URI),

        var('openIDProviderIDSelectURI',
            ('Initial OpenID displayed in OpenID Relying Party interface '
             'text box.  This can be a partial URL representing a default '
             'OpenID Provider rather than an individual user\'s OpenID'),
             default=DEFAULT_OPENID_PROVIDER_URI),
             
        var('authkitCookieSecret', 
            ('Cookie secret for AuthKit authentication middleware.  This value '
             '*MUST* agree with the one used for the ini file of the '
             'application to be secured - see ndgsecurity_securedapp template'),
            default=base64.b64encode(os.urandom(32))[:32]),

        var('beakerSessionCookieSecret', 
            'Secret for securing the SSL Client authentication session cookie',
            default=base64.b64encode(os.urandom(32))[:32]),
            
        var('openidRelyingPartyCookieSecret',
            'Secret for securing OpenID Relying Party session cookie',
            default=base64.b64encode(os.urandom(32))[:32]),

        ]

    def __init__(self, name):
        '''Override base class to make a template dir instance var
        '''
        super(RelyingPartyAuthnServicesTemplate, self).__init__(name)
        self.template_dir_ = 'relyingparty_authn_services'
        
    def template_dir(self):
        '''Override base class so that instance variable rather than class
        variable is used
        
        @rtype: basetring
        @return: template directory path
        '''
        return self.template_dir_
        
    def pre(self, command, output_dir, vars):
        '''Extend to enable substitutions for OpenID Provider Yadis templates,
        port number and fix log file path setting
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars: variables to be substituted into template
        @type vars: dict
        '''  
        
        # Fix for baseURI in case trailing slash was included.  In THIS template
        # it should not be there
        if vars['baseURI'].endswith('/'):
            vars['baseURI'] = vars['baseURI'].rstrip('/')  
            
        # Cut out port number from base URI
        uriParts = urlparse(vars['baseURI'])
        netlocLastElem = uriParts.netloc.split(':')[-1]
        if netlocLastElem.isdigit():
            vars['portNumber'] = netlocLastElem
        else:
            vars['portNumber'] = ''
                    
        # This sets the log file path
        super(RelyingPartyAuthnServicesTemplate, self).pre(command, output_dir, vars)

        
class SecuredAppTemplate(TemplateBase):
    """Create a template for a secured application with authentication and
    authorisation filters"""
    DEFAULT_URI = 'http://localhost:7080/'
    DEFAULT_AUTHN_REDIRECT_URI = 'https://localhost:7443/verify'
    DEFAULT_AUTHZ_SERVICE_URI = 'https://localhost:7443/AuthorisationService'
    DEFAULT_ISSUER_NAME = 'O=NDG, OU=Security, CN=localhost'
    DEFAULT_ISSUER_FORMAT = Issuer.X509_SUBJECT
    DEFAULT_ACCESS_DENIED_HEADING = 'Access Denied'
    
    summary = (
        'NDG Security template for securing an application with '
        'authentication and authorisation filters.  Use in conjunction with '
        'the ndgsecurity_services template')
    
    vars = [
        var('SecuredAppBaseURI',
            'Base URI for the service [sets default return to address '
            'following logout]',
            default=DEFAULT_URI),

        var('authkitCookieSecret', 
            ('Cookie secret for AuthKit authentication middleware [this value '
             '*MUST* agree with the one set in the authentication service\'s '
             'ini file]'),
            default=base64.b64encode(os.urandom(32))[:32]),

        var('beakerSessionCookieSecret', 
            'Cookie secret for keeping security session state',
            default=base64.b64encode(os.urandom(32))[:32]),

        var('authnRedirectURI', 
            ('endpoint hosting OpenID Relying Party and/or SSL authentication '
             'interface'),
            default=DEFAULT_AUTHN_REDIRECT_URI),
            
        var('authzServiceURI', 
            ('endpoint authorisation service which this app is secured with'),
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
        super(SecuredAppTemplate, self).__init__(name)
        self.template_dir_ = 'securedapp'
        
    def template_dir(self):
        '''Override base class so that instance variable rather than class
        variable is used
        
        @rtype: basetring
        @return: template directory path
        '''
        return self.template_dir_
    
    def pre(self, command, output_dir, vars):
        '''Extend to enable substitutions for port number and fix log file path 
        setting
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars: variables to be substituted into template
        @type vars: dict
        '''  
        # Cut out port number from base URI
        uriParts = urlparse(vars['securedAppBaseURI'])
        netlocLastElem = uriParts.netloc.split(':')[-1]
        if netlocLastElem.isdigit():
            vars['portNumber'] = netlocLastElem
        else:
            vars['portNumber'] = ''
        
        # Fix for baseURI in case trailing slash was omitted.
        if not vars['securedAppBaseURI'].endswith('/'):
            vars['securedAppBaseURI'] += '/'
                        
        # This sets the log file path
        super(SecuredAppTemplate, self).pre(command, output_dir, vars)
            

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

    def pre(self, command, output_dir, vars):
        '''Extend to fix log file path setting and check mount point setting
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars: variables to be substituted into template
        @type vars: dict
        '''  
        # Fix for mount point in case leading slash was omitted.
        if not vars['mountPath'].startswith('/'):
            vars['mountPath'] = '/' + vars['mountPath']
            
        super(AttributeServiceTemplate, self).pre(command, output_dir, vars)
            

class AuthorisationServiceTemplate(TemplateBase):
    """Paster template for the SAML authorisation service"""
    
    DEFAULT_PORT = 5100
    DEFAULT_MOUNT_PATH = '/AuthorisationService'
    DEFAULT_ISSUER_NAME = 'O=NDG, OU=Security, CN=localhost'
    DEFAULT_ISSUER_FORMAT = Issuer.X509_SUBJECT
    
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
            default=DEFAULT_ISSUER_FORMAT)
    ]

    def pre(self, command, output_dir, vars):
        '''Extend to fix log file path setting and check mount point setting
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars: variables to be substituted into template
        @type vars: dict
        '''  
        vars['outputDir'] = os.path.abspath(output_dir)
        
        # Fix for mount point in case leading slash was omitted.
        if not vars['mountPath'].startswith('/'):
            vars['mountPath'] = '/' + vars['mountPath']
                

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

    def pre(self, command, output_dir, vars):
        '''Extend to enable substitutions for OpenID Provider Yadis templates,
        port number and fix log file path setting
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars: variables to be substituted into template
        @type vars: dict
        '''  
        # Cut out port number from base URI
        uriParts = urlparse(vars['baseURI'])
        netlocLastElem = uriParts.netloc.split(':')[-1]
        if netlocLastElem.isdigit():
            vars['portNumber'] = netlocLastElem
        else:
            vars['portNumber'] = ''

        # Set Yadis XRDS entries
        vars['yadisExtraServiceEndpoints'] = ''
        vars['serveryadisExtraServiceEndpoints'] = ''
        
        # Attribute Service entry added if an endpoint was specified
        if vars['attributeServiceURI']:
            # yadis.xml_tmpl entry
            vars['yadisExtraServiceEndpoints'
                 ] += _ATTRIBUTE_SERVICE_LOCALID_XRD_ENTRY_TMPL.substitute(
                        attributeServiceURI=vars['attributeServiceURI'])

            # serveryadis.xml_tmpl entry
            vars['serveryadisExtraServiceEndpoints'
                 ] += _ATTRIBUTE_SERVICE_NONLOCALID_XRD_ENTRY_TMPL.substitute(
                        attributeServiceURI=vars['attributeServiceURI'])

        del vars['attributeServiceURI']
        
        if vars['myproxyServerURI']:
            # yadis.xml_tmpl entry
            vars['yadisExtraServiceEndpoints'
                 ] += _MYPROXY_SERVER_LOCALID_XRD_ENTRY_TMPL.substitute(
                            myproxyServerURI=vars['myproxyServerURI'])        
            
            vars['serveryadisExtraServiceEndpoints'
                 ] += _MYPROXY_SERVER_NONLOCALID_XRD_ENTRY_TMPL.substitute(
                        myproxyServerURI=vars['myproxyServerURI'])
                         
        del vars['myproxyServerURI']  
         
        super(OpenIDProviderTemplate, self).pre(command, output_dir, vars)


class ServiceProviderTemplate(TemplateBase):
    '''Template for secured application including Relying Party functionality
    '''
    
    summary = (
        'NDG Security template for securing an application with '
        'authentication and authorisation filters.')
    
    DEFAULT_URI = 'http://localhost:7080/'
    DEFAULT_RELYING_PARTY_PORT_NUM = 6443
    DEFAULT_RELYING_PARTY_URI = 'https://%s:%d/verify' % \
                                                DEFAULT_RELYING_PARTY_PORT_NUM
    DEFAULT_AUTHZ_SERVICE_URI = 'https://localhost:%d%s' % (
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

        var('SecuredAppBaseURI',
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
        super(SecuredAppTemplate, self).__init__(name)
        self.template_dir_ = 'securedapp'
        
    def template_dir(self):
        '''Override base class so that instance variable rather than class
        variable is used
        
        @rtype: basetring
        @return: template directory path
        '''
        return self.template_dir_
    
    def pre(self, command, output_dir, vars):
        '''Extend to enable substitutions for port number and fix log file path 
        setting
        
        @param command: command to create template
        @type command: 
        @param output_dir: output directory for template file(s)
        @type output_dir: string
        @param vars: variables to be substituted into template
        @type vars: dict
        '''  
        # Cut out port number from base URI
        uriParts = urlparse(vars['securedAppBaseURI'])
        hostname, netlocLastElem = uriParts.netloc.split(':')
        if netlocLastElem.isdigit():
            vars['securedAppPortNumber'] = netlocLastElem
        else:
            vars['securedAppPortNumber'] = ''
        
        # Fix for baseURI in case trailing slash was omitted.
        if not vars['securedAppBaseURI'].endswith('/'):
            vars['securedAppBaseURI'] += '/'
            
        # Base URI for Relying Party
        var['relyingPartyBaseURI'
            ] = self.__class__.DEFAULT_RELYING_PARTY_URI % hostname
            
        var['relyingPartyPortNumber'
            ] = self.__class__.DEFAULT_RELYING_PARTY_PORT_NUM
        
        vars['beakerSessionCookieSecret'
             ] = base64.b64encode(os.urandom(32))[:32]
           
        vars['openidRelyingPartyCookieSecret'
                ] = base64.b64encode(os.urandom(32))[:32]
                         
        # This sets the log file path
        super(SecuredAppTemplate, self).pre(command, output_dir, vars)

