"""SSL Peer Authentication Middleware Module

Apply to SSL client authentication to configured URL paths.

SSL Client certificate is expected to be present in environ as SSL_CLIENT_CERT
key as set by standard Apache SSL.

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "11/12/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
__license__ = "BSD - see top-level directory for LICENSE file"
import logging
log = logging.getLogger(__name__)
import os
# Pattern matching to determine which URI paths to apply SSL AuthN to and to
# parse SSL certificate environment variable
import re     
from datetime import datetime

from OpenSSL import crypto

from ndg.security.server.wsgi import NDGSecurityMiddlewareBase


class ApacheSSLAuthnMiddleware(NDGSecurityMiddlewareBase):
    """Perform SSL peer certificate authentication making use of Apache
    SSL environment settings
    
    B{This class relies on SSL environment settings being present as available
    when run embedded within Apache using for example mod_wsgi}
    
    - SSL Client certificate is expected to be present in environ as 
    SSL_CLIENT_CERT key as set by Apache SSL with ExportCertData option to
    SSLOptions directive enabled.
    """
    SSL_KEYNAME = 'HTTPS'
    SSL_KEYVALUES = ('1', 'on')
    
    _isSSLRequest = lambda self: self.environ.get(self.sslKeyName) in \
                                    ApacheSSLAuthnMiddleware.SSL_KEYVALUES
    isSSLRequest = property(fget=_isSSLRequest,
                            doc="Is an SSL request boolean - depends on "
                                "'HTTPS' Apache environment variable setting")
    
    SSL_CLIENT_CERT_KEYNAME = 'SSL_CLIENT_CERT'
    PEM_CERT_PREFIX = '-----BEGIN CERTIFICATE-----'
    
    # Options for ini file
    RE_PATH_MATCH_LIST_OPTNAME = 'rePathMatchList'
    CACERT_FILEPATH_LIST_OPTNAME = 'caCertFilePathList'
    CLIENT_CERT_DN_MATCH_LIST_OPTNAME = 'clientCertDNMatchList'
    CLIENT_CERT_DN_MATCH_LIST_SEP_PAT = re.compile(',\s*')
    SSL_KEYNAME_OPTNAME = 'sslKeyName'
    SSL_CLIENT_CERT_KEYNAME_OPTNAME = 'sslClientCertKeyName'
    
    propertyDefaults = {
        RE_PATH_MATCH_LIST_OPTNAME: [],
        CACERT_FILEPATH_LIST_OPTNAME: [],
        CLIENT_CERT_DN_MATCH_LIST_OPTNAME: [],
        SSL_KEYNAME_OPTNAME: SSL_KEYNAME,
        SSL_CLIENT_CERT_KEYNAME_OPTNAME: SSL_CLIENT_CERT_KEYNAME
    }
    propertyDefaults.update(NDGSecurityMiddlewareBase.propertyDefaults)
    
    PARAM_PREFIX = 'sslAuthn.'
    
    # isValidCert requires special parsing of certificate when passed via a 
    # proxy
    X509_CERT_PAT = re.compile('(\s?-----[A-Z]+\sCERTIFICATE-----\s?)|\s+')
    
    # Flag to other middleware that authentication succeeded by setting this key
    # in the environ to True.  This is done in the isValidCert method
    AUTHN_SUCCEEDED_ENVIRON_KEYNAME = ('ndg.security.server.wsgi.ssl.'
                                       'ApacheSSLAuthnMiddleware.authenticated')

    def __init__(self, app, global_conf, prefix=PARAM_PREFIX, **app_conf):
        """Read configuration settings from the global and application specific
        ini file settings
        """
        super(ApacheSSLAuthnMiddleware, self).__init__(app, 
                                                       global_conf, 
                                                       prefix=prefix,
                                                       **app_conf)

        self.__clientCertDNMatchList = None
        self.__clientCert = None
        self.__sslClientCertKeyName = None
        self.__sslKeyName = None
        
        rePathMatchListParamName = prefix + \
                    ApacheSSLAuthnMiddleware.RE_PATH_MATCH_LIST_OPTNAME
        rePathMatchListVal = app_conf.get(rePathMatchListParamName, '')
        
        self.rePathMatchList = [re.compile(r) 
                                for r in rePathMatchListVal.split()]
        
        caCertFilePathListParamName = prefix + \
                    ApacheSSLAuthnMiddleware.CACERT_FILEPATH_LIST_OPTNAME
                        
        # Verify against trust root if set.  Alternatively, the verification
        # step can be configured in the Apache config file.  The latter will
        # correctly verify proxy certificates if the environment variable
        # OPENSSL_ALLOW_PROXY_CERTS is set in the start up.  The verification
        # code in is_valid_client_cert can't correctly verify proxy certificates 
        # because only a single certificate is passed in the SSL_CLIENT_CERT 
        # environ variable and not the complete certificate chain
        self.caCertStack = app_conf.get(caCertFilePathListParamName, [])
        
        clientCertDNMatchListParamName = prefix + \
                    ApacheSSLAuthnMiddleware.CLIENT_CERT_DN_MATCH_LIST_OPTNAME
                    
        # Specify a restricted list of DNs of which the input client certificate
        # DN must match at least one
        self.clientCertDNMatchList = app_conf.get(
                                        clientCertDNMatchListParamName, [])
        
        sslClientCertParamName = prefix + \
                    ApacheSSLAuthnMiddleware.SSL_CLIENT_CERT_KEYNAME_OPTNAME   
        self.sslClientCertKeyName = app_conf.get(sslClientCertParamName, 
                            ApacheSSLAuthnMiddleware.SSL_CLIENT_CERT_KEYNAME)
        
        sslKeyNameParamName = prefix + \
                    ApacheSSLAuthnMiddleware.SSL_KEYNAME_OPTNAME   
        self.sslKeyName = app_conf.get(sslKeyNameParamName, 
                                       ApacheSSLAuthnMiddleware.SSL_KEYNAME)

    def _getSslClientCertKeyName(self):
        return self.__sslClientCertKeyName

    def _setSslClientCertKeyName(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting %r type for "sslClientCertKeyName"; '
                            'got %r' % (basestring, type(value)))
        self.__sslClientCertKeyName = value

    sslClientCertKeyName = property(_getSslClientCertKeyName, 
                                    _setSslClientCertKeyName, 
                                    doc="environ key name for SSL Client "
                                        "Certificate")

    def _getSslKeyName(self):
        return self.__sslKeyName

    def _setSslKeyName(self, value):       
        if not isinstance(value, basestring):
            raise TypeError('Expecting %r type for "sslKeyName"; got %r' %
                            (basestring, type(value)))
        self.__sslKeyName = value

    sslKeyName = property(_getSslKeyName, 
                          _setSslKeyName, 
                          doc="SslKeyName's Docstring")

        
    def _setClientCertDNMatchList(self, value):
        '''        
        @type value: basestring, list, tuple
        @param value: list of client certificate Distinguished Names as strings
        of X500DN instances'''
        
        raise NotImplementedError('Disable for future release using PyOpenSSL')
#        if isinstance(value, basestring):
#            # Try parsing a space separated list of file paths
#            pat = ApacheSSLAuthnMiddleware.CLIENT_CERT_DN_MATCH_LIST_SEP_PAT
#            dnList = pat.split(value)
#            self.__clientCertDNMatchList = [X500DN(dn=dn) for dn in dnList]
#            
#        elif isinstance(value, (list, tuple)):
#            self.__clientCertDNMatchList = []
#            for dn in value:
#                if isinstance(dn, basestring):
#                    self.__clientCertDNMatchList.append(X500DN(dn=dn))
#                elif isinstance(dn, X500DN):
#                    self.__clientCertDNMatchList.append(dn)
#                else:
#                    raise TypeError('Expecting a string, or %r type for "%s" '
#                                    'list item; got %r' % 
#                    (X500DN,
#                     ApacheSSLAuthnMiddleware.CLIENT_CERT_DN_MATCH_LIST_OPTNAME,
#                     type(dn)))
#                    
#        else:
#            raise TypeError('Expecting a string, list or tuple for "%s"; got '
#                            '%r' % 
#                (ApacheSSLAuthnMiddleware.CLIENT_CERT_DN_MATCH_LIST_OPTNAME,
#                 type(value)))
    
    def _getClientCertDNMatchList(self):
        return self.__clientCertDNMatchList

    clientCertDNMatchList = property(fset=_setClientCertDNMatchList,
                                     fget=_getClientCertDNMatchList,
                                     doc="List of acceptable Distinguished "
                                         "Names for client certificates")
        
    def _getClientCert(self):
        return self.__clientCert

    clientCert = property(fget=_getClientCert,
                          doc="Client certificate for verification set by "
                              "is_valid_client_cert()")

    
    @NDGSecurityMiddlewareBase.initCall         
    def __call__(self, environ, start_response):
        '''Check for peer certificate in environment and if present carry out
        authentication
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        '''
        log.debug("ApacheSSLAuthnMiddleware.__call__ ...")
        
        if not self._pathMatch():
            log.debug("ApacheSSLAuthnMiddleware: ignoring path [%s]", 
                      self.pathInfo)
            return self._setResponse()
        
        elif not self.isSSLRequest:
            log.warning("ApacheSSLAuthnMiddleware: %r environment variable "
                        "not found in environment; ignoring request" % 
                        self.sslKeyName)
            return self._setResponse()
                        
        elif not self.isSSLClientCertSet:
            log.error("ApacheSSLAuthnMiddleware: No SSL Client certificate "
                      "for request to [%s]; setting HTTP 401 Unauthorized", 
                      self.pathInfo)
            return self._setErrorResponse(code=401,
                                          msg='No client SSL Certificate set')
            
        # Parse cert from environ keyword
        client_cert = self._parse_cert()
        
        if self.is_valid_client_cert(client_cert):
            self._setUser()          
            return self._setResponse()
        else:
            return self._setErrorResponse(code=401)

    def _setResponse(self, 
                     notFoundMsg='No application set for '
                                 'ApacheSSLAuthnMiddleware',
                     **kw):
        return super(ApacheSSLAuthnMiddleware, 
                     self)._setResponse(notFoundMsg=notFoundMsg, **kw)

    def _setErrorResponse(self, msg='Invalid SSL client certificate', **kw):
        return super(ApacheSSLAuthnMiddleware, self)._setErrorResponse(msg=msg,
                                                                       **kw)

    def _pathMatch(self):
        """Apply a list of regular expression matching patterns to the contents
        of environ['PATH_INFO'], if any match, return True.  This method is
        used to determine whether to apply SSL client authentication
        """
        path = self.pathInfo
        for regEx in self.rePathMatchList:
            if regEx.match(path):
                return True
            
        return False
        
    def _isSSLClientCertSet(self):
        """Check for SSL Certificate set in environ"""
        sslClientCert = self.environ.get(
                        self.sslClientCertKeyName, '')
        return sslClientCert.startswith(
                                    ApacheSSLAuthnMiddleware.PEM_CERT_PREFIX) 
        
    isSSLClientCertSet = property(fget=_isSSLClientCertSet,
                                  doc="Check for client X.509 certificate "
                                      "%r setting in environ" %
                                      SSL_CLIENT_CERT_KEYNAME)

    def _parse_cert(self):
        '''Parse client certificate from environ'''
        pem_cert = self.environ[self.sslClientCertKeyName]
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
        return cert

    @staticmethod
    def _is_cert_expired(cert):
        '''Check if input certificate has expired
        @param cert: X.509 certificate
        @type cert: OpenSSL.crypto.X509
        @return: true if expired, false otherwise
        @rtype: bool
        '''
        notAfter = cert.get_notAfter()
        dtNotAfter = datetime.strptime(notAfter, '%Y%m%d%H%M%S%fZ')       
        dtNow = datetime.utcnow()
        
        return dtNotAfter < dtNow
        
    def is_valid_client_cert(self, cert):
        '''Check certificate time validity
        
        TODO: allow verification against CA certs - current assumption is 
        that Apache config performs this task!
        '''
        return self.__class__._is_cert_expired(cert)
        
        

        # Certificate string passed through a proxy has spaces in place of
        # newline delimiters.  Fix by re-organising the string into a single 
        # line and remove the BEGIN CERTIFICATE / END CERTIFICATE delimiters.
        # Then, treat as a base64 encoded string decoding and passing as DER
        # format to the X.509 parser
        
#        cert = self.__class__.X509_CERT_PAT.sub('', sslClientCert)
#        derCert = base64.decodestring(cert)
#        self.__clientCert = X509Cert.Parse(derCert, format=X509Cert.formatDER)
#        
#        # Check validity time
#        if not self.__clientCert.isValidTime():
#            return False
#        
#        # Verify against trust root if set.  Alternatively, the verification
#        # step can be configured in the Apache config file.  The latter will
#        # correctly verify proxy certificates if the environment variable
#        # OPENSSL_ALLOW_PROXY_CERTS is set in the start up.  The verification
#        # code HERE can't correctly verify proxy certificates because only a
#        # single certificate is passed in the SSL_CLIENT_CERT environ variable 
#        # and not the complete certificate chain
#        if len(self.caCertStack) == 0:
#            log.warning("No CA certificates set for Client certificate "
#                        "signature verification")
#        else:
#            try:
#                self.caCertStack.verifyCertChain(
#                                            x509Cert2Verify=self.__clientCert)
#
#            except X509CertError, e:
#                log.info("Client certificate verification failed with %s "
#                         "exception: %s" % (type(e), e))
#                return False
#            
#            except Exception, e:
#                log.error("Client certificate verification failed with "
#                          "unexpected exception type %s: %s" % (type(e), e))
#                return False
#           
#        # Verify against list of acceptable DNs if set
#        if len(self.clientCertDNMatchList) > 0:
#            dn = self.__clientCert.dn
#            for expectedDN in self.clientCertDNMatchList: 
#                if dn == expectedDN:
#                    self.environ[
#                        ApacheSSLAuthnMiddleware.AUTHN_SUCCEEDED_ENVIRON_KEYNAME
#                    ] = True
#                    log.debug("Client Certificate DN %s matches DN in "
#                              "permitted DNs list %r", dn, 
#                              self.clientCertDNMatchList)
#                    return True
#                
#            log.debug("No match found for Client Certificate DN %s in "
#                      "permitted DNs list %r", dn, self.clientCertDNMatchList)
#                
#            return False

        self.environ[
            ApacheSSLAuthnMiddleware.AUTHN_SUCCEEDED_ENVIRON_KEYNAME] = True
        return True

    def _setUser(self):
        """Interface hook for a derived class to set user ID from certificate 
        set or other context info.
        """


class AuthKitSSLAuthnMiddleware(ApacheSSLAuthnMiddleware):
    """Update REMOTE_USER AuthKit environ key with certificate CommonName to
    flag logged in status to other middleware and set cookie using Paste
    Auth Ticket
    """
    SET_USER_ENVIRON_KEYNAME = 'paste.auth_tkt.set_user'
    
    @NDGSecurityMiddlewareBase.initCall         
    def __call__(self, environ, start_response):
        '''Check for peer certificate in environment and if present carry out
        authentication.  Overrides parent class behaviour to set REMOTE_USER
        AuthKit environ key based on the client certificate's Distinguished 
        Name CommonName field.  If no certificate is present or it is 
        present but invalid no 401 response is set.  Instead, it is left to
        the following middleware in the chain to deal with this.  When used
        in conjunction with 
        ndg.security.server.wsgi.openid.relyingparty.OpenIDRelyingPartyMiddleware,
        this will result in the display of the Relying Party interface but with
        a 401 status set.
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        '''
        if not self._pathMatch():
            log.debug("AuthKitSSLAuthnMiddleware: ignoring path [%s]", 
                      self.pathInfo)

        elif not self.isSSLRequest:
            log.debug("AuthKitSSLAuthnMiddleware: 'HTTPS' environment "
                      "variable not found in environment; ignoring request")
                        
        elif not self.isSSLClientCertSet:
            log.debug("AuthKitSSLAuthnMiddleware: no client certificate set - "
                      "passing request to next middleware in the chain ...")
            
        else:
            client_cert = self.__class__._parse_cert()
            if self.is_valid_client_cert(client_cert):
                # Update session cookie with user ID
                self._setUser(client_cert)
                log.debug("AuthKitSSLAuthnMiddleware: set "
                          "environ['REMOTE_USER'] = %r" % 
                          environ.get('REMOTE_USER'))
            
        # ... is_valid_cert will log warnings/errors no need to flag the False
        # condition
            
        # Pass request to next middleware in the chain without setting an
        # error response - see method doc string for explanation.
        return self._setResponse()

    def _setUser(self, cert):
        """Set user ID in AuthKit cookie from client certificate submitted
        """
        subject = cert.get_subject()
        userId = subject.commonName
        
        self.environ[
            AuthKitSSLAuthnMiddleware.USERNAME_ENVIRON_KEYNAME] = userId
        self.environ[AuthKitSSLAuthnMiddleware.SET_USER_ENVIRON_KEYNAME](userId)
