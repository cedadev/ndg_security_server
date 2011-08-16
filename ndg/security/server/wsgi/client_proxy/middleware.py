'''
Created on 21 Dec 2010

@author: pjkersha
'''
import logging
log = logging.getLogger(__name__)

import traceback
import socket
import httplib
import urllib
import urlparse
import os
from datetime import datetime, timedelta

from paste import httpexceptions
from paste.proxy import Proxy, parse_headers
from webob.dec import wsgify
from webob import Request, Response
from OpenSSL import SSL, crypto

from myproxy.client import MyProxyClient, MyProxyClientError
from ndg.security.common.utils import pyopenssl


class SSLCtxSessionMiddleware(object):
    """Store an SSL Context object in session middleware for client callouts"""
    PARAM_NAMES = (
        'environSessionKeyName', 
        'ctxSessionKeyName', 
        'caCertFilePath', 
        'caCertDir',)
    
    __slots__ = (
        '_app',
    )
    
    __slots__ += tuple(['__' + i for i in PARAM_NAMES])
    del i
    DEFAULT_ENVIRON_SESSION_KEYNAME = "ndg.security.session"
    DEFAULT_CTX_SESSION_KEYNAME = "ssl_ctx"
    DEFAULT_PARAM_PREFIX = 'ssl_ctx.'
    
    '''@param SSL_VERSION: SSL version for context object
    @type SSL_VERSION: string'''
    SSL_VERSION = SSL.SSLv3_METHOD
    
    def __init__(self, app):
        self._app = app
        
        self.__environSessionKeyName = \
            self.__class__.DEFAULT_ENVIRON_SESSION_KEYNAME
            
        self.__ctxSessionKeyName = \
            self.__class__.DEFAULT_CTX_SESSION_KEYNAME
            
        self.__caCertFilePath = None
        self.__caCertDir = None
        
    def initialise(self, app_conf, prefix=DEFAULT_PARAM_PREFIX, **local_conf):
        """Initialise attributes from the given local configuration settings
        @param app_conf: application configuration settings - ignored - this
        method includes this arg to fit Paste middleware / app function 
        signature
        @type app_conf: dict
        @param prefix: optional prefix for parameter names included in the 
        local_conf dict - enables these parameters to be filtered from others
        which don't apply to this middleware
        @param local_conf: attribute settings to apply
        @type local_conf: dict
        """
        for k in local_conf:
            if prefix:
                paramName = k.lstrip(prefix)
            else:
                paramName = k
                
            if paramName in SSLCtxSessionMiddleware.PARAM_NAMES:                
                setattr(self, paramName, local_conf[k])
            
    @classmethod
    def filter_app_factory(cls, app, app_conf, **kw):
        obj = cls(app)
        obj.initialise(app_conf, **kw)
        return obj
    
    @wsgify
    def __call__(self, request):
        session = request.environ.get(self.__environSessionKeyName)
        if session is None:
            raise httpexceptions.HTTPInternalServerError(
                'Expecting session assigned to %r environ key' % 
                self.__environSessionKeyName)
            
        self._create_ssl_ctx(session)

        return self._app
    
    @property
    def environSessionKeyName(self):
        return self.__environSessionKeyName
    
    @environSessionKeyName.setter
    def environSessionKeyName(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "environSessionKeyName" '
                            'attribute; got %r' % type(val))
    
    @property
    def ctxSessionKeyName(self):
        return self.__ctxSessionKeyName    
    
    @ctxSessionKeyName.setter
    def ctxSessionKeyName(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "ctxSessionKeyName" '
                            'attribute; got %r' % type(val))
        
        self.__ctxSessionKeyName = val
    
    @property
    def caCertFilePath(self):
        return self.__caCertFilePath
    
    @caCertFilePath.setter
    def caCertFilePath(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "caCertFilePath" '
                            'attribute; got %r' % type(val))
            
        self.__caCertFilePath = val
    
    @property
    def caCertDir(self):
        return self.__caCertDir
    
    @caCertDir.setter
    def caCertDir(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "caCertDir" '
                            'attribute; got %r' % type(val))
            
        self.__caCertDir = val
    
    def getSession(self, request):
        '''Get beaker session
        @param request: WSGI request object
        @type request: webob.Request
        @return: session object
        @rtype: beaker.SessionObject
        '''    
        session = request.environ.get(self.__environSessionKeyName)
        return session
    
    def _create_ssl_ctx(self, session):
        """Create or refresh SSL Context object"""
        # TODO: refresh existing context if client credentials are near expiry
        ctx = session.get(self.__ctxSessionKeyName)
        if ctx is None:
            ctx = SSL.Context(self.__class__.SSL_VERSION)
            
            def _callback(conn, x509, errnum, errdepth, ok):
                return ok

            ctx.set_verify(SSL.VERIFY_PEER, _callback)
            ctx.set_verify_depth(9)
            if self.caCertFilePath or self.caCertDir:
                ctx.load_verify_locations(self.caCertFilePath, self.caCertDir)
                
            session[self.__ctxSessionKeyName] = ctx
        

class MyProxyProvisionedSessionMiddlewareError(Exception):
    """Exception class for MyProxyProvisionedSessionMiddleware, a WSGI 
    middleware class which provisions a session object with PKI credentials from
    a MyProxy server
    """
        

class MyProxyRetrievalError(MyProxyProvisionedSessionMiddlewareError):
    """Exception class to flag errors from MyProxy logon calls made from 
    MyProxyProvisionedSessionMiddleware"""
        

class MyProxyRetrievalSocketError(MyProxyProvisionedSessionMiddlewareError):
    """Exception class to flag socket errors from MyProxy logon calls made from 
    MyProxyProvisionedSessionMiddleware"""
    
    
class MyProxyProvisionedSessionMiddleware(SSLCtxSessionMiddleware):
    """Provisions a session object with PKI credentials from a MyProxy server.
    Call MyProxy logon to populate a session based SSL context object with
    client PKI credentials to make SSL calls to other services.
    
    @cvar DEFAULT_CERT_EXPIRY_OFFSET: default time offset prior to certificate
    expiry used to trigger certificate renewal. e.g. if the offset is 1 day
    and the certificate will expiry within one day then certificate renewal
    is invoked with a fresh MyProxy logon call.
    @type DEFAULT_CERT_EXPIRY_OFFSET: timedelta
    """
    __slots__ = (
        '__myProxyClient',
        '__certExpiryOffset',
        '__myProxyClientSSLCertFile',
        '__myProxyClientSSLKeyFile',
        '__myProxyClientSSLKeyFilePassphrase'
    )
    PARAM_NAMES = tuple([i[2:] for i in __slots__])
    del i
    DEFAULT_ENVIRON_SESSION_KEYNAME = "ndg.security.session"
    DEFAULT_PARAM_PREFIX = 'myproxy_provision_session.'
    MYPROXY_CLIENT_PARAM_PREFIX = 'myproxy_client.'
    DEFAULT_CERT_EXPIRY_OFFSET = timedelta(days=1)
    
    def __init__(self, app):
        super(MyProxyProvisionedSessionMiddleware, self).__init__(app)
        self.__myProxyClient = MyProxyClient()
        self.__certExpiryOffset = self.__class__.DEFAULT_CERT_EXPIRY_OFFSET
        self.__myProxyClientSSLCertFile = None
        self.__myProxyClientSSLKeyFile = None
        self.__myProxyClientSSLKeyFilePassphrase = None
        
    @property
    def myProxyClient(self):
        '''MyProxy client used to make calls to MyProxy server to retrieve 
        credentials for user
        '''
        return self.__myProxyClient
    
    @myProxyClient.setter
    def myProxyClient(self, val):
        '''MyProxy client used to make calls to MyProxy server to retrieve 
        credentials for user
        '''
        if not isinstance(val, MyProxyClient):
            raise TypeError('Expecting %r type for "myProxyClient", got %r' % 
                            (MyProxyClient, type(val)))
        self.__myProxyClient = val
            
                    
    @property
    def certExpiryOffset(self):
        '''Certificate expiry offset measured in seconds before current time
        '''
        return self.__certExpiryOffset
    
    @certExpiryOffset.setter
    def certExpiryOffset(self, val):
        '''Certificate expiry offset measured in seconds before current time
        '''
        if isinstance(val, basestring):
            self.__certExpiryOffset = timedelta(seconds=float(val))
            
        elif isinstance(val, (float, int, long)):
            self.__certExpiryOffset = timedelta(seconds=val)
            
        elif isinstance(val, timedelta):
            self.__certExpiryOffset = val
            
        else:
            raise TypeError('Expecting string, int, long, float or timedelta '
                            'type for "certExpiryOffset", got %r' % type(val))
      
    @property      
    def myProxyClientSSLCertFile(self):
        return self.__myProxyClientSSLCertFile
    
    @myProxyClientSSLCertFile.setter
    def myProxyClientSSLCertFile(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for '
                            '"myProxyClientSSLCertFile"; got %r' % type(val))
            
        if not os.access(val, os.R_OK):
            raise IOError('Error accessing "myProxyClientSSLCertFile" file %r' %
                          val)
         
        self.__myProxyClientSSLCertFile = val
        
    @property      
    def myProxyClientSSLKeyFile(self):
        return self.__myProxyClientSSLKeyFile
    
    @myProxyClientSSLKeyFile.setter
    def myProxyClientSSLKeyFile(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for '
                            'myProxyClientSSLKeyFile"; got %r' % type(val))
            
        if not os.access(val, os.R_OK):
            raise IOError('Error accessing "myProxyClientSSLKeyFile" file %r' % 
                          val)
            
        self.__myProxyClientSSLKeyFile = val
        
    @property      
    def myProxyClientSSLKeyFilePassphrase(self):
        return self.__myProxyClientSSLKeyFilePassphrase
    
    @myProxyClientSSLKeyFilePassphrase.setter
    def myProxyClientSSLKeyFilePassphrase(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for '
                            'myProxyClientSSLKeyFilePassphrase"; got %r' %
                            type(val))
            
        self.__myProxyClientSSLKeyFilePassphrase = val
    
    def initialise(self, app_conf, 
                   prefix=DEFAULT_PARAM_PREFIX,
                   myProxyClientPrefix=MYPROXY_CLIENT_PARAM_PREFIX,
                   **local_conf):
        """Parse dictionary of configuration items updating the relevant 
        attributes of this instance
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type myProxyClientPrefix: basestring
        @param myProxyClientPrefix: explicit prefix for MyProxyClient class 
        specific configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        super(MyProxyProvisionedSessionMiddleware, self).initialise(app_conf,
                                                                prefix=prefix,
                                                                **local_conf)
        
        # Sanity check
        if not isinstance(prefix, basestring):
            prefix = ''
            
        # Get MyProxyClient initialisation parameters
        myProxyClientFullPrefix = prefix + myProxyClientPrefix
                            
        myProxyClientKw = dict([(k.replace(myProxyClientFullPrefix, ''), v) 
                                 for k,v in app_conf.items() 
                                 if k.startswith(myProxyClientFullPrefix)])
        
        self.myProxyClient = MyProxyClient(**myProxyClientKw)
        
        for k in local_conf:
            paramName = k.replace(prefix, '', 1)
            if paramName in self.__class__.PARAM_NAMES:
                setattr(self, paramName, local_conf[k])
                             
    @classmethod
    def filter_app_factory(cls, app, app_conf, **kw):
        """Configure filter and associated SSL Context session middleware
        """
        _app = cls(app)
        _app.initialise(app_conf, **kw)
        
        # Set SSL Context middleware upstream from this app
        _app = SSLCtxSessionMiddleware.filter_app_factory(_app, app_conf, **kw)
        return _app
    
    @wsgify
    def __call__(self, request):
        '''
        @param request: WSGI request object
        @type request: WebOb.Request
        @return: WSGI response
        @rtype: iterable
        '''
        resp = super(MyProxyProvisionedSessionMiddleware, self).__call__(
                                                                        request)
        session = self.getSession(request)

        # if not certificate has been set or if it is present but expired,
        # renew        
        if (not self.__class__._is_cert_set(session) or 
            self._is_cert_expired(session)):
            self._refresh_credentials(request)
            
        return resp
    
    def _getMyProxyLogonCallCreds(self, request):
        """Get credentials for MyProxy logon.  Override to give custom behaviour
        @param request: WSGI request object
        @type request: WebOb.Request
        @rtype: tuple
        @return: two element tuple containing username and password to use with
        logon call to MyProxy.  None is set by default for the case where the
        client authenticates over SSL with a client certificate.
        """        
        return (request.environ.get('REMOTE_USER'), None)

    def _refresh_credentials(self, request):
        """Refresh credentials by making a MyProxy server logon request"""
        
        username, password = self._getMyProxyLogonCallCreds(request)
        try:
            credentials = self.__myProxyClient.logon(username, password,
                                     sslCertFile=self.myProxyClientSSLCertFile,
                                     sslKeyFile=self.myProxyClientSSLKeyFile)
                   
        except MyProxyClientError, e:
            raise httpexceptions.HTTPUnauthorized(str(e))
        
        except socket.error, e:
            raise MyProxyRetrievalSocketError("Socket error with MyProxy "
                                              "server %r: %s" % 
                                              (self.__myProxyClient.hostname,e))
        except Exception:
            raise MyProxyRetrievalError("MyProxyClient.logon raised an unknown "
                                        "exception calling %r: %s" %
                                        (self.__myProxyClient.hostname,
                                        traceback.format_exc()))
            
        session = self.getSession(request)
           
        # Get Context from session and update with credentials just retrieved
        sslCtx = session[self.ctxSessionKeyName]
        
        # The first element is the certificate, the second the private key,
        # the remainder, any associated certificate chain  
        session['certs'] = [credentials[0]]
        session['privateKey'] = credentials[1]
        
        clientCert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                             credentials[0])
        
        if log.getEffectiveLevel() <= logging.DEBUG:
            log.debug('Got certificate with subject %r for user %r',
                      clientCert.get_subject(), username)
            
        clientKey = crypto.load_privatekey(crypto.FILETYPE_PEM, credentials[1])
        sslCtx.use_certificate(clientCert)
        sslCtx.use_privatekey(clientKey)
        
        if len(credentials) > 2:
            session['certs'].extend(credentials[2:])
            for chainCertStr in credentials[2:]:
                chainCert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                                    chainCertStr)
                
                if log.getEffectiveLevel() <= logging.DEBUG:
                    log.debug('Associated certificate in chain with subject %r '
                              'for user %r',
                              chainCert.get_subject(), username)
                    
                sslCtx.add_extra_chain_cert(chainCert)
    
    @classmethod
    def _is_cert_set(self, session): 
        return len(session.get('certs', [])) > 0 
              
    def _is_cert_expired(self, session):
        '''Check if input certificate has expired
        @param session: session
        @type session: beaker.session
        @return: true if expired, false otherwise
        @rtype: bool
        '''
        cert = session['certs'][0]
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        notAfter = x509.get_notAfter()
        dtNotAfter = datetime.strptime(notAfter, '%Y%m%d%H%M%S%fZ')       
        dtNow = datetime.utcNow()
        
        return dtNotAfter < dtNow - self.certExpiryOffset


class NDGSecurityProxy(Proxy):
    """Extend paste.proxy.Proxy to enable an SSL context to be set with client
    certificate and key from a user session
    """
    def __init__(self, address, **kw):
        super(NDGSecurityProxy, self).__init__(address, **kw)

        self.__environSessionKeyName = \
            MyProxyProvisionedSessionMiddleware.DEFAULT_ENVIRON_SESSION_KEYNAME
            
        self.__ctxSessionKeyName = \
            MyProxyProvisionedSessionMiddleware.DEFAULT_CTX_SESSION_KEYNAME
                    
    def __call__(self, environ, start_response):
        if (self.allowed_request_methods and 
            environ['REQUEST_METHOD'
                    ].lower() not in self.allowed_request_methods):
            disallowedRequest = httpexceptions.HTTPBadRequest("Disallowed")
            return disallowedRequest(environ, start_response)

        if not self.__environSessionKeyName:
            sslCtx = None
        else:
            session = environ.get(self.__environSessionKeyName)
            if session is None:
                msg = "No session in environ"
                http500Error = httpexceptions.HTTPInternalServerError(msg)
                return http500Error(environ, start_response)
            
            sslCtx = session[self.__ctxSessionKeyName]

        if self.scheme == 'http':
            conn = httplib.HTTPConnection(self.host)
        elif self.scheme == 'https':
            conn = pyopenssl.HTTPSConnection(self.host, ssl_context=sslCtx)
        else:
            raise ValueError(
                "Unknown scheme for %r: %r" % (self.address, self.scheme))
        
        headers = {}
        for key, value in environ.items():
            if key.startswith('HTTP_'):
                key = key[5:].lower().replace('_', '-')
                if key == 'host' or key in self.suppress_http_headers:
                    continue
                headers[key] = value
        headers['host'] = self.host
        if 'REMOTE_ADDR' in environ:
            headers['x-forwarded-for'] = environ['REMOTE_ADDR']
        if environ.get('CONTENT_TYPE'):
            headers['content-type'] = environ['CONTENT_TYPE']
        if environ.get('CONTENT_LENGTH'):
            if environ['CONTENT_LENGTH'] == '-1':
                # This is a special case, where the content length is basically undetermined
                body = environ['wsgi.input'].read(-1)
                headers['content-length'] = str(len(body))
            else:
                headers['content-length'] = environ['CONTENT_LENGTH'] 
                length = int(environ['CONTENT_LENGTH'])
                body = environ['wsgi.input'].read(length)
        else:
            body = ''
            
        path_info = urllib.quote(environ['PATH_INFO'])
        if self.path:            
            request_path = path_info
            if request_path and request_path[0] == '/':
                request_path = request_path[1:]
                
            path = urlparse.urljoin(self.path, request_path)
        else:
            path = path_info
        if environ.get('QUERY_STRING'):
            path += '?' + environ['QUERY_STRING']
            
        conn.request(environ['REQUEST_METHOD'],
                     path,
                     body, headers)
        res = conn.getresponse()
        headers_out = parse_headers(res.msg)
                
        # Handle a security redirect - if not handled it returns None and the
        # original response is returned
        redirectRes = self._handleSecuredRedirect(res.status, 
                                                  environ['REQUEST_METHOD'],
                                                  body,
                                                  headers_out,
                                                  path,
                                                  sslCtx)
        if redirectRes is None:
            _res = res
        else:
            _res = redirectRes  
            
        status = '%s %s' % (_res.status, _res.reason)        
        start_response(status, headers_out)
        # @@: Default?
        length = _res.getheader('content-length')
        if length is not None:
            body = _res.read(int(length))
        else:
            body = _res.read()
        conn.close()
        return [body]

    def _handleSecuredRedirect(self, status, action, body, headers_out, path, 
                               sslCtx):
        '''Intercept security challenges - these are inferred by checking for a
        302 response with a location header requesting a HTTPS endpoint
        '''
        if status != httplib.FOUND:
            return
        
        # Get redirect location
        authnRedirectURI = None
        for k, v in headers_out:
            if k == 'Location':
                authnRedirectURI = v
                break
            
        if authnRedirectURI is None:
            log.error('No redirect location set for %r response from %r',
                                                        httplib.FOUND, path)
            # Let client decide what to do with this response
            return 
        
        # Check the scheme and only apply the redirect here if it HTTPS
        parsedAuthnRedirectURI = urlparse.urlparse(authnRedirectURI)
        if parsedAuthnRedirectURI.scheme != 'https':
            return
        
        host, portStr = parsedAuthnRedirectURI.netloc.split(':', 1)
        port = int(portStr)
        redirectPath = self.__class__._makeUriPath(parsedAuthnRedirectURI)
        
        # Redirect to authentication endpoint uses GET method
        conn = pyopenssl.HTTPSConnection(host, port=port, ssl_context=sslCtx)
        conn.request('GET', redirectPath)
        res = conn.getresponse()
        authnRedirectHeaders = parse_headers(res.msg)
                
        if res.status == httplib.FOUND:
            # Get redirect location
            returnURI = None
            cookies = []
            for k, v in authnRedirectHeaders:
                if k == 'Location':
                    returnURI = v
                
                if k == 'Set-cookie':
                    cookies.append(v)
                
            if returnURI is None:
                log.error('No redirect location set for %r response from %r',
                                            httplib.FOUND, authnRedirectURI)
                # Return the response and let the client decide what to do with
                # it
                return res
            
            # Check URI for HTTP scheme
            parsedReturnURI = urlparse.urlparse(returnURI)
            if parsedReturnURI.scheme != 'http':
                # Expecting http - don't process but instead return to client
                log.error('Return URI %r is not HTTP, passing back original '
                          'response', returnURI)
                return
            
            # Make path
            returnUriPath = self.__class__._makeUriPath(parsedReturnURI)
            
            # Add any cookies to header
            cookieHeaders = [('Set-cookie', i) for i in cookies]
            returnUriHeaders = dict(headers_out + cookieHeaders)
            
            # Get host and port number
            returnUriHost, returnUriPortStr = parsedReturnURI.netloc.split(':', 
                                                                           1)
            returnUriPort = int(returnUriPortStr)
                    
            # Invoke return URI passing headers            
            conn = httplib.HTTPConnection(returnUriHost, port=returnUriPort)
            conn.request(action, returnUriPath, body, returnUriHeaders)
            returnUriRes = conn.getresponse()
            return returnUriRes
        else:
            return res
    
    @staticmethod
    def _makeUriPath(parsedUri):
        '''Make a URI path from path, query argument and fragment components
        of a parsed uri object
        
        @param parsedUri: parsed URI from which to make the path
        @type parsedUri: ParsedResult
        @rtype: string
        @return URI path
        '''
        path = parsedUri.path
        if parsedUri.query:
            path += '?' + parsedUri.query
        
        if parsedUri.fragment:
            path += '#' + parsedUri.fragment
            
        return path
       