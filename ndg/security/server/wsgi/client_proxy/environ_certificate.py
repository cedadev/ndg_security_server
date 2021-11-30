"""Middleware for NDG Security HTTP Proxy using a SSL certificate/key stored in
the WSGI environ
"""
__author__ = "P J Kershaw"
__date__ = "21/12/10"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: middleware.py 7932 2011-08-23 09:21:12Z pjkersha $"
import logging
log = logging.getLogger(__name__)

import socket
import http.client
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import urllib.parse

from paste import httpexceptions
from paste.proxy import parse_headers
from webob.dec import wsgify
from OpenSSL import SSL, crypto

import ndg.httpsclient.utils as httpsclientutils
from ndg.security.server.wsgi.utils import FileObjResponseIterator


class SSLCtxEnvironMiddleware(object):
    """Stores an SSL Context object in the environ for client callouts.
    The context includes a key and certificate stored as a tuple in the environ
    with the key set by the certEnvKeyName parameter.
    """
    PARAM_NAMES = (
        'certEnvKeyName',
        'ctxEnvKeyName',
        'caCertFilePath',
        'caCertDir',
        'verifyPeer')

    __slots__ = (
        '_app',
    )

    __slots__ += tuple(['__' + i for i in PARAM_NAMES])
    del i
    DEFAULT_CTX_ENV_KEYNAME = "ssl_ctx"
    DEFAULT_PARAM_PREFIX = 'ssl_ctx.'

    '''@param SSL_VERSION: SSL version for context object
    @type SSL_VERSION: string'''
    SSL_VERSION = SSL.SSLv3_METHOD

    def __init__(self, app):
        self._app = app

        self.__ctxEnvKeyName = \
            self.__class__.DEFAULT_CTX_ENV_KEYNAME

        self.__caCertFilePath = None
        self.__caCertDir = None
        self.__certEnvKeyName = None
        self.__verifyPeer = True

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
            if prefix and k.startswith(prefix):
                paramName = k[len(prefix):]
            else:
                paramName = k

            if paramName in SSLCtxEnvironMiddleware.PARAM_NAMES:
                setattr(self, paramName, local_conf[k])

    @classmethod
    def filter_app_factory(cls, app, app_conf, **kw):
        obj = cls(app)
        obj.initialise(app_conf, **kw)
        return obj

    def __call__(self, environ, start_response):
        self._create_ssl_ctx(environ)
        return self._app(environ, start_response)

    @property
    def certEnvKeyName(self):
        return self.__certEnvKeyName
 
    @certEnvKeyName.setter
    def certEnvKeyName(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "certEnvKeyName" '
                            'attribute; got %r' % type(val))
        self.__certEnvKeyName = val

    @property
    def ctxEnvKeyName(self):
        return self.__ctxEnvKeyName

    @ctxEnvKeyName.setter
    def ctxEnvKeyName(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "ctxEnvKeyName" '
                            'attribute; got %r' % type(val))
        self.__ctxEnvKeyName = val

    @property
    def caCertFilePath(self):
        return self.__caCertFilePath

    @caCertFilePath.setter
    def caCertFilePath(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "caCertFilePath" '
                            'attribute; got %r' % type(val))

        self.__caCertFilePath = val

    @property
    def caCertDir(self):
        return self.__caCertDir

    @caCertDir.setter
    def caCertDir(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "caCertDir" '
                            'attribute; got %r' % type(val))

        self.__caCertDir = val

    @property
    def verifyPeer(self):
        return self.__verifyPeer

    @verifyPeer.setter
    def verifyPeer(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "caCertDir" '
                            'attribute; got %r' % type(val))

        if val.lower() == 'true':
            self.__verifyPeer = True
        elif val.lower() == 'false':
            self.__verifyPeer = False
        else:
            raise ValueError('Expecting boolean string value for verifyPeer: '
                             'got %s' % val)

    def _create_ssl_ctx(self, environ):
        """Create SSL Context object"""
        ctx = SSL.Context(self.__class__.SSL_VERSION)

        def _callback(conn, x509, errnum, errdepth, ok):
            return ok

        if self.verifyPeer:
            ctx.set_verify(SSL.VERIFY_PEER, _callback)
            ctx.set_verify_depth(9)
        else:
            ctx.set_verify(SSL.VERIFY_NONE, _callback)
        if self.caCertFilePath or self.caCertDir:
            ctx.load_verify_locations(self.caCertFilePath, self.caCertDir)

        if self.certEnvKeyName in environ:
            # Get certificate and key that have been set in the environ by
            # upstream middleware.
            try:
                credentials = environ.get(self.certEnvKeyName)
    
                clientKey = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                                   credentials[0])
                clientCert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                                     credentials[1])
    
                if log.getEffectiveLevel() <= logging.DEBUG:
                    log.debug('Got certificate with subject %r',
                              clientCert.get_subject())
    
                ctx.use_privatekey(clientKey)
                ctx.use_certificate(clientCert)
            except Exception as exc:
                log.error("Exception setting certificate in environ: %s",
                          exc.__str__())

        environ[self.ctxEnvKeyName] = ctx


class CertificateSubjectEnvironMiddleware(object):
    """Retrieves a certificate from the WSGI environ and sets its common name as
    the authenticated user in the environ.
    """
    PARAM_NAMES = (
        'certEnvKeyName',
        'remoteUserEnvKeyName')

    __slots__ = (
        '_app',
    )

    __slots__ += tuple(['__' + i for i in PARAM_NAMES])
    del i
    DEFAULT_PARAM_PREFIX = 'cert_subject.'
    DEFAULT_REMOTE_USER_ENV_KEYNAME = 'REMOTE_USER'

    '''@param SSL_VERSION: SSL version for context object
    @type SSL_VERSION: string'''
    SSL_VERSION = SSL.SSLv3_METHOD

    def __init__(self, app):
        self._app = app

        self.__certEnvKeyName = None
        self.__remoteUserEnvKeyName = \
            self.__class__.DEFAULT_REMOTE_USER_ENV_KEYNAME

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
            if prefix and k.startswith(prefix):
                paramName = k[len(prefix):]
            else:
                paramName = k

            if paramName in CertificateSubjectEnvironMiddleware.PARAM_NAMES:
                setattr(self, paramName, local_conf[k])

    @classmethod
    def filter_app_factory(cls, app, app_conf, **kw):
        obj = cls(app)
        obj.initialise(app_conf, **kw)
        return obj

    def __call__(self, environ, start_response):
        self._set_subject(environ)
        return self._app(environ, start_response)

    @property
    def certEnvKeyName(self):
        return self.__certEnvKeyName
 
    @certEnvKeyName.setter
    def certEnvKeyName(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "certEnvKeyName" '
                            'attribute; got %r' % type(val))
        self.__certEnvKeyName = val

    @property
    def remoteUserEnvKeyName(self):
        return self.__remoteUserEnvKeyName
 
    @remoteUserEnvKeyName.setter
    def remoteUserEnvKeyName(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "remoteUserEnvKeyName" '
                            'attribute; got %r' % type(val))
        self.__remoteUserEnvKeyName = val

    def _set_subject(self, environ):
        """Sets the certificate subject common name as the remote user in the
        environ.
        """
        if self.certEnvKeyName in environ:
            # Get certificate that has been set in the environ by upstream
            # middleware.
            credentials = environ.get(self.certEnvKeyName)

            clientCert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                                 credentials[1])
            subject = clientCert.get_subject()
            if log.getEffectiveLevel() <= logging.DEBUG:
                log.debug('Got certificate with subject %r', subject)
            commonName = subject.commonName
            if commonName:
                environ[self.remoteUserEnvKeyName] = commonName
                log.debug('Set common name in environ: %r', commonName)
            else:
                log.debug("Distinguished name contains no common name")


class NDGSecurityProxyMiddleware(object):
    """Middleware to call NDGSecurityProxy if a request is not for the local
    host and port.
    One of two methods can be used to determine whether a request is to be
    handled locally or redirected through the proxy:
    If the configuration parameter ndg_security_proxy.proxyPrefix is set,
    requests that should be proxied should have URLs of the form:
    http://<proxy host>/<proxy prefix>/<target scheme>/<target host>/<target port>/<target path>
    The request will be proxied to the target URL:
    <target scheme>://<target host>:<target port>/<target path>
    To use the default port for the scheme, set <target port> to '-'.
    If proxyPrefix is not set, the URL in the request will be compared to the
    local address to determine whether a request is to be proxied. In general,
    the configuration parameter ndg_security_proxy.localAddresses should be set
    to the fully qualified domain name of the host and port which this
    application stack is listening (or a comma separated list of FQDNs). When
    running the application with paste, the local address can be detected and
    this option need not be set.
    The environment variables http_proxy, https_proxy and no_proxy may be used
    to cause requests to be directed to this proxy. If an external proxy should
    be used for the outgoing requests made by this proxy, it should be
    configured using the configuration parameters:
    ndg_security_proxy.proxy.http_proxy, ndg_security_proxy.proxy.https_proxy
    and ndg_security_proxy.proxy.no_proxy.
    """
    DEFAULT_PARAM_PREFIX = 'ndg_security_proxy.'
    DEFAULT_PASTE_PROXY_PARAM_PREFIX = 'proxy.'

    PARAM_NAMES = (
        'localAddresses',
        'proxyPrefix'
    )
    __slots__ = (
        '_app',
        '__fqdn',
        '__localAddressComponents',
        '__proxy'
    )
    __slots__ += tuple(['__' + i for i in PARAM_NAMES])
    del i

    def __init__(self, app):
        self._app = app
        self.__fqdn = socket.getfqdn()
        self.__localAddresses = None
        self.__localAddressComponents = None
        self.__proxy = None
        self.__proxyPrefix = None

    def initialise(self, app_conf,
                   prefix=DEFAULT_PARAM_PREFIX,
                   pasteProxyPrefix=DEFAULT_PASTE_PROXY_PARAM_PREFIX,
                   **local_conf):
        """Parse dictionary of configuration items updating the relevant
        attributes of this instance

        @type app_conf: dict
        @param app_conf: PasteDeploy application specific configuration
        dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type pasteProxyPrefix: basestring
        @param pasteProxyPrefix: additional prefix for parameters configuring
        the proxy
        @type local_conf: dict
        @param local_conf: middleware configuration
        """
        # Sanity check
        if not isinstance(prefix, str):
            prefix = ''

        # Get proxy initialisation parameters
        proxyFullPrefix = prefix + pasteProxyPrefix
        proxyKw = {}

        for k in local_conf:
            if proxyFullPrefix and k.startswith(proxyFullPrefix):
                paramName = k[len(proxyFullPrefix):]
                proxyKw[paramName] = local_conf[k]
            else:
                if prefix and k.startswith(prefix):
                    paramName = k[len(prefix):]
                else:
                    paramName = k
                if paramName in self.__class__.PARAM_NAMES:
                    setattr(self, paramName, local_conf[k])
        if self.__localAddresses:
            self.__localAddressComponents = []
            for addr in [h.strip() for h in self.__localAddresses.split(',')]:
                parts = addr.partition(':')
                self.__localAddressComponents.append(
                    (parts[0], parts[2] if len(parts) >= 3 else None))
        if self.proxyPrefix:
            proxyKw['proxyPrefix'] = self.proxyPrefix
        self.__proxy = NDGSecurityProxy(**proxyKw)

    @property
    def localAddresses(self):
        return self.__localAddresses

    @localAddresses.setter
    def localAddresses(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "localAddresses" '
                            'attribute; got %r' % type(val))
        self.__localAddresses = val

    @property
    def proxyPrefix(self):
        return self.__proxyPrefix

    @proxyPrefix.setter
    def proxyPrefix(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "proxyPrefix" '
                            'attribute; got %r' % type(val))
        self.__proxyPrefix = val

    @classmethod
    def filter_app_factory(cls, app, app_conf, **kw):
        """Configure filter.
        """
        _app = cls(app)
        _app.initialise(app_conf, **kw)

        return _app

    @wsgify
    def __call__(self, request):
        if self.proxyPrefix:
            if self._is_local_call_by_prefix(request):
                return self._app
            else:
                # Proxy request
                return request.get_response(self.__proxy)
        elif self._is_local_call(request):
            return self._app
        else:
            # Proxy request
            return request.get_response(self.__proxy)

    def _is_local_call(self, request):
        """Determines whether a request is a call to the local server or a
        proxy request.
        @type request: WebOb.request
        @param request: request
        @rtype: bool
        @return: True if the request is one to the local server, otherwise False
        """
        if self.__localAddressComponents:
            addresses =  self.__localAddressComponents
        else:
            server_port = request.server_port
            addresses = [(self.__fqdn, server_port)]

        request_host_parts = request.host.partition(':')
        request_host = request_host_parts[0]
        request_fqdn = socket.gethostbyaddr(request_host)[0]
        if hasattr(request, 'host_port'):
            request_port = request.host_port
        elif len(request_host_parts) == 3:
            request_port = request_host_parts[2]
        else:
            request_port = None
        if not request_port:
            request_port = {'http': http.client.HTTP_PORT,
                            'https': http.client.HTTPS_PORT}.get(request.scheme)
        request_port = int(request_port)

        result = False
        for (server_host, server_port) in addresses:
            if not server_port:
                server_port = {'http': http.client.HTTP_PORT,
                               'https': http.client.HTTPS_PORT}.get(request.scheme)
            server_port = int(server_port)
            result = ((request_fqdn == server_host) and
                      (request_port == server_port))
            if result:
                break
        log.debug("Call for %s is %s", request.url,
                  ("local" if result else "proxied"))
        #log.debug("Call for %s://%s:%s is %s", request.scheme, request_fqdn,
        #          request_port, ("local" if result else "proxied"))
        return result

    def _is_local_call_by_prefix(self, request):
        """Determines whether a request is a call to the local server or a
        proxy request.
        @type request: WebOb.request
        @param request: request
        @rtype: bool
        @return: True if the request is one to the local server, otherwise False
        """
        path_components = request.path.split('/')
        if len(path_components) > 1 and not path_components[0]:
            path_components.pop(0)
        result = (path_components[0] != self.proxyPrefix)
        log.debug("Call for %s is %s", request.url,
                  ("local" if result else "proxied"))
        return result


class NDGSecurityProxy(object):
    """HTTP proxy that uses an SSL context taken from the WSGI environ for HTTPS
    requests. Note that the initial request should NOT normally be HTTPS since
    a client would normally attempt to use a HTTPS proxying method that requires
    the proxy to act as a tunnel for an SSL connection directly from client to
    target server. (A client that uses an HTTP-like proxying approach should be
    compatible.) The HTTPS context is used when a redirect occurs to a HTTPS URL
    for a security service.
    This is partly based on paste.proxy.TransparentProxy.
    """
    DEFAULT_CTX_ENV_KEYNAME = "ssl_ctx"
    __slots__ = (
        '__ctxEnvKeyName',
        '__http_proxy',
        '__https_proxy',
        '__no_proxy',
        '__proxies',
        '__proxyPrefix'
    )

    def __init__(self, ctxEnvKeyName=None, proxyPrefix=None,
                 http_proxy=None, https_proxy=None, no_proxy=None):
        self.__ctxEnvKeyName = (self.__class__.DEFAULT_CTX_ENV_KEYNAME
                                if ctxEnvKeyName is None else ctxEnvKeyName)
        self.__proxies = None
        self.__proxyPrefix = proxyPrefix
        self.http_proxy = http_proxy
        self.https_proxy = https_proxy
        self.no_proxy = no_proxy

    @property
    def ctxEnvKeyName(self):
        return self.__ctxEnvKeyName

    @ctxEnvKeyName.setter
    def ctxEnvKeyName(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "ctxEnvKeyName" '
                            'attribute; got %r' % type(val))
        self.__ctxEnvKeyName = val

    @property
    def proxyPrefix(self):
        return self.__proxyPrefix

    @proxyPrefix.setter
    def proxyPrefix(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "proxyPrefix" '
                            'attribute; got %r' % type(val))
        self.__proxyPrefix = val

    @property
    def http_proxy(self):
        return self.__http_proxy

    @http_proxy.setter
    def http_proxy(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "http_proxy" '
                            'attribute; got %r' % type(val))
        self.__http_proxy = val
        if self.__proxies is None:
            self.__proxies = {}
        self.__proxies['http'] = val

    @property
    def https_proxy(self):
        return self.__https_proxy

    @https_proxy.setter
    def https_proxy(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "https_proxy" '
                            'attribute; got %r' % type(val))
        self.__https_proxy = val
        if self.__proxies is None:
            self.__proxies = {}
        self.__proxies['https'] = val

    @property
    def no_proxy(self):
        return self.__no_proxy

    @no_proxy.setter
    def no_proxy(self, val):
        if not isinstance(val, str):
            raise TypeError('Expecting string type for "no_proxy" '
                            'attribute; got %r' % type(val))
        self.__no_proxy = val

    def __call__(self, environ, start_response):
        """Rerieves the SSL context from the environ and forwards the request to
        the target URL.
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: response from target URL
        """
        if not self.__ctxEnvKeyName:
            sslCtx = None
        else:
            sslCtx = environ.get(self.__ctxEnvKeyName)
            if sslCtx is None:
                msg = "No SSL context in environ"
                http500Error = httpexceptions.HTTPInternalServerError(msg)
                return http500Error(environ, start_response)

        original_path = (environ.get('SCRIPT_NAME', '')
                         + environ.get('PATH_INFO', ''))
        if self.proxyPrefix:
            path_components = original_path.lstrip('/').split('/', 4)
            if (len(path_components) < 4 or
                path_components[0] != self.proxyPrefix):
                http500Error = httpexceptions.HTTPInternalServerError(
                    'Proxy URL path is not of form '
                    '"/proxyPrefix/scheme/host/port/path"')
                return http500Error(environ, start_response)
            elif len(path_components) == 4:
                path_components[4] = ''
            path_components.pop(0)
            (scheme, host, port, path) = path_components
            # '-' denotes the default port.
            if port != '-':
                host = host + ':' + port
            path = urllib.parse.quote('/' + path)
        else:
            scheme = environ['wsgi.url_scheme']
            host = environ['HTTP_HOST']
            path = urllib.parse.quote(original_path)
        query = environ.get('QUERY_STRING', None)

        url = urllib.parse.urlunsplit((scheme, host, path, query, None))
        log.debug("Target URL: %s", url)

        headers = {}
        for key, value in list(environ.items()):
            if key.startswith('HTTP_'):
                key = key[5:].lower().replace('_', '-')
                headers[key] = value
        headers['host'] = host

        # From paste.proxy:TransparentProxy
        if 'REMOTE_ADDR' in environ and 'HTTP_X_FORWARDED_FOR' not in environ:
            headers['x-forwarded-for'] = environ['REMOTE_ADDR']

        if environ.get('CONTENT_TYPE'):
            headers['content-type'] = environ['CONTENT_TYPE']

        if environ.get('CONTENT_LENGTH'):
            if environ['CONTENT_LENGTH'] != '-1':
                headers['content-length'] = environ['CONTENT_LENGTH']

        request = urllib.request.Request(url, headers=headers)
        config = httpsclientutils.Configuration(sslCtx,
                                                log.isEnabledFor(logging.DEBUG),
                                                proxies=self.__proxies,
                                                no_proxy=self.no_proxy)
        log.debug("Making request to %s", url)
        (return_code, return_message, response) = httpsclientutils.open_url(
                                                                request, config)
        status = '%s %s' % (return_code, return_message)
        log.debug("Response status: %s", status)

        # Pass 401 status back to caller.
        if return_code == http.client.UNAUTHORIZED:
            start_response(http.client.UNAUTHORIZED, [])
            return []

        if not response:
            msg = "Security proxy returned status: %s" % status
            http500Error = httpexceptions.HTTPInternalServerError(msg)
            return http500Error(environ, start_response)

        headers_out = parse_headers(response.headers)

        start_response(status, headers_out)


        # Detach HTTPResponse from the urllib response otherwise the former will
        # be closed by the urllib response's __del__ method.
        httpresponse = response.fp._sock
        response.fp._sock = None
        responseIter = FileObjResponseIterator(httpresponse,
                file_size=int(httpresponse.getheader('content-length', '-1')))
        return responseIter
