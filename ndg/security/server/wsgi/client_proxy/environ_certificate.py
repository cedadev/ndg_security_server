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
import httplib
import urllib
import urllib2
import urlparse

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
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "certEnvKeyName" '
                            'attribute; got %r' % type(val))
        self.__certEnvKeyName = val

    @property
    def ctxEnvKeyName(self):
        return self.__ctxEnvKeyName

    @ctxEnvKeyName.setter
    def ctxEnvKeyName(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "ctxEnvKeyName" '
                            'attribute; got %r' % type(val))
        self.__ctxEnvKeyName = val

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

    @property
    def verifyPeer(self):
        return self.__verifyPeer

    @verifyPeer.setter
    def verifyPeer(self, val):
        if not isinstance(val, basestring):
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

        environ[self.ctxEnvKeyName] = ctx


class NDGSecurityProxyMiddleware(object):
    """Middleware to call NDGSecurityProxy if a request is not for the local
    host and port.
    """
    DEFAULT_CTX_ENV_KEYNAME = "ssl_ctx"
    DEFAULT_PARAM_PREFIX = 'ndg_security_proxy.'
    DEFAULT_PASTE_PROXY_PARAM_PREFIX = 'proxy.'

    PARAM_NAMES = (
        'ctxEnvKeyName',
        'localAddresses'
    )
    __slots__ = (
        '_app',
        '__fqdn',
        '__local_address_components',
        '__proxy'
    )
    __slots__ += tuple(['__' + i for i in PARAM_NAMES])
    del i

    def __init__(self, app):
        self._app = app
        self.__fqdn = socket.getfqdn()
        self.__localAddresses = None
        self.__local_address_components = None
        self.__proxy = None
        self.__ctxEnvKeyName = \
            self.__class__.DEFAULT_CTX_ENV_KEYNAME

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
        if not isinstance(prefix, basestring):
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
            self.__local_address_components = []
            for addr in [h.strip() for h in self.__localAddresses.split(',')]:
                parts = addr.partition(':')
                self.__local_address_components.append(
                    (parts[0], parts[2] if len(parts) >= 3 else None))
        self.__proxy = NDGSecurityProxy()

    @property
    def ctxEnvKeyName(self):
        return self.__ctxEnvKeyName

    @ctxEnvKeyName.setter
    def ctxEnvKeyName(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "ctxEnvKeyName" '
                            'attribute; got %r' % type(val))
        self.__ctxEnvKeyName = val

    @property
    def localAddresses(self):
        return self.__localAddresses

    @localAddresses.setter
    def localAddresses(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "localAddresses" '
                            'attribute; got %r' % type(val))
        self.__localAddresses = val

    @classmethod
    def filter_app_factory(cls, app, app_conf, **kw):
        """Configure filter.
        """
        _app = cls(app)
        _app.initialise(app_conf, **kw)

        return _app

    @wsgify
    def __call__(self, request):
        if self._is_local_call(request):
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
        if self.__local_address_components:
            addresses =  self.__local_address_components
        else:
            server_port = request.server_port
            addresses = [(self.__fqdn, server_port)]

        request_host = request.host.partition(':')[0]
        request_fqdn = socket.gethostbyaddr(request_host)[0]
        request_port = request.host_port
        if not request_port:
            request_port = {'http': httplib.HTTP_PORT,
                            'https': httplib.HTTPS_PORT}.get(request.scheme)
        request_port = int(request_port)

        result = False
        for (server_host, server_port) in addresses:
            if not server_port:
                server_port = {'http': httplib.HTTP_PORT,
                               'https': httplib.HTTPS_PORT}.get(request.scheme)
            server_port = int(server_port)
            result = ((request_fqdn == server_host) and
                      (request_port == server_port))
            if result:
                break
        log.debug("Call for %s://%s:%s is %s", request.scheme, request_fqdn,
                  request_port, ("local" if result else "proxied"))
        return result

    def _get_ssl_context(self, request):
        """Retrieves the SSL context from the WSGI environ.
        @type request: WebOb.request
        @param request: request
        @rtype: OpenSSL ssl_context
        @return: SSL context
        """
        if self.__ctxEnvKeyName in request.environ:
            ssl_context = request.environ[self.__ctxEnvKeyName]
        else:
            raise httpexceptions.HTTPInternalServerError(
                'Expecting SSL context assigned to %r environ key' %
                self.__ctxEnvKeyName)
        return ssl_context


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
        '__ctxEnvKeyName'
    )

    def __init__(self):
        self.__ctxEnvKeyName = \
            self.__class__.DEFAULT_CTX_ENV_KEYNAME

    @property
    def ctxEnvKeyName(self):
        return self.__ctxEnvKeyName

    @ctxEnvKeyName.setter
    def ctxEnvKeyName(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "ctxEnvKeyName" '
                            'attribute; got %r' % type(val))
        self.__ctxEnvKeyName = val

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

        scheme = environ['wsgi.url_scheme']
        host = environ['HTTP_HOST']

        headers = {}
        for key, value in environ.items():
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

        path = (environ.get('SCRIPT_NAME', '')
                + environ.get('PATH_INFO', ''))
        path = urllib.quote(path)
        query = environ.get('QUERY_STRING', None)

        url = urlparse.urlunsplit((scheme, host, path, query, None))
        request = urllib2.Request(url, headers=headers)
        config = httpsclientutils.Configuration(sslCtx, True)
        (return_code, return_message, response) = httpsclientutils.open_url(
                                                                request, config)
        status = '%s %s' % (return_code, return_message)

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
