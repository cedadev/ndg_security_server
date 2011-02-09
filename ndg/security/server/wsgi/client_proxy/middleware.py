'''
Created on 21 Dec 2010

@author: pjkersha
'''
from paste import httpexceptions
from paste.proxy import Proxy
from M2Crypto import httpslib, SSL

class NDGSecurityProxy(Proxy):
    """Extend paste.proxy.Proxy to enable an SSL context to be set with client
    certificate and key from a user session
    """
    def __init__(self, environ_session_keyname, *arg, **kw):
        super(NDGSecurityProxy, self).__init__(*arg, **kw)
        self.environ_session_keyname = environ_session_keyname
        
    def __call__(self, environ, start_response):
        if (self.allowed_request_methods and 
            environ['REQUEST_METHOD'].lower() not in self.allowed_request_methods):
            return httpexceptions.HTTPBadRequest("Disallowed")(environ, start_response)

        if not self.environ_session_keyname:
            sslCtx = None
        else:
            session = environ.get(self.environ_session_keyname)
            if session is None:
                return httpexceptions.HTTPInternalServerError(
                            "No session in environ")(environ, start_response)
            keyPasswd = None
            certChain              
            sslCtx = SSL.Context()
            sslCtx.load_cert_chain(certchainfile, keyfile=None, 
                                   callback=lambda *arg, **kw: keyPasswd)
            
        if self.scheme == 'http':
            conn = httplib.HTTPConnection(self.host)
        elif self.scheme == 'https':
            conn = httpslib.HTTPSConnection(self.host, ssl_context=sslCtx)
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
        
        status = '%s %s' % (res.status, res.reason)
        start_response(status, headers_out)
        # @@: Default?
        length = res.getheader('content-length')
        if length is not None:
            body = res.read(int(length))
        else:
            body = res.read()
        conn.close()
        return [body]
