"""PyDAP client extension to support SSL based authentication with redirects
devised for the Earth System Grid project
"""
__author__ = "P J Kershaw"
__date__ = "11/05/10"
__copyright__ = ""
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:$'
import re
import urllib2
import logging
log = logging.getLogger(__name__)

from M2Crypto import SSL, m2urllib2
from pydap.exceptions import ClientError


class DapClient(object):
    """PyDAP client extended to support SSL based authentication with redirects
    devised for the Earth System Grid project
    """
    def __init__(self, certfile, keyfile=None):
        """Set up an SSL Context based on the certificate and key file passed
        """
        ctx = self.secure_init(certfile, keyfile)
        opener = m2urllib2.build_opener(ctx, urllib2.HTTPCookieProcessor())
        urllib2.install_opener(opener)
        
        self.install_ndg_client(certfile, keyfile)
        
    def secure_init(self, certfile, keyfile=None):
        # keyfile assumed to be the same as certfile if it's omitted
        if keyfile is None:
            keyfile = certfile
            
        ctx = SSL.Context('sslv3')
        ctx.load_cert(certfile=certfile, keyfile=keyfile)
        return ctx

    def install_ndg_client(self, certfile, keyfile=None):
        '''Override PyDAP default HTTP request function'''
        
        def _request(url):
            log.info('Opening [%s] ...' % url)
                       
            response = urllib2.urlopen(url)
            responseDict = response.headers.dict
            data = response.read()
    
            # When an error is returned, we parse the error message from the
            # server and return it in a ``ClientError`` exception.
            if responseDict.get("content-description") == "dods_error":
                m = re.search('code = (?P<code>\d+);\s*message = "(?P<msg>.*)"',
                        data, re.DOTALL | re.MULTILINE)
                msg = 'Server error %(code)s: "%(msg)s"' % m.groupdict()
                raise ClientError(msg)
            
            responseDict['status'] = str(response.code)
    
            return responseDict, data
    
        from pydap.util import http
        http.request = _request
        self._request = _request
        
    def open_url(self, url):
        '''Wrap PyDAP open_url function as a method to this class ensuring that
        it is called with the altered version of pydap.util.http.request set in
        __init__
        '''
        import pydap.client
        pydap.client.request = self._request
        return pydap.client.open_url(url)


