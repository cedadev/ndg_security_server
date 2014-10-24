"""Middleware for NDG Security attribute request for client
"""
__author__ = "R B Wilkinson"
__date__ = "27/04/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging
import urlparse

import ndg.httpsclient.utils as httpsclient_utils
import ndg.httpsclient.ssl_context_util as  ssl_context_util
from ndg.saml.saml2.binding.soap.client.attributequery import (
                                                AttributeQuerySslSOAPBinding,)
from ndg.saml.xml.etree import ResponseElementTree
from ndg.security.common.config import importElementTree
ElementTree = importElementTree()
from ndg.security.common.saml_utils.esgf import ESGFDefaultQueryAttributes
from ndg.security.common.utils.etree import prettyPrint
from ndg.security.server.wsgi import NDGSecurityMiddlewareBase

log = logging.getLogger(__name__)

class AttributeRequestMiddleware(NDGSecurityMiddlewareBase):
    """Makes an attribute request to obtain ESG attributes corresponding to the
    username stored in the environ.
    """
    DEFAULT_PARAM_PREFIX = 'attr_req.'
    ATTRIBUTE_QUERY_PARAMS_PREFIX = 'attributeQuery.'
    ATTRIBUTE_NAME_MAP = {
        'urn:esg:first:name': 'firstname',
        'urn:esg:last:name': 'lastname',
        'urn:esg:email:address': 'email'
    }
    # Key in environ for session
    SESSION_KEY_OPTION_DEFAULT = 'beaker.session.ndg.security'
    # Key in session for attribute dict
    SESSION_ATTRIBUTE_KEY_OPTION_DEFAULT = 'openid.ax'
    # Constants for parsing XDRS document
    XRDS_NS = 'xri://$xrd*($v*2.0)'
    XRDS_SERVICE_PATH = ('{%s}XRD/{%s}Service' % (XRDS_NS, XRDS_NS))
    XRDS_TYPE_PATH = ('{%s}Type' % XRDS_NS)
    XRDS_URI_PATH = ('{%s}URI' % XRDS_NS)
    XRDS_ATTRIBUTE_SERVICE_TYPE = 'urn:esg:security:attribute-service'
    
    PARAM_NAMES = (
        'attributeServiceUrl',
        'sslCACertDir',
        'sslCertFilePath',
        'sslPriKeyFilePath',
        'sessionAttributeKey',
        'sessionKey'
    )

    __slots__ = (
        '_app',
        '_attributeQueryClient',
        '_httpsClientConfig'
    )

    __slots__ += tuple(['__' + i for i in PARAM_NAMES])
    del i

    def __init__(self, app):
        self._app = app

        self.__attributeServiceUrl = None
        self.__sessionAttributeKey = self.__class__.SESSION_ATTRIBUTE_KEY_OPTION_DEFAULT
        self.__sessionKey = self.__class__.SESSION_KEY_OPTION_DEFAULT

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
        if prefix is None:
            prefix = ''
        prefixLength = len(prefix)
        queryPrefix = prefix + self.__class__.ATTRIBUTE_QUERY_PARAMS_PREFIX
        queryPrefixLength = len(queryPrefix)
        for k in local_conf:
            # SSL parameters apply to this class and to the attribute query
            # client.
            if k.startswith(queryPrefix):
                paramName = k[queryPrefixLength:]
            elif k.startswith(prefix):
                paramName = k[prefixLength:]

            if paramName in AttributeRequestMiddleware.PARAM_NAMES:
                setattr(self, paramName, local_conf[k])

        self._attributeQueryClient = AttributeQuerySslSOAPBinding()

        # Parse authorisation decision query options
        self._attributeQueryClient.parseKeywords(prefix=queryPrefix,
                                                 **local_conf)

        sslContext = ssl_context_util.make_ssl_context(self.sslPriKeyFilePath,
                                                       self.sslCertFilePath,
                                                       None,
                                                       self.sslCACertDir,
                                                       verify_peer=True)
        self._httpsClientConfig = httpsclient_utils.Configuration(sslContext,
                                                                  False)

    @classmethod
    def filter_app_factory(cls, app, app_conf, **kw):
        obj = cls(app)
        obj.initialise(app_conf, **kw)
        return obj

    def __call__(self, environ, start_response):
        """Checks whether the attributes are stored in the session and if not
        makes an attribute request.
        """
        # Get session.
        session = environ.get(self.sessionKey)
        if session is None:
            raise Exception(
                'AttributeRequestMiddleware.__call__: No beaker session key '
                '"%s" found in environ' % self.sessionKey)

        username = environ.get(self.__class__.USERNAME_ENVIRON_KEYNAME)
        log.debug("Found username: %s", username)
        if (username and (self.sessionAttributeKey not in session)):
            attributes = self._getAttributes(username)
            session[self.sessionAttributeKey] = attributes
            session.save()

        return self._app(environ, start_response)

    @staticmethod
    def _isHttpUrl(string):
        """Determines whether a string can be interpreted as a HTTP or HTTPS
        URL.
        @type string: basestring
        @param string: string to test
        @rtype: bool
        @return: True if string can be parsed as a URL with a scheme that is
        HTTP or HTTPS and at least a net location, otherwise False
        """
        parts = urlparse.urlsplit(string)
        return (parts.scheme in ['http', 'https']) and bool(parts.netloc)

    def _getAttributeService(self, subject):
        """
        @type subject: basestring
        @param subject: subject for which the query is to be made
        @rtype: basestring
        @return: URL of attribute service
        """
        if not self._isHttpUrl(subject):
            log.debug("Subject is not a HTTP URL - not making Yadis request to"
                      " obtain attribute service: %s", subject)
            return None
        try:
            log.debug("Making Yadis request to obtain attribute service for"
                      " subject %s", subject)
            xrdsStr = httpsclient_utils.fetch_from_url(subject,
                                                       self._httpsClientConfig)
        except Exception, exc:
            log.error(
                    "Unable to determine attribute service for subject %s: %s",
                    subject, exc.__str__())
            return None
        xrdsEl = ElementTree.XML(xrdsStr)
        for svcEl in xrdsEl.findall(self.__class__.XRDS_SERVICE_PATH):
            isAttrService = False
            for typeEl in svcEl.findall(self.__class__.XRDS_TYPE_PATH):
                if typeEl.text == self.__class__.XRDS_ATTRIBUTE_SERVICE_TYPE:
                    isAttrService = True
            if isAttrService:
                for uriEl in svcEl.findall(self.__class__.XRDS_URI_PATH):
                    attributeServiceUrl = uriEl.text
                    log.debug("Found attribute service URL: %s",
                              attributeServiceUrl)
                    return attributeServiceUrl
        return None

    def _getAttributes(self, subject):
        """Makes a query for the attributes and returns them.
        The attribute names used in the SAML query are mapped to keys to use in
        the session.
        @type subject: basestring
        @param subject: subject for which the query is to be made
        @rtype: dict of basestring
        @return: attribute names and values
        """
        attributeQuery = self._attributeQueryClient.makeQuery()
        if self.attributeServiceUrl:
            log.debug("Using configured attribute service URL; %s",
                      self.attributeServiceUrl)
            attributeServiceUrl = self.attributeServiceUrl
        else:
            attributeServiceUrl = self._getAttributeService(subject)

        self._attributeQueryClient.setQuerySubjectId(attributeQuery, subject)
        attributeQuery.attributes.extend(ESGFDefaultQueryAttributes.ATTRIBUTES)

        response = self._attributeQueryClient.send(attributeQuery,
                                                   uri=attributeServiceUrl)

        samlResponseElem = ResponseElementTree.toXML(response)

        if log.isEnabledFor(logging.DEBUG):
            log.debug("Pretty print SAML Response ...")
            log.debug(prettyPrint(samlResponseElem))
            # log.debug(ElementTree.tostring(samlResponseElem))

        returnValues = {}
        for assertion in response.assertions:
            for attrStmt in assertion.attributeStatements:
                for attr in attrStmt.attributes:
                    attrKey = self.__class__.ATTRIBUTE_NAME_MAP.get(attr.name)
                    if attrKey:
                        if len(attr.attributeValues) > 1:
                            value = []
                            for attrVal in attr.attributeValues:
                                value.append(attrVal.value)
                        else:
                            value = attr.attributeValues[0].value
                        returnValues[attrKey] = value
                        log.debug("Received attribute: %s = %s", attrKey, value)

        return returnValues

    @property
    def attributeServiceUrl(self):
        return self.__attributeServiceUrl

    @attributeServiceUrl.setter
    def attributeServiceUrl(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "attributeServiceUrl" '
                            'attribute; got %r' % type(val))

        self.__attributeServiceUrl = val

    @property
    def sslCACertDir(self):
        return self.__sslCACertDir

    @sslCACertDir.setter
    def sslCACertDir(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "sslCACertDir" '
                            'attribute; got %r' % type(val))

        self.__sslCACertDir = val

    @property
    def sslCertFilePath(self):
        return self.__sslCertFilePath

    @sslCertFilePath.setter
    def sslCertFilePath(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "sslCertFilePath" '
                            'attribute; got %r' % type(val))

        self.__sslCertFilePath = val

    @property
    def sslPriKeyFilePath(self):
        return self.__sslPriKeyFilePath

    @sslPriKeyFilePath.setter
    def sslPriKeyFilePath(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "sslPriKeyFilePath" '
                            'attribute; got %r' % type(val))

        self.__sslPriKeyFilePath = val

    @property
    def sessionAttributeKey(self):
        return self.__sessionAttributeKey

    @sessionAttributeKey.setter
    def sessionAttributeKey(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "sessionAttributeKey" '
                            'attribute; got %r' % type(val))

        self.__sessionAttributeKey = val

    @property
    def sessionKey(self):
        return self.__sessionKey

    @sessionKey.setter
    def sessionKey(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting string type for "sessionKey" '
                            'attribute; got %r' % type(val))

        self.__sessionKey = val
