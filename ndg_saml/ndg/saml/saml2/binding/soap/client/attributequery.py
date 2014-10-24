"""SAML 2.0 client bindings module implements SOAP binding for attribute query

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/09/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import re
import logging
log = logging.getLogger(__name__)

from M2Crypto.m2urllib2 import HTTPSHandler

from ndg.saml.saml2.core import Attribute, AttributeQuery

from ndg.saml.utils import TypedList
from ndg.saml.saml2.binding.soap.client.subjectquery import (
                                                    SubjectQuerySOAPBinding,
                                                    SubjectQueryResponseError)

# Prevent whole module breaking if this is not available - it's only needed for
# AttributeQuerySslSOAPBinding
try:
    from ndg.saml.utils.m2crypto import SSLContextProxy
    _sslContextProxySupport = True
    
except ImportError:
    _sslContextProxySupport = False


class AttributeQueryResponseError(SubjectQueryResponseError):
    """SAML Response error from Attribute Query"""
    

class AttributeQuerySOAPBinding(SubjectQuerySOAPBinding): 
    """SAML Attribute Query SOAP Binding
    """
    QUERY_ATTRIBUTES_ATTRNAME = 'queryAttributes'
    LEN_QUERY_ATTRIBUTES_ATTRNAME = len(QUERY_ATTRIBUTES_ATTRNAME)
    QUERY_ATTRIBUTES_PAT = re.compile(',\s*')
    
    __PRIVATE_ATTR_PREFIX = "__"
    __slots__ = ('__attributes',)

    SERIALISE_KW = 'serialise'
    DESERIALISE_KW = 'deserialise'
    QUERY_TYPE = AttributeQuery
    
    def __init__(self, **kw):
        '''Create SOAP Client for SAML Attribute Query'''
        
        # Default to ElementTree based serialisation/deserialisation
        if AttributeQuerySOAPBinding.SERIALISE_KW not in kw:
            from ndg.saml.xml.etree import AttributeQueryElementTree
            kw[AttributeQuerySOAPBinding.SERIALISE_KW
               ] = AttributeQueryElementTree.toXML
               
        if AttributeQuerySOAPBinding.DESERIALISE_KW not in kw:
            from ndg.saml.xml.etree import ResponseElementTree
            kw[AttributeQuerySOAPBinding.DESERIALISE_KW
               ] = ResponseElementTree.fromXML

        self.__attributes = TypedList(Attribute)

        super(AttributeQuerySOAPBinding, self).__init__(**kw)
            
    def addQueryAttributes(self, query):
        """Adds to a query attributes that are configured for
        SubjectQuerySOAPBinding.
        """
        super(AttributeQuerySOAPBinding, self).addQueryAttributes(query)
        # Initialise the query attributes from those preset.
        query.attributes = TypedList(Attribute)
        query.attributes.extend(self.queryAttributes)

    def __setattr__(self, name, value):
        """Enable setting of SAML query attribute objects via a comma separated
        string suitable for use reading from an ini file.  
        """
        try:
            super(AttributeQuerySOAPBinding, self).__setattr__(name, value)
            
        except AttributeError:
            if name.startswith(
                        AttributeQuerySOAPBinding.QUERY_ATTRIBUTES_ATTRNAME):
                # Special handler for parsing string format settings
                if not isinstance(value, basestring):
                    raise TypeError('Expecting string format for special '
                                    '%r attribute; got %r instead' %
                                    (name, type(value)))
                    
                pat = AttributeQuerySOAPBinding.QUERY_ATTRIBUTES_PAT
                attribute = Attribute()
                
                (attribute.name, 
                 attribute.friendlyName, 
                 attribute.nameFormat) = pat.split(value)
                 
                self.queryAttributes.append(attribute)
            else:
                raise
             
    def _getQueryAttributes(self):
        return self.__attributes

    def _setQueryAttributes(self, value):
        if not isinstance(value, TypedList) and value.elementType != Attribute:
            raise TypeError('Expecting TypedList(Attribute) type for '
                            '"queryAttributes"; got %r instead' % type(value))
        
        # Remove all previously set items and add new ones 
        del self.__attributes[:]
        for attribute in value:
            self.__attributes.append(attribute)
  
    queryAttributes = property(_getQueryAttributes, 
                               _setQueryAttributes, 
                               doc="List of attributes to query from the "
                                   "Attribute Authority")

    
class AttributeQuerySslSOAPBinding(AttributeQuerySOAPBinding):
    """Specialisation of AttributeQuerySOAPbinding taking in the setting of
    SSL parameters for mutual authentication
    """
    SSL_CONTEXT_PROXY_SUPPORT = _sslContextProxySupport
    __slots__ = ('__sslCtxProxy',)
    
    def __init__(self, **kw):
        if not AttributeQuerySslSOAPBinding.SSL_CONTEXT_PROXY_SUPPORT:
            raise ImportError("ndg.saml.utils.m2crypto import "
                              "failed - missing M2Crypto package?")
        
        # Miss out default HTTPSHandler and set in send() instead
        if 'handlers' in kw:
            raise TypeError("__init__() got an unexpected keyword argument "
                            "'handlers'")
            
        super(AttributeQuerySslSOAPBinding, self).__init__(handlers=(), **kw)
        self.__sslCtxProxy = SSLContextProxy()

    def send(self, query, **kw):
        """Override base class implementation to pass explicit SSL Context
        """
        httpsHandler = HTTPSHandler(ssl_context=self.sslCtxProxy.createCtx())
        self.client.openerDirector.add_handler(httpsHandler)
        return super(AttributeQuerySslSOAPBinding, self).send(query, **kw)
            
    def _getSslCtxProxy(self):
        return self.__sslCtxProxy
    
    def _setSslCtxProxy(self, value):
        if not isinstance(value, SSLContextProxy):
            raise TypeError('Expecting %r type for "sslCtxProxy attribute; got '
                            '%r' % type(value))
            
        self.__sslCtxProxy = value
            
    sslCtxProxy = property(fget=_getSslCtxProxy, fset=_setSslCtxProxy,
                           doc="SSL Context Proxy object used for setting up "
                               "an SSL Context for queries")
    
    def __setattr__(self, name, value):
        """Enable setting of SSLContextProxy attributes as if they were 
        attributes of this class.  This is intended as a convenience for 
        making settings parameters read from a config file
        """
        try:
            super(AttributeQuerySslSOAPBinding, self).__setattr__(name, value)
            
        except AttributeError, e:
            # Coerce into setting SSL Context Proxy attributes
            try:
                setattr(self.sslCtxProxy, name, value)
            except:
                raise e
