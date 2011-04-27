"""WSGI Middleware to set an Attribute Authority instance in the WSGI environ

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "19/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)
import os

from ndg.security.server.attributeauthority import AttributeAuthority
from ndg.security.server.wsgi import NDGSecurityMiddlewareBase


class AttributeAuthorityMiddleware(NDGSecurityMiddlewareBase):
    '''WSGI to add an NDG Security Attribute Authority in the environ.  This
    enables multiple WSGI filters to access the same underlying Attribute
    Authority instance e.g. provide SAML SOAP and WSDL SOAP based interfaces
    to the same Attribute Authority
    '''
    DEFAULT_KEYNAME = 'ndg.security.server.wsgi.attributeauthority'
    ENVIRON_KEYNAME_CFG_OPTNAME = 'environKeyName'
    
    DEFAULT_ATTR_QUERY_IFACE_KEYNAME = \
        'ndg.security.server.wsgi.attributeauthority.attributeQuery'
    ENVIRON_KEYNAME_ATTR_QUERY_IFACE_CFG_OPT_NAME = \
        'environKeyNameAttributeQueryInterface'
        
    def __init__(self, app):
        '''Set-up an Attribute Authority instance
        '''
        # Stop in debugger at beginning of SOAP stub if environment variable 
        # is set
        self.__debug = bool(os.environ.get('NDGSEC_INT_DEBUG'))
        if self.__debug:
            import pdb
            pdb.set_trace()
        
        self._app = app
        self.__aa = None
        self.__attributeQuery = None
        self.__keyName = None
        self.__attributeQueryKeyName = None

    def initialise(self, global_conf, prefix='attributeauthority.',
                   **app_conf):
        """Set-up Attribute authority middleware using a Paste app factory 
        pattern.  Overloaded base class method to enable custom settings from 
        app_conf
        
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        # Set key name for attribute authority set in environ
        environKeyOptName = prefix + \
                    AttributeAuthorityMiddleware.ENVIRON_KEYNAME_CFG_OPTNAME
                    
        self.keyName = app_conf.pop(environKeyOptName,
                                AttributeAuthorityMiddleware.DEFAULT_KEYNAME)

        attrQueryIfaceEnvironKeyOptName = prefix + \
            AttributeAuthorityMiddleware.\
            ENVIRON_KEYNAME_ATTR_QUERY_IFACE_CFG_OPT_NAME
            
        self.attributeQueryKeyName = app_conf.pop(
            attrQueryIfaceEnvironKeyOptName,
            AttributeAuthorityMiddleware.DEFAULT_ATTR_QUERY_IFACE_KEYNAME)
        
        self.aa = AttributeAuthority.fromProperties(prefix=prefix, **app_conf)
        self.attributeQuery = self.aa.samlAttributeQueryFactory()

    @classmethod
    def filter_app_factory(cls, app, global_conf, **app_conf):
        '''Wrapper to enable instantiation compatible with Paste Deploy
        filter application factory function signature
        
        @type app: callable following WSGI interface
        @param app: next middleware application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        '''
        app = cls(app)
        app.initialise(global_conf, **app_conf)
        
        return app
    
    def __call__(self, environ, start_response):
        '''Set the Attribute Authority instantiated at initialisation in 
        environ
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        @rtype: iterable
        @return: next application in the WSGI stack
        '''
        environ[self.keyName] = self.aa
        environ[self.attributeQueryKeyName] = self.attributeQuery
        return self._app(environ, start_response)
    
    def _get_aa(self):
        return self.__aa
    
    def _set_aa(self, val):
        if not isinstance(val, AttributeAuthority):
            raise TypeError('Expecting %r for "aa" attribute; got %r' %
                            (AttributeAuthority, type(val)))
        self.__aa = val
            
    aa = property(fget=_get_aa,
                  fset=_set_aa,
                  doc="Attribute Authority instance")

    def _getKeyName(self):
        return self.__keyName

    def _setKeyName(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting %r for "keyName" attribute; got %r' %
                            (basestring, type(val)))
        self.__keyName = val
        
    keyName = property(fget=_getKeyName, 
                       fset=_setKeyName, 
                       doc="Key name used to index Attribute Authority in "
                           "environ dictionary")

    def _get_attributeQueryKeyName(self):
        return self.__attributeQueryKeyName

    def _set_attributeQueryKeyName(self, val):
        if not isinstance(val, basestring):
            raise TypeError('Expecting %r for "attributeQueryKeyName" '
                            'attribute; got %r' % (basestring, type(val)))
        self.__attributeQueryKeyName = val
        
    attributeQueryKeyName = property(fget=_get_attributeQueryKeyName, 
                                     fset=_set_attributeQueryKeyName, 
                                     doc="Key name used to index Attribute "
                                         "Authority SAML attribute query "
                                         "function in environ dictionary")
    
    def _get_attributeQuery(self):
        return self.__attributeQuery

    def _set_attributeQuery(self, val):
        if not callable(val):
            raise TypeError('Expecting a callable for "attributeQuery" '
                            'attribute; got %r' % type(val))
        self.__attributeQuery = val
        
    attributeQuery = property(fget=_get_attributeQuery, 
                              fset=_set_attributeQuery, 
                              doc="Attribute Authority SAML attribute query "
                                  "function")
