"""NDG Security OpenID Provider AX Interface for CSV file based attribute store

For test purposes only

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "30/09/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

import re

from ndg.security.server.wsgi.openid.provider.axinterface import (AXInterface, 
    AXInterfaceConfigError, MissingRequiredAttrs)
from ndg.security.server.wsgi.openid.provider import (AbstractAuthNInterface, 
    OpenIDProviderMiddleware)


class CSVFileAXInterface(AXInterface):
    """OpenID Provider Attribute Exchange Interface based on a Comma Separated 
    Variable file containing user identities and associated attributes.  
    For test/development purposes
    only.
    
    The expected file format is:
    
    <OpenID>, <attr 1>, <attr 2>, ... <attr N>
    """
    ATTR_NAMES = (
        "csvFilePath",
        "attributeNames",
        "attributeMap",
    )
    __slots__ = tuple(["__%s" % n for n in ATTR_NAMES])
    del n
    
    IDENTITY_URI_SESSION_KEYNAME = \
                        OpenIDProviderMiddleware.IDENTITY_URI_SESSION_KEYNAME
    
    def __init__(self, **properties):
        """
        @param properties: file path to Comma Separated file 
        containing user ids and roles
        @type properties: dict
        """
        self.__csvFilePath = None
        self.__attributeNames = []
        self.__attributeMap = {}
        
        self.setProperties(**properties)
        if self.csvFilePath is not None:
            self.read()

    def _getAttributeNames(self):
        return self.__attributeNames

    def _setAttributeNames(self, value):
        """@param value: if a string, it will be parsed into a list delimiting
        elements by whitespace
        @type value: basestring/tuple or list
        """
        if isinstance(value, (list, tuple)):
            self.__attributeNames = list(value)
            
        elif isinstance(value, str):
            self.__attributeNames = value.split()  
        else:
            raise TypeError('Expecting string, list or tuple type for '
                            '"attributeNames"; got %r' % type(value))
        
    attributeNames = property(fget=_getAttributeNames, 
                              fset=_setAttributeNames, 
                              doc="list of attribute names supported.  The "
                                  "order of the names is important and "
                                  "determines the order in which they will be "
                                  "assigned from the columns in the CSV file")

    def setProperties(self, **properties):
        for name, val in list(properties.items()):
            setattr(self, name, val)
    
    def read(self):
        csvFile = open(self.csvFilePath)
        lines = csvFile.readlines()
        
        nAttributes = len(self.attributeNames)
        for line in lines:
            fields = re.split(',\s*', line.strip())
            
            # Dictionary keyed by user ID with each val itself a dict keyed
            # by attribute name
            self.attributeMap[fields[0]] = dict(list(zip(self.attributeNames,
                                                    fields[1:nAttributes+1])))
               
    def _getCsvFilePath(self):
        return self.__csvFilePath

    def _setCsvFilePath(self, value):
        if not isinstance(value, str):
            raise TypeError('Expecting string type for "csvFilePath"; got %r'
                            % type(value))
        self.__csvFilePath = value

    csvFilePath = property(fget=_getCsvFilePath, 
                           fset=_setCsvFilePath, 
                           doc="file path to Comma Separated Variable format "
                               "file containing user IDs and attributes")
    
    def _getAttributeMap(self):
        return self.__attributeMap

    def _setAttributeMap(self, value):
        self.__attributeMap = value

    attributeMap = property(fget=_getAttributeMap, 
                            fset=_setAttributeMap, 
                            doc="Dictionary of attributes keyed by user ID")
    
    def __call__(self, ax_req, ax_resp, authnInterface, authnCtx):
        """Add the attributes to the ax_resp object requested in the ax_req
        object.  If it is not possible to return them, raise 
        MissingRequiredAttrs error
        
        @type ax_req: openid.extensions.ax.FetchRequest
        @param ax_req: attribute exchange request object.  To find out what 
        attributes the Relying Party has requested for example, call
        ax_req.getRequiredAttrs()
        @type ax_resp: openid.extensions.ax.FetchResponse
        @param ax_resp: attribute exchange response object.  This method should
        update the settings in this object.  Use addValue and setValues methods
        @type authnInterface: AbstractAuthNInterface
        @param authnInterface: custom authentication interface set at login.  
        See ndg.security.server.openid.provider.AbstractAuthNInterface for more 
        information
        @type authnCtx: dict like
        @param authnCtx: session containing authentication context information
        such as username and OpenID user identifier URI snippet
        """
        log.debug('CSVFileAXInterface.__call__  ...')
        
        identityURI = authnCtx.get(
                                CSVFileAXInterface.IDENTITY_URI_SESSION_KEYNAME)
        if identityURI is None:
            raise AXInterfaceConfigError("No OpenID user identifier set in "
                                         "session context")
        
        requiredAttributeURIs = ax_req.getRequiredAttrs()
            
        userAttributeMap = self.attributeMap.get(identityURI)
        if userAttributeMap is None:
            raise AXInterfaceConfigError("No attribute entry for user [%s] " %
                                         identityURI)
                                     
        missingAttributeURIs = [
            requiredAttributeURI 
            for requiredAttributeURI in requiredAttributeURIs
            if requiredAttributeURI not in self.attributeNames
        ]
        if len(missingAttributeURIs) > 0:
            raise MissingRequiredAttrs("OpenID Provider does not support "
                                       "release of these attributes required "
                                       "by the Relying Party: %s" %
                                       ', '.join(missingAttributeURIs))
        
        # Add the requested attributes
        for requestedAttributeURI in list(ax_req.requested_attributes.keys()):
            if requestedAttributeURI in self.attributeNames:
                log.info("Adding requested AX parameter %s=%s ...", 
                         requestedAttributeURI,
                         userAttributeMap[requestedAttributeURI])
                
                ax_resp.addValue(requestedAttributeURI,
                                 userAttributeMap[requestedAttributeURI])
            else:
                log.info("Skipping Relying Party requested AX parameter %s: "
                         "this parameter is not available", 
                         requestedAttributeURI)
                
