"""NDG Security OpenID Provider AX Interface for the SQLAlchemy database
toolkit

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "23/10/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)

import traceback
from string import Template
from sqlalchemy import create_engine, exc, sql

from ndg.security.server.wsgi.openid.provider.axinterface import (AXInterface,
    AXInterfaceConfigError, AXInterfaceRetrieveError, MissingRequiredAttrs)
from ndg.security.server.wsgi.openid.provider import OpenIDProviderMiddleware


class SQLAlchemyAXInterface(AXInterface):
    '''Provide a database based AX interface to the OpenID Provider
    making use of the SQLAlchemy database package'''

    USERNAME_SESSION_KEYNAME = OpenIDProviderMiddleware.USERNAME_SESSION_KEYNAME

    CONNECTION_STRING_OPTNAME = 'connectionString'
    SQLQUERY_OPTNAME = 'sqlQuery'
    ATTRIBUTE_NAMES_OPTNAME = "attributeNames"
    SQLQUERY_USERID_KEYNAME = 'username'

    ATTR_NAMES = (
        CONNECTION_STRING_OPTNAME,
        SQLQUERY_OPTNAME,
        ATTRIBUTE_NAMES_OPTNAME,
    )
    __slots__ = tuple(["__%s" % name for name in ATTR_NAMES])
    del name

    def __init__(self, **properties):
        '''Instantiate object taking in settings from the input
        properties

        @type properties: dict
        @param properties: keywords corresponding instance attributes - see
        __slots__ for list of options
        '''
        log.debug('Initialising SQLAlchemyAXInterface instance ...')

        self.__connectionString = None
        self.__sqlQuery = None
        self.__attributeNames = None

        self.setProperties(**properties)

    def _getConnectionString(self):
        return self.__connectionString

    def _setConnectionString(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "%s" '
                            'attribute; got %r' %
                            (SQLAlchemyAXInterface.CONNECTION_STRING_OPTNAME,
                             type(value)))
        self.__connectionString = value

    connectionString = property(fget=_getConnectionString,
                                fset=_setConnectionString,
                                doc="Database connection string")

    def _getSqlQuery(self):
        return self.__sqlQuery

    def _setSqlQuery(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "sqlQuery" '
                            'attribute; got %r' % type(value))
        self.__sqlQuery = value

    sqlQuery = property(fget=_getSqlQuery,
                        fset=_setSqlQuery,
                        doc="SQL Query for authentication request")

    def _getAttributeNames(self):
        return self.__attributeNames

    def _setAttributeNames(self, value):
        """@param value: if a string, it will be parsed into a list delimiting
        elements by whitespace
        @type value: basestring/tuple or list
        """
        if isinstance(value, (list, tuple)):
            self.__attributeNames = list(value)

        elif isinstance(value, basestring):
            self.__attributeNames = value.split()
        else:
            raise TypeError('Expecting string, list or tuple type for '
                            '"attributeNames"; got %r' % type(value))

    attributeNames = property(fget=_getAttributeNames,
                              fset=_setAttributeNames,
                              doc="list of attribute names supported.  The "
                                  "order of the names is important and "
                                  "determines the order in which they will be "
                                  "assigned to values from the SQL query "
                                  "result")

    def setProperties(self, **properties):
        """Set object attributes by keyword argument to this method.  Keywords
        are restricted by the entries in __slots__
        """
        for name, val in properties.items():
            setattr(self, name, val)

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
        log.debug('SQLAlchemyAXInterface.__call__  ...')

        username = authnCtx.get(SQLAlchemyAXInterface.USERNAME_SESSION_KEYNAME)
        if username is None:
            raise AXInterfaceConfigError("No username set in session context")

        requiredAttributeURIs = ax_req.getRequiredAttrs()

        if self.attributeNames is None:
            raise AXInterfaceConfigError('No "attributeNames" setting has '
                                         'been made')

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

        # Query for available attributes
        userAttributeMap = self._attributeQuery(username)

        # Add the requested attribute if available
        for requestedAttributeURI in ax_req.requested_attributes.keys():
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

    def _attributeQuery(self, username):
        '''Query the database for attributes and map these to the attribute
        names given in the configuration.  Overload as required to ensure a
        correct mapping between the SQL query results and the attribute names
        they refer to
        '''
        if self.connectionString is None:
            raise AXInterfaceConfigError('No "connectionString" setting has '
                                         'been made')
        dbEngine = create_engine(self.connectionString)

        try:
            queryInputs = {
                SQLAlchemyAXInterface.SQLQUERY_USERID_KEYNAME: username
            }
            query = Template(self.sqlQuery).substitute(queryInputs)

        except KeyError, e:
            raise AXInterfaceConfigError("Invalid key %r for attribute query "
                                         "string.  The valid key is %r" % (e,
                                SQLAlchemyAXInterface.SQLQUERY_USERID_KEYNAME))

        connection = dbEngine.connect()

        try:
            filtered_query = sql.text(query)
            result = connection.execute(filtered_query, username=username)
            attributeValues = result.fetchall()[0]
        except IndexError:
            raise AXInterfaceRetrieveError("No attributes returned for "
                                           "query=\"%s\"" % query)

        except (exc.ProgrammingError, exc.OperationalError):
            raise AXInterfaceRetrieveError("SQL error: %s" %
                                           traceback.format_exc())
        finally:
            connection.close()

        if len(self.attributeNames) != len(attributeValues):
            raise AXInterfaceConfigError("Attribute query results %r, don't "
                                         "match the attribute names specified "
                                         "in the configuration file: %r" %
                                         (attributeValues, self.attributeNames))

        attributes = dict(zip(self.attributeNames, attributeValues))

        log.debug("Retrieved user AX attributes %r" % attributes)

        return attributes

    def __getstate__(self):
        '''Enable pickling for use with beaker.session'''
        _dict = {}
        for attrName in SQLALchemyAXInterface.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_SQLALchemyAXInterface" + attrName

            _dict[attrName] = getattr(self, attrName)

        return _dict
    def __setstate__(self, attrDict):
        '''Enable pickling for use with beaker.session'''
        self.setProperties(**attrDict)
