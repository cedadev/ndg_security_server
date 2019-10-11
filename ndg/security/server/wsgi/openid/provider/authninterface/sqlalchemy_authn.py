"""
SQLAlchemy based Authentication interface for the OpenID Provider

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/10/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)
try:
    from hashlib import md5
except ImportError:
    # Allow for < Python 2.5
    from md5 import md5

import traceback
from string import Template
from sqlalchemy import create_engine, exc, sql


from ndg.security.common.utils import str2Bool as _str2Bool
from ndg.security.server.wsgi.openid.provider.authninterface import (
    AbstractAuthNInterface, AuthNInterfaceInvalidCredentials,
    AuthNInterfaceRetrieveError, AuthNInterfaceConfigError)


class SQLAlchemyAuthnInterface(AbstractAuthNInterface):
    '''Provide a database based Authentication interface to the OpenID Provider
    making use of the SQLAlchemy database package'''

    str2Bool = staticmethod(_str2Bool)

    USERNAME_SQLQUERY_KEYNAME = 'username'
    PASSWD_SQLQUERY_KEYNAME = 'password'
    CONNECTION_STRING_OPTNAME = 'connectionString'
    LOGON_SQLQUERY_OPTNAME = 'logonSqlQuery'
    USERNAME2USERIDENTIFIER_SQLQUERY_OPTNAME = 'username2UserIdentifierSqlQuery'
    IS_MD5_ENCODED_PWD = 'isMD5EncodedPwd'

    ATTR_NAMES = (
        CONNECTION_STRING_OPTNAME,
        LOGON_SQLQUERY_OPTNAME,
        USERNAME2USERIDENTIFIER_SQLQUERY_OPTNAME,
        IS_MD5_ENCODED_PWD
    )
    __slots__ = tuple(["__%s" % name for name in ATTR_NAMES])

    def __init__(self, **prop):
        '''Instantiate object taking in settings from the input
        properties'''
        log.debug('Initialising SQLAlchemyAuthnInterface instance ...')

        self.__connectionString = None
        self.__logonSqlQuery = None
        self.__username2UserIdentifierSqlQuery = None
        self.__isMD5EncodedPwd = False

        try:
            self.connectionString = prop[
                            SQLAlchemyAuthnInterface.CONNECTION_STRING_OPTNAME]

            self.logonSqlQuery = prop[
                            SQLAlchemyAuthnInterface.LOGON_SQLQUERY_OPTNAME]

            self.username2UserIdentifierSqlQuery = prop[
            SQLAlchemyAuthnInterface.USERNAME2USERIDENTIFIER_SQLQUERY_OPTNAME]

            self.isMD5EncodedPwd = prop[
                            SQLAlchemyAuthnInterface.IS_MD5_ENCODED_PWD]
        except KeyError as e:
            raise AuthNInterfaceConfigError("Initialisation from keywords: %s"%
                                            e)

    def _getConnectionString(self):
        return self.__connectionString

    def _setConnectionString(self, value):
        if not isinstance(value, str):
            raise TypeError('Expecting string type for "%s" attribute; got %r'%
                            (SQLAlchemyAuthnInterface.CONNECTION_STRING_OPTNAME,
                             type(value)))
        self.__connectionString = value

    connectionString = property(fget=_getConnectionString,
                                fset=_setConnectionString,
                                doc="Database connection string")

    def _getLogonSqlQuery(self):
        return self.__logonSqlQuery

    def _setLogonSqlQuery(self, value):
        if not isinstance(value, str):
            raise TypeError('Expecting string type for "%s" '
                            'attribute; got %r' %
                            (SQLAlchemyAuthnInterface.LOGON_SQLQUERY_OPTNAME,
                             type(value)))
        self.__logonSqlQuery = value

    logonSqlQuery = property(fget=_getLogonSqlQuery,
                        fset=_setLogonSqlQuery,
                        doc="SQL Query for authentication request")

    def _getUsername2UserIdentifierSqlQuery(self):
        return self.__username2UserIdentifierSqlQuery

    def _setUsername2UserIdentifierSqlQuery(self, value):
        if not isinstance(value, str):
            raise TypeError('Expecting string type for "%s" attribute; got %r'%
                            (SQLAlchemyAuthnInterface.
                             USERNAME2USERIDENTIFIER_SQLQUERY_OPTNAME,
                             type(value)))
        self.__username2UserIdentifierSqlQuery = value

    username2UserIdentifierSqlQuery = property(
                                    fget=_getUsername2UserIdentifierSqlQuery,
                                    fset=_setUsername2UserIdentifierSqlQuery,
                                    doc="SQL Query for OpenID user identifier "
                                        "look-up")

    def _getIsMD5EncodedPwd(self):
        return self.__isMD5EncodedPwd

    def _setIsMD5EncodedPwd(self, value):
        if isinstance(value, bool):
            self.__isMD5EncodedPwd = value
        elif isinstance(value, str):
            self.__isMD5EncodedPwd = SQLAlchemyAuthnInterface.str2Bool(value)
        else:
            raise TypeError('Expecting bool type for "isMD5EncodedPwd" '
                            'attribute; got %r' % type(value))

    isMD5EncodedPwd = property(fget=_getIsMD5EncodedPwd,
                               fset=_setIsMD5EncodedPwd,
                               doc="Boolean set to True if password is MD5 "
                                   "encrypted")

    def logon(self, environ, identityURI, username, password):
        """Interface login method

        @type environ: dict
        @param environ: standard WSGI environ parameter

        @type identityURI: basestring
        @param identityURI: user's identity URL e.g.
        'https://joebloggs.somewhere.ac.uk/'

        @type username: basestring
        @param username: username

        @type password: basestring
        @param password: corresponding password for username given

        @raise AuthNInterfaceInvalidCredentials: invalid username/password
        @raise AuthNInterfaceUsername2IdentifierMismatch: no OpenID matching
        the given username
        @raise AuthNInterfaceConfigError: missing database engine plugin for
        SQLAlchemy
        """
        if self.isMD5EncodedPwd:
            try:
                _password = md5(password).hexdigest()
            except Exception as e:
                raise AuthNInterfaceConfigError("%s exception raised making a "
                                                "digest of the input "
                                                "password: %s" %
                                                (type(e),
                                                 traceback.format_exc()))
        else:
            _password = password

        try:
            dbEngine = create_engine(self.connectionString)
        except ImportError as e:
            raise AuthNInterfaceConfigError("Missing database engine for "
                                            "SQLAlchemy: %s" % e)
        connection = dbEngine.connect()

        try:
            queryInputs = {
                SQLAlchemyAuthnInterface.USERNAME_SQLQUERY_KEYNAME: username,
                SQLAlchemyAuthnInterface.PASSWD_SQLQUERY_KEYNAME: _password
            }
            query = Template(self.logonSqlQuery).substitute(queryInputs)

        except KeyError as e:
            raise AuthNInterfaceConfigError("Invalid key %r for logon SQL "
                "query string.  Valid keys are %r and %r" %
                (e,
                 SQLAlchemyAuthnInterface.USERNAME_SQLQUERY_KEYNAME,
                 SQLAlchemyAuthnInterface.PASSWD_SQLQUERY_KEYNAME))


        try:
            filtered_query = sql.text(query)
            result = connection.execute(filtered_query, username=username,
                                        password=_password)
            nEntries = int([r[0] for r in result][0])

        except (exc.ProgrammingError, exc.OperationalError):
            raise AuthNInterfaceRetrieveError("Error with SQL: %s" %
                                              traceback.format_exc())
        except (ValueError, TypeError) as e:
            raise AuthNInterfaceRetrieveError("Expecting integer count result "
                                              "from login SQL query: %s" %
                                              traceback.format_exc())
        finally:
            connection.close()

        if nEntries < 1:
            raise AuthNInterfaceInvalidCredentials("Logon query %r: invalid "
                                                   "password for user %r" %
                                                   (query, username))
        elif nEntries > 1:
            raise AuthNInterfaceInvalidCredentials("Logon: multiple entries "
                                                   "returned for query %r" %
                                                   query)

        log.debug('Logon succeeded for user %r' % username)

    def logout(self):
        """No special functionality is required for logout"""

    def username2UserIdentifiers(self, environ, username):
        """Map the login username to an identifier which will become the
        unique path suffix to the user's OpenID identifier.  The
        OpenIDProviderMiddleware takes self.urls['id_url'] and adds it to this
        identifier:

            identifier = self._authN.username2UserIdentifiers(environ,
                                                              username)[0]
            identifierKw = dict(userIdentifier=identifier)
            identityURL = Template(self.urls['url_id'].substitute(identifierKw)

        @type environ: dict
        @param environ: standard WSGI environ parameter

        @type username: basestring
        @param username: user identifier

        @rtype: tuple
        @return: identifiers to be used to make OpenID user identity URLs.

        @raise AuthNInterfaceRetrieveError: error with retrieval of information
        to identifier e.g. error with database look-up.
        @raise AuthNInterfaceConfigError: missing database engine plugin for
        SQLAlchemy
        """

        try:
            dbEngine = create_engine(self.connectionString)
        except ImportError as e:
            raise AuthNInterfaceConfigError("Missing database engine for "
                                            "SQLAlchemy: %s" % e)
        connection = dbEngine.connect()

        try:
            queryInputs = {
                SQLAlchemyAuthnInterface.USERNAME_SQLQUERY_KEYNAME: username,
            }
            queryTmpl = Template(self.username2UserIdentifierSqlQuery)
            query = queryTmpl.substitute(queryInputs)

        except KeyError as e:
            raise AuthNInterfaceConfigError("Invalid key %r for username to "
                                            "user identifier SQL query string. "
                                            " The valid key is %r" % (e,
                            SQLAlchemyAuthnInterface.USERNAME_SQLQUERY_KEYNAME))

        try:
            # Use SQL parameter substitution
            filtered_query = sql.text(query)

            result = connection.execute(filtered_query, username=username)
            userIdentifiers = tuple([i[0] for i in result.fetchall()])

        except (exc.ProgrammingError, exc.OperationalError):
            raise AuthNInterfaceRetrieveError("Error with SQL query: %s" %
                                              traceback.format_exc())
        finally:
            connection.close()

        if len(userIdentifiers) == 0:
            raise AuthNInterfaceInvalidCredentials('No entries for "%s" user' %
                                                   username)

        log.debug('username %r maps to OpenID identifiers: %r', username,
                  userIdentifiers)

        return userIdentifiers


    def __getstate__(self):
        '''Enable pickling for use with beaker.session'''
        _dict = {}
        for attrName in SQLAlchemyAuthnInterface.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_SQLAlchemyAuthnInterface" + attrName

            _dict[attrName] = getattr(self, attrName)

        return _dict

    def __setstate__(self, attrDict):
        '''Enable pickling for use with beaker.session'''
        for attr, val in list(attrDict.items()):
            setattr(self, attr, val)