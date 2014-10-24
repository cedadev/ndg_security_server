#!/usr/bin/env python
"""NDG Security ndg.security.common.utils.openid package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "17/09/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import re
import urllib
from string import Template
import logging
log = logging.getLogger(__name__)

from ConfigParser import SafeConfigParser

# Make an optional import to allow use of the UserIdentifier class alone which
# has no database dependence
_psycopg2Unavailable = False
try:
    from psycopg2 import connect
except ImportError:
    _psycopg2Unavailable = True


class UserIdentifiersConfigError(Exception):
    """Configuration error for UserIdentifiers instance"""


class UserIdentifiers(object):
    """Library of helper methods to parse a set of space delimited first names
    and a surname string into a suitable OpenID indentifier of the form
    <firstname>.<surname>
    """

    @staticmethod
    def none2String(s):
        """Convert None type to an empty string
        
        @type s: basestring/None
        @param s: string to be converted
        @rtype: basestring
        @return: converted string 
        """
        if s is None:
            return ''
        else:
            return s

    # Split surnames allowing for spaces, hyphenation and ' for e.g. O'Connor
    splitPat = re.compile("[-)('\s]+")

    @staticmethod
    def sentenceCase(s, preserveCaps=False):
        """Convert string to sentence case - first letter of first word is 
        capitalised
        @type s: basestring
        @param s: string to be converted
        @type preserveCaps: bool
        @param preserveCaps: set to True to leave uppercase strings such as 
        acronyms alone
        @rtype: basestring
        @return: converted string 
        """
        if s is None:
            return ''
        elif s.isupper() and preserveCaps:
            return s
        else:
            return s[0].upper() + s[1:].lower()

    camelCase = staticmethod(lambda s: ''.join(
                                    [UserIdentifiers.sentenceCase(i)
                                     for i in UserIdentifiers.splitPat.split(
                                     UserIdentifiers.none2String(s.strip()))
                                     if i]
                                    )
                            )

    getFirstName = staticmethod(lambda s: UserIdentifiers.camelCase(
                            UserIdentifiers.none2String(s.strip()).split()[0]))

    @staticmethod
    def mcFilter(s):
        '''Allow for surnames starting with Mc e.g. McDonald
        @type s: basestring
        @param s: string to be converted
        @rtype: basestring
        @return: converted string 
        '''
        if s.startswith('Mc'):
            return 'Mc' + s[2].upper() + s[3:]
        else:
            return s

    convertSurname = staticmethod(lambda s: UserIdentifiers.mcFilter(
                                                UserIdentifiers.camelCase(s)))

    isUrlSafe = staticmethod(lambda s: urllib.quote(s) == s)

    @staticmethod
    def makeIdentifier(firstNames, surname):
        """Make an OpenID identifier based on the users first name joined to
        their last name with a dot separator"""
        if not firstNames:
            return UserIdentifiers.camelCase(surname)
        else:
            try:
                firstName = UserIdentifiers.getFirstName(firstNames)
            except IndexError:
                log.warning('Error parsing first name from "%s": using '
                            'surname only' % firstNames)
                firstName = ''

            if firstName.endswith('.'):
                firstName = firstName[:-1]

            try:
                surname = UserIdentifiers.convertSurname(surname)
            except IndexError:
                log.warning('Error parsing surname from "%s": setting to null '
                            'string' % surname)
                surname = ''

            if not firstName and not surname:
                log.warning('Null identifier returned for firstNames="%s" and '
                            'surname="%s"' % (firstNames, surname))
                return ''

            # Allow for surname or firstname not set
            newId = (firstName+'.'+surname).strip('.')
            if not UserIdentifiers.isUrlSafe(newId):
                urlSafeId = urllib.quote(newId)
                log.warning('Changing id "%s" to "%s" to make it URL safe' %
                            (newId, urlSafeId))
                return urlSafeId
            else:
                return newId


class DatabaseUserIdentifiersConfigError(Exception):
    """Configuration error for DatabaseUserIdentifiers instance"""


class DatabaseUserIdentifiers(UserIdentifiers):
    """Generate a list of OpenID identifiers from a query
    to a user database"""

    SECTION_NAME = "DatabaseOpenIDUserIdentifiers"
    HOST_OPTNAME = "host"
    DBNAME_OPTNAME = "dbName"
    USERNAME_OPTNAME = "username"
    PWD_OPTNAME = "pwd"
    QUERY_GENERATE_OPTNAME = "query.generate"
    QUERY_GENERATE_FROM_USERKEY_OPTNAME = "query.generateFromUserKey"
    QUERY_UNIQ_IDENTIFIER_OPTNAME = "query.uniqIdentifier"
    QUERY_GET_IDENTIFIERS_OPTNAME = "query.getIdentifiers"
    UNIQ_IDENTIFIER_FIELD_NAME = "openIdUserComponent"
    USERKEY_FIELD_NAME = "userKey"

    def __init__(self, propertiesFilePath=None):
        """Connect to Postgres database"""
        super(DatabaseUserIdentifiers, self).__init__()
        
        if _psycopg2Unavailable:
            log.warning("psycopg2 package is required for this class")

        self.__con = None
        self.__host = None
        self.__dbName = None
        self.__username = None
        self.__pwd = None
        self.__generateQuery = None
        self.__generateFromUserKeyQuery = None
        self.__getIdentifiersQuery = None
        self.__uniqIdentifierQuery = None
        self.__cursor = None
        self.__db = None
        
        if propertiesFilePath is None:
            raise AttributeError("No Configuration file was set")

        self.readConfigFile(propertiesFilePath)

    def __del__(self):
        """Close database connection"""
        self.close()

    def readConfigFile(self, propertiesFilePath):
        """Read the configuration for the database connection

        @type propertiesFilePath: string
        @param propertiesFilePath: file path to config file"""

        if not isinstance(propertiesFilePath, basestring):
            raise TypeError("Input Properties file path "
                            "must be a valid string.")

        cfg = SafeConfigParser()
        cfg.read(propertiesFilePath)

        self.__host = cfg.get(
                        DatabaseUserIdentifiers.SECTION_NAME,
                        DatabaseUserIdentifiers.HOST_OPTNAME)
        self.__dbName = cfg.get(
                        DatabaseUserIdentifiers.SECTION_NAME,
                        DatabaseUserIdentifiers.DBNAME_OPTNAME)
        self.__username = cfg.get(
                        DatabaseUserIdentifiers.SECTION_NAME,
                        DatabaseUserIdentifiers.USERNAME_OPTNAME)
        self.__pwd = cfg.get(
                        DatabaseUserIdentifiers.SECTION_NAME,
                        DatabaseUserIdentifiers.PWD_OPTNAME)

        self.__generateQuery = cfg.get(
                        DatabaseUserIdentifiers.SECTION_NAME,
                        DatabaseUserIdentifiers.QUERY_GENERATE_OPTNAME)

        self.__generateFromUserKeyQuery = cfg.get(
                    DatabaseUserIdentifiers.SECTION_NAME,
                    DatabaseUserIdentifiers.QUERY_GENERATE_FROM_USERKEY_OPTNAME)

        self.__getIdentifiersQuery = cfg.get(
                    DatabaseUserIdentifiers.SECTION_NAME,
                    DatabaseUserIdentifiers.QUERY_GET_IDENTIFIERS_OPTNAME)

        self.__uniqIdentifierQuery = cfg.get(
                    DatabaseUserIdentifiers.SECTION_NAME,
                    DatabaseUserIdentifiers.QUERY_UNIQ_IDENTIFIER_OPTNAME)

    def connect(self,
                username=None,
                dbName=None,
                host=None,
                pwd=None,
                prompt="Database password: "):
        """Connect to database

        Values for keywords omitted are derived from the config file.  If pwd
        is not in the config file it will be prompted for from stdin

        @type username: string
        @keyword username: database account username
        @type dbName: string
        @keyword dbName: name of database
        @type host: string
        @keyword host: database host machine
        @type pwd: string
        @keyword pwd: password for database account.  If omitted and not in
        the config file it will be prompted for from stdin
        @type prompt: string
        @keyword prompt: override default password prompt"""

        if not host:
            host = self.__host

        if not dbName:
            dbName = self.__dbName

        if not username:
            username = self.__username

        if not pwd:
            pwd = self.__pwd

            if not pwd:
                import getpass
                pwd = getpass.getpass(prompt)

        try:
            self.__db = connect("host=%s dbname=%s user=%s password=%s" %
                                (host, dbName, username, pwd))
            self.__cursor = self.__db.cursor()

        except NameError, e:
            raise DatabaseUserIdentifiersConfigError(
                    "Error accessing connect() function - check that the "
                    "Postgres Python package psycopg2 is installed; error is: "
                    "%s" % e)

        except Exception, e:
            log.error("Error connecting to database \"%s\": %s" % (dbName, e))
            raise

    def close(self):
        """Close database connection"""
        if self.__con:
            self.__con.close()

    @staticmethod
    def makeUniqId(ids, idBase, newId=None, counter=1):
        """Check newId is not already assigned in the ids list,
        if it is, make a new id based on idBase and the counter.
        Check this new id and again if it's already assigned try
        again but incrementing the counter to give a new id.
        Make recursive calls until a unique id is arrived at
        
        @type ids: list
        @param ids: list of existing OpenID identifiers
        @type idBase: basestring
        @param idBase: base string from which to construct a new identifier
        @type newId: basestring
        @param newId: candidate identifier to add in
        @type counter: int
        @param counter: number to append to an existing identifier in order to
        make it into a new unique one
        @rtype: basestring
        @return: new unique identifier
        """
        if newId is None:
            newId = idBase

        if newId.lower() in ids:
            newId = "%s%d" % (idBase, counter)
            newId = DatabaseUserIdentifiers.makeUniqId(ids,
                                                       idBase,
                                                       newId=newId,
                                                       counter=counter+1)
        return newId

    def generate(self):
        """Generate a list of OpenID identifiers from the configured
        query
        @rtype: list 
        @return: list of username/OpenID user identifiers tuples
        """

        try:
            self.connect()

            ids = []
            lowerCaseIds = []
            accountIds = []
            self.__cursor.execute(self.__generateQuery)
            queryRes = self.__cursor.fetchall()

            # Create OpenID URL snippets
            for res in queryRes:
                accountIds += [res[0]]
                identifier = DatabaseUserIdentifiers.makeIdentifier(*res[1:3])
                identifier = DatabaseUserIdentifiers.makeUniqId(lowerCaseIds, 
                                                                identifier)
                ids += [identifier]
                lowerCaseIds += [identifier.lower()]
        finally:
            self.close()

        # Associate the OpenID snippets with their account IDs
        return zip(accountIds, ids)

    def getIdentifiers(self):
        """Get all OpenID identifiers currently held in the database
        @rtype: list
        @return: list of OpenID user identifiers
        """
        try:
            self.connect()

            self.__cursor.execute(self.__getIdentifiersQuery)
            queryRes = self.__cursor.fetchall()

            identifiers = [res[0] for res in queryRes]
        finally:
            self.close()

        return identifiers

    def generateFromUserKey(self, userKey):
        """Generate a single OpenID identifier from a single user key configured
        in the given query
        @type userKey: basestring
        @param userKey: database user table primary key
        @rtype: string
        @return: OpenID user identifier, None if user key is not found
        """
        queryTmpl = Template(self.__generateFromUserKeyQuery)
        userKeyKw = {
            DatabaseUserIdentifiers.USERKEY_FIELD_NAME: userKey
        }
        query = queryTmpl.substitute(userKeyKw)

        try:
            self.connect()

            self.__cursor.execute(query)
            queryRes = self.__cursor.fetchall()
        finally:
            self.close()

        if len(queryRes) == 0:
            log.debug("No userkey = %r found", userKey)
            return None
        
        # Create OpenID URL snippet
        res = queryRes[0]
        identifier = DatabaseUserIdentifiers.makeIdentifier(*res[1:3])
        existingIdentifiers = [i.lower() for i in self.getIdentifiers()]
        identifier = DatabaseUserIdentifiers.makeUniqId(existingIdentifiers,
                                                        identifier)

        # Return the generated identifier
        return identifier

    def isUniqIdentifier(self, identifier):
        """Check for the given OpenID User identifier URI snippet in the
        database
        @type identifier: basestring
        @param identifier: OpenID user identifier
        @rtype: bool
        @return: True if input identifier is not present in the database
        """
        queryTmpl = Template(self.__uniqIdentifierQuery)
        identKw = {
            DatabaseUserIdentifiers.UNIQ_IDENTIFIER_FIELD_NAME: identifier
        }
        query = queryTmpl.substitute(identKw)

        try:
            self.connect()
            self.__cursor.execute(query)
            queryRes = self.__cursor.fetchall()
        finally:
            self.close()

        return len(queryRes) == 0

    def __getCursor(self):
        """Return a database cursor instance"""
        return self.__cursor

    cursor = property(fget=__getCursor, doc="database cursor")


import optparse
import sys
import os

class Main(object):
    """Wrapper to DatabaseUserIdentifiers class to enable call from the
    command line
    """

    MIN_NARGS = 3
    GENERATE_CMD_NARGS = ''
    GENERATE_CMD_STR = 'generate-identifiers'
    GET_IDENTIFIERS_CMD_STR = 'get-identifiers'
    GENERATE_FROM_USERKEY_CMD_STR = 'generate-identifier-from-userkey'
    QUERY_IDENTIFIER_CMD_STR = "is-uniq-identifier"

    CMD_STRS = (
        GENERATE_CMD_STR,
        GET_IDENTIFIERS_CMD_STR,
        GENERATE_FROM_USERKEY_CMD_STR,
        QUERY_IDENTIFIER_CMD_STR
    )
    DEBUG_ENVVAR_NAME = 'OPENID_USER_IDENTIFIERS_DEBUG'

    @classmethod
    def run(cls):
        """Parse command line arguments and run the query specified"""

        if cls.DEBUG_ENVVAR_NAME in os.environ:
            import pdb
            pdb.set_trace()

        parser = optparse.OptionParser()
        parser.add_option("-c",
                          "--command",
                          dest="command",
                          help="Database query to execute [%s]" %
                               '|'.join(cls.CMD_STRS))

        parser.add_option("-f",
                          "--config-file",
                          dest="configFilePath",
                          help="database configuration file path")

        parser.add_option("-u",
                          "--user-identifier",
                          dest="userIdentifier",
                          help="user identifier for %s command only" %
                               cls.QUERY_IDENTIFIER_CMD_STR)

        parser.add_option("-k",
                          "--user-key",
                          dest="userKey",
                          type="string",
                          help="database user key for %s command only" %
                               cls.GENERATE_FROM_USERKEY_CMD_STR)

        opt = parser.parse_args()[0]

        if not opt.command:
            msg = "Error, no command set.\n\n" + parser.format_help()
            raise SystemExit(msg)

        ids = DatabaseUserIdentifiers(opt.configFilePath)

        if opt.command == cls.GENERATE_CMD_STR:
            for i in ids.generate():
                print(i)
        elif opt.command == cls.GET_IDENTIFIERS_CMD_STR:
            identifiers = ids.getIdentifiers()
            print(identifiers)

        elif opt.command == cls.GENERATE_FROM_USERKEY_CMD_STR:
            if not opt.userKey:
                msg = "Error, no user key set for query command.\n\n" +\
                    parser.format_help()
                raise SystemExit(msg)

            identifier = ids.generateFromUserKey(opt.userKey)
            if identifier is None:
                print('')
            else:
                print(identifier)

        elif opt.command == cls.QUERY_IDENTIFIER_CMD_STR:
            if not opt.userIdentifier:
                msg = "Error, no user identifier set for query command.\n\n" +\
                    parser.format_help()
                raise SystemExit(msg)

            isUniqIdent = ids.isUniqIdentifier(opt.userIdentifier)
            print(isUniqIdent)

            # In line with exit status convention 0 status means it
            # IS NOT currently allocated, 1 means it is
            sys.exit(not isUniqIdent)
        else:
            msg = "Command %s not recognised.\n\n" % opt.command + \
                    parser.format_help()
            raise SystemExit(msg)

if __name__ == "__main__":
    logging.basicConfig()
    Main.run()