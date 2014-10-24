# Copyright (C) 2009 Science and Technology Facilities Council (Science and Technology Facilities Council).
# This software may be distributed under the terms of the
# Q Public License, version 1.0 or later.
# http://ndg.nerc.ac.uk/public_docs/QPublic_license.txt
"""
Utilities for transfor of credentials over login service

@author: Philip Kershaw
"""
__revision__ = '$Id:$'

import logging
log = logging.getLogger(__name__)

import urllib
from pylons import session, request, g


class SecuritySession(dict):
    """Utility for Pylons security session keys enables correct
    keys to be set
    
    @type key: string
    @cvar key: name of security key in session object
    
    @type subKeys: tuple
    @cvar subKeys: list of valid security keys to set h = session manager
    address, sid = session ID, u = username, org = organisation where user is
    logged in, roles = the roles the user is entitled to at org"""
    
    key = 'ndgSec'
    subKeys = ('h', 'sid', 'u', 'org', 'roles')

    def __init__(self):
        '''Initialize security dict key in session object'''
        if SecuritySession.key not in session:
            session[SecuritySession.key] = {}.fromkeys(SecuritySession.subKeys)            
            session[SecuritySession.key]['roles'] = []
           
    def set(self, **subKeys):
        """Update the security key of session object with the
        input sub keys
        
        type **subKeys: dict
        param **subKeys: set any of the security keywords as contained in
        SecuritySession.subKeys"""
        
        # Set the security session keys from request.params if no keywords 
        # were input
        if subKeys == {}:
            subKeys = SSOServiceQuery.decodeRequestParams()
            
        # Ensure security key is present
        if SecuritySession.key not in session:
            session[SecuritySession.key] = {}
         
        # Ensure valid keys are being set   
        for k in subKeys:
            if k not in SecuritySession.subKeys:
                raise KeyError('Invalid key Security session dict: "%s"' % k)
        
        # Update security values
        session[SecuritySession.key].update(subKeys)            
        session.save()
        log.debug("Set security session: %s" % session[SecuritySession.key])

    def __delitem__(self, key):
        "Keys cannot be removed"        
        raise KeyError('Keys cannot be deleted from security session')

    def __getitem__(self, key):
        '''data dictionary overload'''
        if key not in session[SecuritySession.key]:
            raise KeyError("Invalid key '%s'" % key)
        
        return session[SecuritySession.key][key]
        
    def __setitem__(self, key, item):
        '''data dictionary overload'''
        if key not in SecuritySession.subKeys:
            raise KeyError("Invalid security key %s" % key)
        
        session[SecuritySession.key][key] = item
           
    def get(self, kw):
        '''data dictionary overload'''
        return session[SecuritySession.key][kw]

    def clear(self):
        '''data dictionary overload'''
        raise KeyError("Data cannot be cleared from security session")
   
    def keys(self):
        '''data dictionary overload'''
        return session[SecuritySession.key].keys()

    def items(self):
        '''data dictionary overload'''
        return session[SecuritySession.key].items()

    def values(self):
        return session[SecuritySession.key].values()

    def has_key(self, key):
        return session[SecuritySession.key].has_key(key)

    # 'in' operator
    def __contains__(self, key):
        return key in session[SecuritySession.key]

    
    @classmethod
    def save(self):
        session.save()
        
    @classmethod
    def delete(self):
        """Delete security key from session object"""
        if SecuritySession.key in session:
            del session[SecuritySession.key]
            session.save()
        log.debug("Deleted security key to session object: %s" % session)

            
def setSecuritySession(**kw):
    '''Convenience wrapper to SecuritySession and it's set method'''
    SecuritySession().set(**kw)
   
           
class LoginServiceQueryError(Exception):
    """Error handling for SSOServiceQuery - a class which handles the 
    parsing of security args in a HTTP GET request for the LoginService"""
    
class SSOServiceQuery(object):
    """Create query string containing security credentials.  This is used by
    the Identity Provider pass the credentials over a HTTP GET back to the 
    Service Provider
    
    @cvar keys: query args to be copied into security session dict
    @type keys: tuple
    @cvar roleSep: delimit roles names in URL arg with this symbol
    @type roleSep: string
    @cvar argSep: standard arg separator for URLs
    @type argSep: string"""
    
    keys = SecuritySession.subKeys
    rolesSep = ","
    argSep = "&"
        
    def __str__(self):
        """Provide convenient short-cut for call to make query string

        @rtype: string
        @return: URL query string with security args"""
        return self.makeQueryStr()
   
    @classmethod
    def makeQueryStr(cls):
        """Create the query string containing the required security 
        credentials to return to the service provider
        
        @rtype: string
        @return: URL query string with security args"""
        
        # Make a copy of the security session dict reseting the
        # roles to a single string ready for passing over URL
        secDict = session[SecuritySession.key].copy()
        secDict['roles'] = cls.rolesSep.join(secDict['roles'])
        
        # Return the full query as a string
        return cls.argSep.join(["%s=%s" % (k, secDict[k]) for k in cls.keys])

    @classmethod
    def stripFromURI(cls, *params):
        """Make a new query string using Pylons request.params but stripping
        args relating to security
        
        @param params: parameters to remove instead of those contained in keys
        class variable
        @type additionalParams: tuple
        @rtype: string
        @return: URL query string with security args removed"""
        keys = params or cls.keys
        return str(cls.argSep.join(['%s=%s' % (i, request.params[i]) \
                                for i in request.params if i not in keys]))

    @classmethod
    def decodeRequestParams(cls):
        """Get security parameters from request.params received from Login 
        Service (IdP).  Decode parameters where necessary: roles are sent as a
        comma delimited list - convert into a list type
        
        @rtype: dict
        @return: dictionary of security parameters 
        """
        
        try:
            # request.params is actually a MultiDict type but for the purposes
            # of this code it can be treated as a regular dict type
            keys = dict([(k, request.params[k]) for k in cls.keys])
        except KeyError, e:
            LoginServiceQueryError, \
                '%s argument is missing from URL returned by Login Service' %\
                str(e)
                
        # Modify roles from a comma delimited string into a list
        if 'roles' in keys:
            keys['roles'] = keys['roles'].split(cls.rolesSep)

        return keys

# Backwards compatibility
LoginServiceQuery = SSOServiceQuery

# TODO: this could be used in the future to replace parts of BaseController.
# __call__ but leave for the moment as there may be a more modular solution
def constructURL(pathInfo,
                 scheme=None,
                 netloc=None,
                 altPathInfo='/discovery',
                 query=None):
    """Utility for BaseController.  Remove getCredentials calls"""
 
    if scheme is None and netloc is None:
        pathPfx = g.server
    else:
        pathPfx = urlunsplit((scheme, netloc, '', '', ''))
        
    if 'getCredentials' in pathInfo:
        logger.debug("Reverting request URL from getCredentials to discovery...")
        requestURL = pathPfx + altPathInfo       
    else:
        requestURL = pathPfx + pathInfo
        if query is None:
            query='&'.join(["%s=%s"%item for item in request.params.items()])

        if query:
            requestURL += '?' + query
            
    return requestURL
