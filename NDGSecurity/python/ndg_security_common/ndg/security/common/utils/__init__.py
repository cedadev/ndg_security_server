"""Utilities package for NDG Security

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/04/09"
__copyright__ = ""
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import UserDict
from urlparse import urlparse, urlunparse, urljoin, ParseResult

# Interpret a string as a boolean
str2Bool = lambda str: str.lower() in ("yes", "true", "t", "1")


class UniqList(list):
    """Extended version of list type to enable a list with unique items.
    If an item is added that is already present then it is silently omitted
    from the list
    """
    def extend(self, iter):
        return super(UniqList, self).extend([i for i in iter if i not in self])
        
    def __iadd__(self, iter):
        return super(UniqList, self).__iadd__([i for i in iter 
                                               if i not in self])
         
    def append(self, item):
        for i in self:
            if i == item:
                return None
            
        return super(UniqList, self).append(item)


class TypedList(list):
    """Extend list type to enabled only items of a given type.  Supports
    any type where the array type in the Standard Library is restricted to 
    only limited set of primitive types
    """
    
    def __init__(self, elementType, *arg, **kw):
        """
        @type elementType: type/tuple
        @param elementType: object type or types which the list is allowed to
        contain.  If more than one type, pass as a tuple
        """
        self.__elementType = elementType
        super(TypedList, self).__init__(*arg, **kw)
    
    def _getElementType(self):
        return self.__elementType
    
    elementType = property(fget=_getElementType, 
                           doc="The allowed type or types for list elements")
     
    def extend(self, iter):
        for i in iter:
            if not isinstance(i, self.__elementType):
                raise TypeError("List items must be of type %s" % 
                                (self.__elementType,))
                
        return super(TypedList, self).extend(iter)
        
    def __iadd__(self, iter):
        for i in iter:
            if not isinstance(i, self.__elementType):
                raise TypeError("List items must be of type %s" % 
                                (self.__elementType,))
                    
        return super(TypedList, self).__iadd__(iter)
         
    def append(self, item):
        if not isinstance(item, self.__elementType):
                raise TypeError("List items must be of type %s" % 
                                (self.__elementType,))
    
        return super(TypedList, self).append(item)

class RestrictedKeyNamesDict(dict):
    """Utility class for holding a constrained list of key names
    """
    
    def __init__(self, *arg, **kw):
        """Alter standard dict() initialisation to fix key names set at 
        initialisation
        """
        super(RestrictedKeyNamesDict, self).__init__(*arg, **kw)
        self.__keyNames = self.keys() 
          
    def __setitem__(self, key, val):
        if key not in self.__keyNames:
            raise KeyError('Key name %r not recognised.  Valid key names '
                           'are: %r' % (key, self.__keyNames))
            
        dict.__setitem__(self, key, val)

    def update(self, d, **kw):        
        for dictArg in (d, kw):
            for k in dictArg:
                if k not in self.__keyNames:
                    raise KeyError('Key name "%s" not recognised.  Valid '
                                   'key names are: %s' % 
                                   self.__keyNames)
        
        dict.update(self, d, **kw)
        
  
class VettedDict(UserDict.DictMixin):
    """Enforce custom checking on keys and items before addition to a 
    dictionary
    """
    
    def __init__(self, *args):
        """Initialise setting the allowed type or types for keys and items
        
        @param args: two arguments: the first is a callable which filters for 
        permissable keys in this dict, the second sets the type or list of
        types permissable for items in this dict
        @type args: tuple
        """
        if len(args) != 2:
            raise TypeError('__init__() takes 2 arguments, KeyFilter and '
                            'valueFilter (%d given)' % len(args))
        
        # Validation of inputs
        for arg, argName in zip(args, ('KeyFilter', 'valueFilter')):
            if not callable(arg):
                raise TypeError('Expecting callable for %r input; got %r' % 
                                (argName, type(arg)))

        self.__KeyFilter, self.__valueFilter = args
        
        self.__map = {}
        
    def _verifyKeyValPair(self, key, val):
        """Check given key value pair and return False if they should be 
        filtered out.  Filter functions may also raise an exception if they
        wish to abort completely
        
        @param key: dict key to check
        @type key: basestring
        @param val: value to check
        @type val: any
        """
        if not self.__KeyFilter(key):
            return False
        
        elif not self.__valueFilter(val):
            return False
        
        else:
            return True
                  
    def __setitem__(self, key, val):
        """Enforce type checking when setting new items
        
        @param key: key for item to set
        @type key: any
        @param val: value to set for this key
        @type val: any
        """       
        if self._verifyKeyValPair(key, val):
            self.__map[key] = val

    def __getitem__(self, key):
        """Provide implementation for getting items
        @param key: key for item to retrieve
        @type key: any
        @return: value for input key
        @rtype: any
        """
        if key not in self.__map:
            raise KeyError('%r key not found in dict' % key)
        
        return self.__map[key]
    
    def get(self, key, *arg):
        """Provide implementation of get item with default
        
        @param key: key for item to retrieve
        @type key: any
        @param arg: use to set a default argument
        @type arg: tuple
        """
        if key in self.__map:
            return self.__map[key]
        
        elif len(arg) > 1:
            # Default value set
            return arg[1]
        else:
            return None

    def __repr__(self):
        return repr(self.__map)
    
    def keys(self):
        return self.__map.keys()
    
    def items(self):
        return self.__map.items()
    
    def values(self):
        return self.__map.values()
    
    def __contains__(self, val):
        return self.__map.__contains__(val)
    



class FakeUrllib2HTTPRequest(object):
    """Substitute for urllib2 HTTP request to enable use of cookielib with 
    httplib. Adapted from:
    
    http://stackoverflow.com/questions/1016765/how-to-use-cookielib-with-httplib-in-python
    """

    def __init__(self, uri, headers={}):
        '''@param uri: URI for request
        @type uri: string or ParseResult
        @param headers: HTTP header fields 
        @type headers: dict
        '''
        if isinstance(uri, basestring):
            self._parsed_uri = urlparse(uri)
            
        elif isinstance(uri, ParseResult):
            self._parsed_uri = uri
        else:
            raise TypeError('Expecting string or ParseResult type for input '
                            'uri; got %r' % type(uri))
        
        self._headers = {}
        for key, value in headers.items():
            self.add_header(key, value)

    def has_header(self, name):
        '''@param name: header field name to check
        @type name: basestring
        @return: True if field name is in HTTP header
        @rtype: bool
        '''
        return name in self._headers

    def add_header(self, key, val):
        '''@param key: field name to add
        @type key: basestring
        @param val: field value to add
        @type val: basestring
        '''
        self._headers[key.capitalize()] = val

    def add_unredirected_header(self, key, val):
        '''Add header item capitalising the field name
        @param key: field name to add
        @type key: basestring
        @param val: field value to add
        @type val: basestring
        '''
        self._headers[key.capitalize()] = val

    def is_unverifiable(self):
        '''@return: true
        @rtype: bool
        '''
        return True

    def get_type(self):
        '''@return: protocol scheme e.g. http
        @rtype: basestring
        '''
        return self._parsed_uri.scheme

    def get_full_url(self):
        '''@return: complete URL for the request
        @rtype: basestring
        '''
        return urlunparse(self._parsed_uri)

    def get_header(self, header_name, default=None):
        '''@param header_name: field name of header item to return
        @type header_name: basestring
        @param default: default value to set if header name not in headers
        @type default: any
        @return: value for given header field name
        @rtype: basestring or type determined by default
        '''
        return self._headers.get(header_name, default)

    def get_host(self):
        '''@return: host name
        @rtype: basestring
        '''
        return self._parsed_uri.scheme.split(':', 1)[0]

    get_origin_req_host = get_host

    def get_headers(self):
        '''@return: header items
        @rtype: dict
        '''
        return self._headers
