"""Utilities module for NDG Security SAML implementation

NERC DataGrid Project

This implementation is adapted from the Java OpenSAML implementation.  The 
copyright and licence information are included here:

Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
__author__ = "P J Kershaw"
__date__ = "10/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
try:
    from datetime import strptime
except ImportError:
    # Allow for Python < 2.5
    from time import strptime as _strptime
    strptime = lambda datetimeStr, format: datetime(*(_strptime(datetimeStr, 
                                                                format)[0:6]))
from datetime import datetime, timedelta

        
# Interpret a string as a boolean
str2Bool = lambda str: str.lower() in ("yes", "true", "t", "1")

      
class SAMLDateTime(object):
    """Generic datetime formatting utility for SAML timestamps - XMLSchema
    Datetime format
    
    @cvar DATETIME_FORMAT: date/time format string for SAML timestamps
    @type DATETIME_FORMAT: string
    """
    DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
    
    @classmethod
    def toString(cls, dtValue):
        """Convert issue instant datetime to correct string type for output
        
        @type dtValue: datetime.datetime
        @param dtValue: issue instance as a datetime
        @rtype: basestring
        @return: issue instance as a string
        """
        if not isinstance(dtValue, datetime):
            raise TypeError("Expecting datetime type for string conversion, "
                            "got %r" % dtValue)
            
        # isoformat provides the correct formatting
#        return dtIssueInstant.strftime(cls.DATETIME_FORMAT)
        return datetime.isoformat(dtValue)+'Z'

    @classmethod
    def fromString(cls, strDateTime):
        """Convert issue instant string to datetime type
        
        @type strDateTime: basestring
        @param strDateTime: issue instance as a string
        @rtype: datetime.datetime
        @return: issue instance as a datetime
        """
        if not isinstance(strDateTime, basestring):
            raise TypeError("Expecting basestring derived type for string "
                            "conversion, got %r" % strDateTime)
        
        # Workaround for seconds fraction as strptime doesn't seem able to deal
        # with this 
        dateTimeTuple = strDateTime.split('.')
        
        # Seconds fraction may not be present - see
        # http://www.w3.org/TR/xmlschema-2/#dateTime - explicitly test for ...
        if len(dateTimeTuple) == 2:
            strDateTimeFraction, strSecondsFraction = dateTimeTuple
            secondsFraction = float("0." + strSecondsFraction.replace('Z', ''))
        else:
            strDateTimeFraction = dateTimeTuple[0].replace('Z', '')
            secondsFraction = 0.
            
        dtValue = datetime.strptime(strDateTimeFraction, cls.DATETIME_FORMAT)
        dtValue += timedelta(seconds=secondsFraction)
        
        return dtValue


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
        """@return: element type for this list
        @rtype: type
        """
        return self.__elementType
    
    elementType = property(fget=_getElementType, 
                           doc="The allowed type or types for list elements")
     
    def extend(self, iter):
        """Extend an existing list with the input iterable
        @param iter: iterable to extend list with
        @type iter: iterable
        """
        for i in iter:
            if not isinstance(i, self.__elementType):
                raise TypeError("List items must be of type %s" % 
                                (self.__elementType,))
                
        return super(TypedList, self).extend(iter)
        
    def __iadd__(self, iter):
        """Extend an existing list with the input iterable with += operator
        
        @param iter: iterable to extend list with
        @type iter: iterable
        """
        for i in iter:
            if not isinstance(i, self.__elementType):
                raise TypeError("List items must be of type %s" % 
                                (self.__elementType,))
                    
        return super(TypedList, self).__iadd__(iter)
         
    def append(self, item):
        """Append a list with the given item
        
        @param item: item to extend list
        @type item: must agree witj "elementType" attribute of this list 
        """
        if not isinstance(item, self.__elementType):
                raise TypeError("List items must be of type %s" % 
                                (self.__elementType,))
    
        return super(TypedList, self).append(item)
