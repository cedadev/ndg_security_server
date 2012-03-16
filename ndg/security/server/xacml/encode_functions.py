"""NDG Security

Extension functions for encoding strings
"""
__author__ = "R B Wilkinson"
__date__ = "15/03/12"
__copyright__ = ""
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import hashlib
import logging
import urllib

from ndg.xacml.core.attributevalue import AttributeValueClassFactory
from ndg.xacml.core.context.exceptions import XacmlContextTypeError
from ndg.xacml.core.functions import (AbstractFunction,
                                      FunctionClassFactoryBase,
                                      functionMap)

logging.basicConfig(level=logging.DEBUG)
attributeValueClassFactory = AttributeValueClassFactory()


class Md5HexBase(AbstractFunction):
    FUNCTION_NS = None
    TYPE = attributeValueClassFactory('http://www.w3.org/2001/XMLSchema#string')
    RETURN_TYPE = attributeValueClassFactory(
                                'http://www.w3.org/2001/XMLSchema#string')
    def evaluate(self, arg):
        """URL encodes a value
        
        @param arg: 
        @type arg: str
        @return: URL encoded value
        @rtype: str
        @raise XacmlContextTypeError: incorrect type for input
        """
        if not isinstance(arg, self.__class__.TYPE):
            raise XacmlContextTypeError('Expecting type %r for '
                                        'argument; got %r' %
                                        (self.__class__.TYPE,
                                         type(arg)))
        result = hashlib.md5(arg.value).hexdigest()
        return self.__class__.RETURN_TYPE(result)


class Md5HexFunctionClassFactory(FunctionClassFactoryBase):
    """Class Factory for *-md5hex XACML custom function classes

    @cvar FUNCTION_NAMES: function URNs
    @type FUNCTION_NAMES: tuple

    @cvar FUNCTION_NS_SUFFIX: generic suffix for md5hex function URNs
    @type FUNCTION_NS_SUFFIX: string

    @cvar FUNCTION_BASE_CLASS: base class for all md5hex classes
    @type FUNCTION_BASE_CLASS: type
    """
    FUNCTION_NAMES = (
        'urn:ndg:xacml:2.0:function:string-md5hex',
        'urn:ndg:xacml:2.0:function:anyURI-md5hex'
    )
    FUNCTION_NS_SUFFIX = '-md5hex'
    FUNCTION_BASE_CLASS = Md5HexBase


class UrlencodeBase(AbstractFunction):
    FUNCTION_NS = None
    TYPE = attributeValueClassFactory('http://www.w3.org/2001/XMLSchema#string')
    RETURN_TYPE = attributeValueClassFactory(
                                'http://www.w3.org/2001/XMLSchema#string')
    def evaluate(self, arg):
        """URL encodes a value
        
        @param arg: 
        @type arg: str
        @return: URL encoded value
        @rtype: str
        @raise XacmlContextTypeError: incorrect type for input
        """
        if not isinstance(arg, self.__class__.TYPE):
            raise XacmlContextTypeError('Expecting type %r for '
                                        'argument; got %r' %
                                        (self.__class__.TYPE,
                                         type(arg)))
        result = urllib.quote_plus(arg.value)
        return self.__class__.RETURN_TYPE(result)


class UrlencodeFunctionClassFactory(FunctionClassFactoryBase):
    """Class Factory for *-urlencode XACML custom function classes

    @cvar FUNCTION_NAMES: function URNs
    @type FUNCTION_NAMES: tuple

    @cvar FUNCTION_NS_SUFFIX: generic suffix for urlencode function URNs
    @type FUNCTION_NS_SUFFIX: string

    @cvar FUNCTION_BASE_CLASS: base class for all urlencode classes
    @type FUNCTION_BASE_CLASS: type
    """
    FUNCTION_NAMES = (
        'urn:ndg:xacml:2.0:function:string-urlencode',
        'urn:ndg:xacml:2.0:function:anyURI-urlencode'
    )
    FUNCTION_NS_SUFFIX = '-urlencode'
    FUNCTION_BASE_CLASS = UrlencodeBase


def addXacmlEncodeFunctions():
    """Add functions to encode values for, e.g., constructing paths from
    subject IDs.
    """
    for name in Md5HexFunctionClassFactory.FUNCTION_NAMES:
        functionMap.load_custom_function(name, Md5HexFunctionClassFactory())
    for name in UrlencodeFunctionClassFactory.FUNCTION_NAMES:
        functionMap.load_custom_function(name, UrlencodeFunctionClassFactory())
