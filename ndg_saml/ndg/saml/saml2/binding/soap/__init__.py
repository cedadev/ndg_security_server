"""SAML 2.0 SOAP Binding package

Implementation of SAML 2.0 for NDG Security

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "30/06/10"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from ndg.saml.saml2.core import Response

                                 
class SOAPBindingError(Exception):
    '''Base exception type for client SAML SOAP Binding'''


class SOAPBindingInvalidResponse(SOAPBindingError):
    '''Raise if the response is invalid'''
    def __init__(self, *arg, **kw):
        SOAPBindingError.__init__(self, *arg, **kw)
        self.__response = None
    
    def _getResponse(self):
        '''Gets the response corresponding to this error
        
        @return the response
        '''
        return self.__response

    def _setResponse(self, value):
        '''Sets the response corresponding to this error.
        
        @param value: the response
        '''
        if not isinstance(value, Response):
            raise TypeError('"response" must be a %r, got %r' % (Response,
                                                                 type(value)))
        self.__response = value
        
    response = property(fget=_getResponse, fset=_setResponse, 
                        doc="SAML Response associated with this exception")
