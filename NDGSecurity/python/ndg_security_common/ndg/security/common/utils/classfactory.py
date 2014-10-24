"""
Class Factory

NERC DataGrid project
"""
__author__ = "C Byrom - Tessella"
__date__ = "28/08/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from ndg.security.common.utils.factory import (importModuleObject,
                                               callModuleObject)
 
def importClass(*arg, **kw):
    """Backwards compatibility - use importModuleObject instead"""
    nArgs = len(arg)
    if nArgs > 1:
        kw['objectName'] = arg.pop(1)
    else:
        kw['objectName'] = kw.pop('className', None)
        
    return importModuleObject(*arg, **kw)

            
def instantiateClass(*arg, **kw):
    """Wrapper to callModuleObject"""
    nArgs = len(arg)
    arg = list(arg)
    if nArgs > 1:
        kw['objectName'] = arg.pop(1)
    else:
        kw['objectName'] = kw.pop('className', None)
        
    if nArgs > 2:
        kw['objectArgs'] = arg.pop(2)
    else:
        kw['objectArgs'] = kw.pop('classArgs', None)
        
    if nArgs > 3:
        kw['objectProperties'] = arg.pop(3)
    else:
        kw['objectProperties'] = kw.pop('classProperties', None)

    arg = tuple(arg)
    return callModuleObject(*arg, **kw)
