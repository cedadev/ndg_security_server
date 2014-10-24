"""Configuration file parsers specialisations

NERC DataGrid Project
"""
__author__ = "Philip Kershaw"
__date__ = "25/01/2010"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import re
from ConfigParser import SafeConfigParser

class CaseSensitiveConfigParser(SafeConfigParser):
    '''
    Subclass the SafeConfigParser - to preserve the original string case of the
    cfg section names - NB, the RawConfigParser default is to lowercase these 
    by default
    '''  
    def optionxform(self, optionstr):
        '''@type optionstr: basestring
        @param optionstr: config file option name
        @return: option name with case preserved
        @rtype: basestring
        '''
        return optionstr
    
class WithGetListConfigParser(CaseSensitiveConfigParser):
    LIST_STRING_PAT = re.compile(',\s*')
    
    def getlist(self, section, option):
        val = self.get(section, option)
        return WithGetListConfigParser.LIST_STRING_PAT.split(val)
