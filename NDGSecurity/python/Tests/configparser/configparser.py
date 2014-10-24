#!/usr/bin/env python
"""Config parser test code

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/05/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

from ndg.security.common.utils.configfileparsers import (
                                                    CaseSensitiveConfigParser)

class MyConfigFileError(Exception):
    pass

class MyConfigFile(object):
    """Read a config file containing the parameters defined in options"""
    
    # Option name, the retrieval function type to use - edit this list to add
    # and remove parameters as required
    options = {
       "myString": CaseSensitiveConfigParser.get, 
       "myInt": CaseSensitiveConfigParser.getint, 
       "myBool": CaseSensitiveConfigParser.getboolean
    }
    
    def read(self, filePath):
        cfg = CaseSensitiveConfigParser()
        nParsed = cfg.read(filePath)
        if len(nParsed) == 0:
            raise MyConfigFileError("Error parsing %s" % filePath)
        
        for optName in MyConfigFile.options:
            setattr(self,
                    optName, 
                    MyConfigFile.options[optName](cfg, 'DEFAULT', optName))
            
if __name__ == "__main__":
    myCfg = MyConfigFile()
    myCfg.read('./my.cfg')
    print myCfg.myString
    print myCfg.myInt
    print myCfg.myBool