#!/usr/bin/env python
"""NDG Security test harness for authorisation middleware used to secure an
application

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - See top-level directory for LICENSE file"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: securedapp.py 7861 2011-01-31 13:48:11Z pjkersha $"
import optparse   
from os import path
from ndg.security.server.utils.paste_utils import PasteDeployAppServer

INI_FILENAME = 'securedapp.ini'
   
# To start run 
# $ paster serve services.ini 
#
# or run this file as a script.  For options:
# $ ./securedapp.py -h
if __name__ == '__main__': 
    cfgFilePath = path.join(path.dirname(path.abspath(__file__)), INI_FILENAME)
        
    parser = optparse.OptionParser()
    parser.add_option("-p",
                      "--port",
                      dest="port",
                      default=7080,
                      type='int',
                      help="port number to run under")

    parser.add_option("-c",
                      "--conf",
                      dest="configFilePath",
                      default=cfgFilePath,
                      help="Configuration file path")
    
    opt = parser.parse_args()[0]

    server = PasteDeployAppServer(cfgFilePath=opt.configFilePath, 
                                  port=opt.port) 
    server.start()