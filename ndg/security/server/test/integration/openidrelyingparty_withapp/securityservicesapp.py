#!/usr/bin/env python
"""NDG Security test harness for security web services middleware stack

NERC DataGrid Project

"""
__author__ = "P J Kershaw"
__date__ = "20/11/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import os
from os.path import dirname, abspath, join

    
# To start run 
# $ paster serve services.ini or run this file as a script
# $ ./securityservicesapp.py [port #]
if __name__ == '__main__':
    import sys
    import logging
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 7443
        
    cfgFilePath = os.path.join(dirname(abspath(__file__)), 
                               'securityservices.ini')
        
    from paste.httpserver import serve
    from paste.deploy import loadapp
    from paste.script.util.logging_config import fileConfig
    
    fileConfig(cfgFilePath)
    app = loadapp('config:%s' % cfgFilePath)
    serve(app, host='0.0.0.0', port=port)