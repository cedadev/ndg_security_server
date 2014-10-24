#!/usr/bin/env python

"""NDG MyProxy admin command line interface - enables new users to be
registered with NDG CA and added to the MyProxy repository.  This command 
must be run from the MyProxy host.

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "19/05/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id"

# Handle socket errors from WS
import socket 

# Command line processing
import sys
import os
import optparse
import getpass


from ndg.security.MyProxy import *


#_____________________________________________________________________________
if __name__ == '__main__':

    parser = optparse.OptionParser()
    parser.add_option("-n", 
                      "--add-user", 
                      dest="newUserName",
                      help=\
                      "add a new user to MyProxy with the username given")

    parser.add_option("-f", 
                      "--properties-file",
                      dest="propFilePath",
                      help=\
"file path for MyProxy properties file - default is ./myProxyProperties.xml")

    parser.add_option("-p",
                      "--pass-phrase-from-stdin",
                      action="store_true",
                      dest="bPassPhraseFromStdin",
                      default=False,
                      help="""\
Take user's pass-phrase from stdin.  If this flag is omitted, pass-phrase is
prompted for from tty""")

    (options, args) = parser.parse_args()


    if not options.newUserName:
        sys.stderr.write("No new username set.\n\n")
        parser.print_help()
        sys.exit(1)
        
        
    if options.propFilePath is None:
        # Check in installation area otherwise assume local directory
        options.propFilePath = os.path.join(".", 'myProxyProperties.xml')


    if options.bPassPhraseFromStdin:
        # Read from standard input
        passPhrase = sys.stdin.read().strip()           
    else:
        # Obtain from prompt
        try:
            passPhrase = getpass.getpass(prompt="New user pass-phrase: ") 
            confirmPassPhrase = \
                            getpass.getpass(prompt="Confirm pass-phrase: ")
            
            if confirmPassPhrase != passPhrase:
                sys.stderr.write("Pass-phrases are not the same - exiting.\n")
                sys.exit(1)
                
        except KeyboardInterrupt:
            sys.exit(1)


    # Create server instance at start up
    try:
        myPx = MyProxy(propFilePath=options.propFilePath)

    except Exception, e:
        sys.stderr.write("Initialising MyProxy client: %s\n\n" % str(e))
        parser.print_help()
        sys.exit(1)
    
    try:
         myPx.addUser(options.newUserName, passPhrase)

    except Exception, e:
        sys.stderr.write("MyProxy client: %s\n\n" % str(e))
        parser.print_help()
        sys.exit(1)
        
    sys.exit(0)