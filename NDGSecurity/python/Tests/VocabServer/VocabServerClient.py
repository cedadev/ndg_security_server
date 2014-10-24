#!/bin/env python
#
# Exampe echo client, to show extended code generation in ZSI
#
# Import the client proxy object
from VocabServerAPI_dlService_client import * 
import sys


# Instantiate a client proxy object
loc = VocabServerAPI_dlServiceLocator()
vocabSrv = loc.getVocabServerAPI_dl()

try:
    #import pdb;pdb.set_trace()
    whatLists = vocabSrv.whatListsCat()
    print 'whatListsCat:\n'
    for elem in whatLists:
        print elem
        
except Exception, e:
    print "Failed: ", e

