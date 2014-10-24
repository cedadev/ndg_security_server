#!/bin/env python
#
# First cut at getting GCMD definitions for NDG discovery gateway
#
# Import the client proxy object
from VocabServerAPI_dlService_client import * 
import xml.etree.ElementTree as ET
import sys


# Instantiate a client proxy object
loc = VocabServerAPI_dlServiceLocator()
vocabSrv = loc.getVocabServerAPI_dl()

try:
    #import pdb;pdb.set_trace()
    whatLists = vocabSrv.whatListsCat()
    print 'Lists in Catalogue at Vocab Server:\n'
    for elem in whatLists:
        x=ET.fromstring(elem)
        print x.find('entryTerm').text
except Exception, e:
    print "Failed whatLists: ", e

try:
    #this works: gives all members of GCMD vocabulary
    #res=vocabSrv.getList('P041','','')
    #for i in res:
    #    x=ET.fromstring(i)
    #    print x.find('entryTerm').text
    
    # this is just a toy example
    term='EARTH SCIENCE > Oceans > Ocean Waves > Wave Height'
    r=vocabSrv.verifyTerm('P041',term,'')
    print r
    res=ET.fromstring(vocabSrv.getList('P041',r[0],'')[0])
    print '{{',term,'}} is defined as {{',res.find('entryTermDef').text,'}}'
except Exception, e:
    print "Failed getList: ", e
