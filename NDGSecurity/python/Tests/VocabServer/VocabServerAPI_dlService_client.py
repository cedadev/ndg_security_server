################################################## 
# VocabServerAPI_dlService_client.py 
# generated by ZSI.generate.wsdl2python
##################################################



import urlparse, types
from ZSI.TCcompound import ComplexType, Struct
from ZSI import client
import ZSI

from VocabServerAPI_dlService_messages import *
from urllib2Client import URLlib2Binding

# Locator
class VocabServerAPI_dlServiceLocator:
    VocabServerAPI_dl_address = "http://grid.bodc.nerc.ac.uk/axis/services/VocabServerAPI_dl"
    def getVocabServerAPI_dlAddress(self):
        return VocabServerAPI_dlServiceLocator.VocabServerAPI_dl_address
    def getVocabServerAPI_dl(self, url=None, **kw):
        return VocabServerAPI_dlSoapBindingSOAP(url or VocabServerAPI_dlServiceLocator.VocabServerAPI_dl_address, **kw)

# Methods
class VocabServerAPI_dlSoapBindingSOAP:
    def __init__(self, url, **kw):
        kw.setdefault("readerclass", None)
        kw.setdefault("writerclass", None)
        # no resource properties
        #self.binding = client.Binding(url=url, **kw)
        self.binding = URLlib2Binding(url=url, **kw)
        # no ws-addressing

    # op: <ZSI.wstools.WSDLTools.Message instance at 0xb6d67c8c>
    def whatLists(self, in0):

        request = whatListsRequest()
        request.in0 = in0

        kw = {}
        # no input wsaction
        self.binding.Send(None, None, request, soapaction="", **kw)
        # no output wsaction
        response = self.binding.Receive(whatListsResponse.typecode)
        whatListsReturn = response.whatListsReturn
        return whatListsReturn

    # op: <ZSI.wstools.WSDLTools.Message instance at 0xb6d6cb0c>
    def getList(self, in0,in1,in2):

        request = getListRequest()
        request.in0 = in0
        request.in1 = in1
        request.in2 = in2

        kw = {}
        # no input wsaction
        self.binding.Send(None, None, request, soapaction="", **kw)
        # no output wsaction
        response = self.binding.Receive(getListResponse.typecode)
        getListReturn = response.getListReturn
        return getListReturn

    # op: <ZSI.wstools.WSDLTools.Message instance at 0xb6d67b0c>
    def verifyTerm(self, in0,in1,in2):

        request = verifyTermRequest()
        request.in0 = in0
        request.in1 = in1
        request.in2 = in2

        kw = {}
        # no input wsaction
        self.binding.Send(None, None, request, soapaction="", **kw)
        # no output wsaction
        response = self.binding.Receive(verifyTermResponse.typecode)
        verifyTermReturn = response.verifyTermReturn
        return verifyTermReturn

    # op: <ZSI.wstools.WSDLTools.Message instance at 0xb6d6ceec>
    def pvMap(self, in0,in1,in2):

        request = pvMapRequest()
        request.in0 = in0
        request.in1 = in1
        request.in2 = in2

        kw = {}
        # no input wsaction
        self.binding.Send(None, None, request, soapaction="", **kw)
        # no output wsaction
        response = self.binding.Receive(pvMapResponse.typecode)
        pvMapReturn = response.pvMapReturn
        return pvMapReturn

    # op: <ZSI.wstools.WSDLTools.Message instance at 0xb6d742ec>
    def getPhenomDict(self, in0):

        request = getPhenomDictRequest()
        request.in0 = in0

        kw = {}
        # no input wsaction
        self.binding.Send(None, None, request, soapaction="", **kw)
        # no output wsaction
        response = self.binding.Receive(getPhenomDictResponse.typecode)
        getPhenomDictReturn = response.getPhenomDictReturn
        return getPhenomDictReturn

    # op: <ZSI.wstools.WSDLTools.Message instance at 0xb6d6cd6c>
    def whatListsCat(self):

        request = whatListsCatRequest()

        kw = {}
        # no input wsaction
        self.binding.Send(None, None, request, soapaction="", **kw)
        # no output wsaction
        response = self.binding.Receive(whatListsCatResponse.typecode)
        whatListsCatReturn = response.whatListsCatReturn
        return whatListsCatReturn

    # op: <ZSI.wstools.WSDLTools.Message instance at 0xb6d7420c>
    def searchVocab(self, in0,in1,in2):

        request = searchVocabRequest()
        request.in0 = in0
        request.in1 = in1
        request.in2 = in2

        kw = {}
        # no input wsaction
        self.binding.Send(None, None, request, soapaction="", **kw)
        # no output wsaction
        response = self.binding.Receive(searchVocabResponse.typecode)
        searchVocabReturn = response.searchVocabReturn
        return searchVocabReturn
