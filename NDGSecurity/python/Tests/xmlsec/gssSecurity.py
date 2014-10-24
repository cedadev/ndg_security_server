#!/bin/env python

try:
    from pyGridWare.security.gss.GssSignatureHandler import GssSignatureHandler
except TypeError: pass
from ZSI.writer import *

if __name__ == "__main__":
    gss = GssSignatureHandler()
    gss.setSecureMessage()
    
    sw = SoapWriter()
    gss.sign(sw)