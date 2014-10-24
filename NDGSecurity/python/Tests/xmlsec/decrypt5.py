#!/usr/bin/env python


from ndg.security.XMLSecDoc import *
    
if __name__ == "__main__":
    xmlSecDoc = XMLSecDoc()
    xmlSecDoc.decrypt(filePath="/home/users/pjkersha/Development/security/python/Tests/xmlsec/encrypt4-res.xml", 
                      encrKeyFilePath="/home/users/pjkersha/Development/security/python/Tests/xmlsec/badc-aa-key.pem",
                      encrKeyPwd="    ")