#!/bin/env python

'''Validate M2Crypto/Crypto/DOM based encryption handler vs. pyXMLSec
code'''
from M2Crypto import X509, BIO, RSA
import base64

# For shared key encryption
from Crypto.Cipher import AES, DES3
import os

from ZSI.wstools.Namespaces import DSIG, ENCRYPTION, OASIS, WSU, WSA200403, \
                                   SOAP, SCHEMA # last included for xsi

from xml.xpath.Context import Context
from xml import xpath

from xml.dom.ext.reader.PyExpat import Reader
from ZSI.wstools.c14n import Canonicalize


def getElements(node, nameList):
    '''DOM Helper function for getting child elements from a given node'''
    # Avoid sub-string matches
    nameList = isinstance(nameList, basestring) and [nameList] or nameList
    return [n for n in node.childNodes if str(n.localName) in nameList]


class _ENCRYPTION(ENCRYPTION):
    '''Derived from ENCRYPTION class to add in extra 'tripledes-cbc' - is this
    any different to 'des-cbc'?  ENCRYPTION class implies that it is the same
    because it's assigned to 'BLOCK_3DES' ??'''
    BLOCK_TRIPLEDES = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
    
class EncryptionError(Exception):
    """Flags an error in the encryption process"""

class DecryptionError(Exception):
    """Raised from EncryptionHandler.decrypt if an error occurs with the
    decryption process"""


class EncryptionHandler(object):
    """Encrypt/Decrypt XML"""
    
    # Map namespace URIs to Crypto algorithm module and mode 
    cryptoAlg = \
    {
         _ENCRYPTION.WRAP_AES256:      {'module':       AES, 
                                        'mode':         AES.MODE_ECB,
                                        'blockSize':    16},
         
         # CBC (Cipher Block Chaining) modes
         _ENCRYPTION.BLOCK_AES256:     {'module':       AES, 
                                        'mode':         AES.MODE_CBC,
                                        'blockSize':    16},
                                        
         _ENCRYPTION.BLOCK_TRIPLEDES:  {'module':       DES3, 
                                        'mode':         DES3.MODE_CBC,
                                        'blockSize':    8}   
    }
    
     
    def __init__(self,
                 certFilePath=None, 
                 priKeyFilePath=None, 
                 priKeyPwd=None,
                 chkSecurityTokRef=False):
        
        self.__certFilePath = certFilePath
        self.__priKeyFilePath = priKeyFilePath
        self.__priKeyPwd = priKeyPwd
        
        self.__chkSecurityTokRef = chkSecurityTokRef


    def encrypt(self, xmlTxt):
        """Encrypt xml text
        
        Use Key Wrapping - message is encrypted using a shared key which 
        itself is encrypted with the public key provided by the X.509 cert.
        certFilePath"""
        
        # Use X.509 Cert to encrypt
        x509Cert = X509.load_cert(self.__certFilePath)

        docNode = Reader().fromString(xmlTxt)

      
        encrDataElem = docNode.createElement('EncryptedData')
        encrDataElem.setAttribute('xmlns', _ENCRYPTION.BASE)
        encrDataElem.setAttribute('Type', _ENCRYPTION.BASE + 'Element')
        
        # Encryption method used to encrypt the target data
        dataEncrMethodElem = docNode.createElement('EncryptionMethod')        
        dataEncrMethodElem.setAttribute('Algorithm', 
                                        _ENCRYPTION.BLOCK_TRIPLEDES)
        encrDataElem.appendChild(dataEncrMethodElem)
        
        
        # Key Info
        keyInfoElem = docNode.createElement('KeyInfo')
        keyInfoElem.setAttribute('xmlns', DSIG.BASE)
        encrDataElem.appendChild(keyInfoElem)
        
        encrKeyElem = docNode.createElement('EncryptedKey')
        encrKeyElem.setAttribute('xmlns', _ENCRYPTION.BASE)
        keyInfoElem.appendChild(encrKeyElem)
        
        # Encryption method used to encrypt the shared key
        keyEncrMethodElem = docNode.createElement('EncryptionMethod')
        keyEncrMethodElem.setAttribute('Algorithm', _ENCRYPTION.KT_RSA_1_5)
        encrKeyElem.appendChild(keyEncrMethodElem)


        # Key Info
        encrKeyInfoElem = docNode.createElement('KeyInfo')
        encrKeyInfoElem.setAttribute('xmlns', DSIG.BASE)
        encrKeyElem.appendChild(encrKeyInfoElem)
        
        keyNameElem = docNode.createElement('KeyName')
        encrKeyInfoElem.appendChild(keyNameElem)
        keyNameElem.appendChild(docNode.createTextNode(self.__priKeyFilePath))
        
        
        # References to what has been encrypted
        encrKeyCiphDataElem = docNode.createElement('CipherData')
        encrKeyElem.appendChild(encrKeyCiphDataElem)
        
        encrKeyCiphValElem = docNode.createElement('CipherValue')
        
        encrKeyCiphDataElem.appendChild(encrKeyCiphValElem)
                     
        # Cipher data
        ciphDataElem = docNode.createElement('CipherData')
        encrDataElem.appendChild(ciphDataElem)
        
        ciphValueElem = docNode.createElement('CipherValue')
        ciphDataElem.appendChild(ciphValueElem)

        import pdb;pdb.set_trace()

        # Get elements for encryption
        dataElem = docNode.childNodes[2]
        data = Canonicalize(dataElem)
     
        # DES3 algorithm requires data length to be a multiple of 8 - pad as
        # required    
        modData = len(data) % 8
        nPad = modData and 8 - modData or 0
        data += ' '*(nPad-1)        
              
        # Last byte should be number of padding bytes
        # (http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block)
        data += chr(nPad)
        
        # Generate shared key and input vector - for testing use hard-coded 
        # values to allow later comparison
        #sharedKey = os.urandom(24)
        #iv = os.urandom(8)
        sharedKey = '01234567890123456789ABCD'
        iv = 'ABCDEFGH'
        
        # Encrypt required elements - Prepend input vector to data
        alg = DES3.new(sharedKey, DES3.MODE_CBC, iv)
        encryptedData = alg.encrypt(iv + data)
        
        dataCiphValue = base64.encodestring(encryptedData).strip()

        ciphValueElem.appendChild(docNode.createTextNode(dataCiphValue))
        
        
        # ! Delete unencrypted message body elements !
        docNode.removeChild(dataElem)

        
        # Use X.509 cert public key to encrypt the shared key - Extract key
        # from the cert
        rsaPubKey = x509Cert.get_pubkey().get_rsa()
        
        # Encrypt the shared key
        encryptedSharedKey = rsaPubKey.public_encrypt(sharedKey, 
                                                      RSA.pkcs1_padding)
        
        encrKeyCiphVal = base64.encodestring(encryptedSharedKey).strip()
        
        # Add the encrypted shared key to the EncryptedKey section in the SOAP
        # header
        encrKeyCiphValElem.appendChild(docNode.createTextNode(encrKeyCiphVal))

        return Canonicalize(encrDataElem)
        
        
    def decrypt(self, encryptedXML):
        """Decrypt XML"""
        
        docNode = Reader().fromString(encryptedXML)
        processorNss = \
        {
            'xenc':   ENCRYPTION.BASE,
            'ds':     DSIG.BASE, 
            'wsu':    WSU.UTILITY, 
            'wsse':   OASIS.WSSE, 
            'soapenv':"http://schemas.xmlsoap.org/soap/envelope/" 
        }
        ctxt = Context(docNode, processorNss=processorNss)
        

        # Get EncryptedData node
        encrNode = xpath.Evaluate('//EncryptedData', 
                                  contextNode=docNode, 
                                  context=ctxt)[0]
                                  
                                  
        # Check for wrapped key encryption
        encrKeyNodes = xpath.Evaluate('//KeyInfo/EncryptedKey', 
                                      contextNode=docNode, 
                                      context=ctxt)
        if len(encrKeyNodes) > 1:
            raise DecryptionError, 'This implementation can only handle ' + \
                                   'single EncryptedKey element'
        
        try:
            encrKeyNode = encrKeyNodes[0]
        except:
            # Shared key encryption used - leave out for the moment
            raise DecryptionError, 'This implementation can only handle ' + \
                                   'wrapped key encryption'

        
        # Check wrapped key encryption method
        keyEncrMethodNode = getElements(encrKeyNode, 'EncryptionMethod')[0]     
        keyAlgorithm = keyEncrMethodNode.getAttributeNodeNS(None, 
                                                            "Algorithm").value
#        if keyAlgorithm != ENCRYPTION.KT_RSA_1_5:
#            raise DecryptionError, \
#            'Encryption algorithm for wrapped key is "%s", expecting "%s"' % \
#                (keyAlgorithm, ENCRYPTION.KT_RSA_1_5)

                                                            
        if self.__chkSecurityTokRef and self.__certFilePath:
             
            # Check input cert. against SecurityTokenReference
            securityTokRefXPath = '//KeyInfo/X509Data'
            securityTokRefNode = xpath.Evaluate(securityTokRefXPath, 
                                                contextNode=encrKeyNode, 
                                                context=ctxt)
            # Look for ds:X509* elements to check against X.509 cert input


        # Look for cipher data for wrapped key
        keyCiphDataNode = getElements(encrKeyNode, 'CipherData')[0]
        keyCiphValNode = getElements(keyCiphDataNode, 'CipherValue')[0]

        keyCiphVal = str(keyCiphValNode.childNodes[0].nodeValue)
        encryptedKey = base64.decodestring(keyCiphVal)

        # Read RSA Private key in order to decrypt wrapped key  
        priKeyFile = BIO.File(open(self.__priKeyFilePath))                                            
        priKey = RSA.load_key_bio(priKeyFile, 
                                  callback=lambda *ar, **kw: self.__priKeyPwd)
        
        import pdb;pdb.set_trace()
        sharedKey = priKey.private_decrypt(encryptedKey, RSA.pkcs1_padding)

#        x509Cert = X509.load_cert(self.__certFilePath)
#        rsaPubKey = x509Cert.get_pubkey().get_rsa()
#        rsaPubKey.public_decrypt(encryptedKey, RSA.pkcs1_padding)        
        
        # Check encryption method
        dataEncrMethodNode = getElements(encrNode, 'EncryptionMethod')[0]     
        dataAlgorithm = dataEncrMethodNode.getAttributeNodeNS(None, 
                                                        "Algorithm").value
        try:        
            # Match algorithm name to Crypto module
            CryptoAlg = self.cryptoAlg[dataAlgorithm]
            
        except KeyError:
            raise DecryptionError, \
'Encryption algorithm for data is "%s", supported algorithms are:\n "%s"' % \
                (keyAlgorithm, "\n".join(self.cryptoAlg.keys()))
            
        # Get Data
        dataCiphDataNode = getElements(encrNode, 'CipherData')[0]
        dataCiphValNode = getElements(dataCiphDataNode, 'CipherValue')[0]
    
        dataCiphVal = dataCiphValNode.childNodes[0].nodeValue
        encryptedData = base64.decodestring(dataCiphVal)
        
        alg = CryptoAlg['module'].new(sharedKey, CryptoAlg['mode'])
        decryptedData = alg.decrypt(encryptedData)
        
        # Strip prefix - assume is block size
        decryptedData = decryptedData[CryptoAlg['blockSize']:]
        
        # Strip any padding
        lastChar = decryptedData[-1]
        nPad = ord(lastChar)
        
        # Sanity check - there may be no padding at all - the last byte being
        # the end of the encrypted XML?
        #
        # TODO: are there better sanity checks than this?!
        if nPad < CryptoAlg['blockSize'] and nPad > 0 and \
           lastChar != '\n' and lastChar != '>':
            
            # Follow http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block -
            # last byte gives number of padding bytes
            decryptedData = decryptedData[:-nPad]
            
        # Parse the encrypted data
        rdr = Reader()
        dataNode = rdr.fromString(decryptedData, ownerDoc=docNode)
        
        # Add decrypted element to parent and remove encrypted one
        parentNode = encrNode._get_parentNode()
        parentNode.appendChild(dataNode)
        parentNode.removeChild(encrNode)
        
        from xml.dom.ext import ReleaseNode
        ReleaseNode(encrNode)
        
        # Ensure body_root attribute is up to date in case it was
        # previously encrypted
        print decryptedData
        import pdb;pdb.set_trace()        

        return docNode

if __name__ == "__main__":
    txt = None
    
    e = EncryptionHandler(certFilePath='../Junk-cert.pem',
                          priKeyFilePath='../Junk-key.pem',
                          priKeyPwd=open('../tmp2').read().strip())
    
    #encryptedData = e.encrypt(None)
    from ndg.security.XMLSecDoc import *
#    xmlSecDoc = XMLSecDoc(encrPubKeyFilePath='../Junk-cert.pem',
#                          encrPriKeyFilePath='../Junk-key.pem')
#    txt = xmlSecDoc.encrypt(filePath='encrypt4-doc.xml', rtnAsString=True)

    txt = open('encrypt4-doc.xml').read()
    encrTxt = e.encrypt(txt)
    open('xmlsecTestEncr.xml', 'w').write(encrTxt)
#    encrTxt = open('encrypt4-res-3DES.xml').read()
#    print e.decrypt(encrTxt)
