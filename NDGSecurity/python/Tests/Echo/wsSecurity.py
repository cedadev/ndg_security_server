#!/bin/env python

"""WS-Security test class includes digital signature handler

NERC Data Grid Project

P J Kershaw 01/09/06

Copyright (C) 2009 Science and Technology Facilities Council

"""

__revision__ = '$Id$'

import re

# Digest and signature/verify
from sha import sha
from M2Crypto import X509, BIO, RSA
import base64

# For shared key encryption
from Crypto.Cipher import AES, DES3
import os

import ZSI
from ZSI.wstools.Namespaces import DSIG, ENCRYPTION, OASIS, WSU, WSA200403, \
                                   SOAP, SCHEMA # last included for xsi
                                   
from ZSI.TC import ElementDeclaration,TypeDefinition
from ZSI.generate.pyclass import pyclass_type

from ZSI.wstools.Utility import DOMException, SplitQName
from ZSI.wstools.Utility import NamespaceError, MessageInterface, ElementProxy

# XML Parsing
from cStringIO import StringIO
from Ft.Xml.Domlette import NonvalidatingReaderBase, NonvalidatingReader
from Ft.Xml import XPath

# Canonicalization
from ZSI.wstools.c14n import Canonicalize
from xml.dom import Node
from xml.xpath.Context import Context
from xml import xpath

# Include for re-parsing doc ready for canonicalization in sign method - see
# associated note
from xml.dom.ext.reader.PyExpat import Reader


class _ENCRYPTION(ENCRYPTION):
    '''Derived from ENCRYPTION class to add in extra 'tripledes-cbc' - is this
    any different to 'des-cbc'?  ENCRYPTION class implies that it is the same
    because it's assigned to 'BLOCK_3DES' ??'''
    BLOCK_TRIPLEDES = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"

class _WSU(WSU):
    '''Try different utility namespace for use with WebSphere'''
    #UTILITY = "http://schemas.xmlsoap.org/ws/2003/06/utility"
    UTILITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    
def getElements(node, nameList):
    '''DOM Helper function for getting child elements from a given node'''
    # Avoid sub-string matches
    nameList = isinstance(nameList, basestring) and [nameList] or nameList
    return [n for n in node.childNodes if str(n.localName) in nameList]


class VerifyError(Exception):
    """Raised from SignatureHandler.verify if signature is invalid"""

class SignatureError(Exception):
    """Flag if an error occurs during signature generation"""
        
class SignatureHandler(object):
    
    def __init__(self,
                 certFilePath=None, 
                 priKeyFilePath=None, 
                 priKeyPwd=None):
        
        self.__certFilePath = certFilePath
        self.__priKeyFilePath = priKeyFilePath
        self.__priKeyPwd = priKeyPwd


    def sign(self, soapWriter):
        '''Sign the message body and binary security token of a SOAP message
        '''
        # Add X.509 cert as binary security token
        x509Cert = X509.load_cert(self.__certFilePath)
        
        x509CertPat = re.compile(\
            '-----BEGIN CERTIFICATE-----\n?(.*?)\n?-----END CERTIFICATE-----',
            re.S)
        x509CertStr = x509CertPat.findall(x509Cert.as_pem())[0]

        soapWriter._header.setNamespaceAttribute('wsse', OASIS.WSSE)
        soapWriter._header.setNamespaceAttribute('wsu', _WSU.UTILITY)
        soapWriter._header.setNamespaceAttribute('ds', DSIG.BASE)
        soapWriter._header.setNamespaceAttribute('ec', DSIG.C14N_EXCL)
        
        # TODO: Put in a check to make sure <wsse:security> isn't already 
        # present in header
        wsseElem = soapWriter._header.createAppendElement(OASIS.WSSE, 
                                                         'Security')
        wsseElem.setNamespaceAttribute('wsse', OASIS.WSSE)
        wsseElem.node.setAttribute('SOAP-ENV:mustUnderstand', "1")
        
        binSecTokElem = wsseElem.createAppendElement(OASIS.WSSE, 
                                                     'BinarySecurityToken')
        
        # Change value and encoding types to suite WebSphere
#        binSecTokElem.node.setAttribute('ValueType', "wsse:X509v3")
        valueType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509"
        binSecTokElem.node.setAttribute('ValueType', valueType)
#        binSecTokElem.node.setAttribute('EncodingType', "wsse:Base64Binary")
        encodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
        binSecTokElem.node.setAttribute('EncodingType', encodingType)
        
        # Add ID so that the binary token can be included in the signature
        binSecTokElem.node.setAttribute('wsu:Id', "binaryToken")

        binSecTokElem.createAppendTextNode(x509CertStr)

        
        # Signature
        signatureElem = wsseElem.createAppendElement(DSIG.BASE, 'Signature')
        signatureElem.setNamespaceAttribute('ds', DSIG.BASE)
        
        # Signature - Signed Info
        signedInfoElem = signatureElem.createAppendElement(DSIG.BASE, 
                                                           'SignedInfo')
        
        # Signed Info - Canonicalization method
        signedInfoC14nInclNS = ['xsi', 'xsd', 'SOAP-ENV', 'ds', 'wsse']
        signedInfoC14nKw = {'unsuppressedPrefixes': signedInfoC14nInclNS} 
        c14nMethodElem = signedInfoElem.createAppendElement(DSIG.BASE,
                                                    'CanonicalizationMethod')
        c14nMethodElem.node.setAttribute('Algorithm', DSIG.C14N_EXCL)
        c14nInclNamespacesElem = c14nMethodElem.createAppendElement(\
						DSIG.C14N_EXCL,
                                                'InclusiveNamespaces')
        c14nInclNamespacesElem.node.setAttribute('PrefixList', 
			' '.join(signedInfoC14nInclNS))
        
        # Signed Info - Signature method
        sigMethodElem = signedInfoElem.createAppendElement(DSIG.BASE,
                                                    'SignatureMethod')
        #sigMethodElem.node.setAttribute('Algorithm', DSIG.DIGEST_SHA1)
        sigMethodElem.node.setAttribute('Algorithm', DSIG.SIG_RSA_SHA1)
        
        # Signature - Signature value
        signatureValueElem = signatureElem.createAppendElement(DSIG.BASE, 
                                                             'SignatureValue')
        
        # Key Info
        KeyInfoElem = signatureElem.createAppendElement(DSIG.BASE, 'KeyInfo')
        secTokRefElem = KeyInfoElem.createAppendElement(OASIS.WSSE, 
                                                  'SecurityTokenReference')
        
        # Reference back to the binary token included earlier
        wsseRefElem = secTokRefElem.createAppendElement(OASIS.WSSE, 
                                                        'Reference')
        wsseRefElem.node.setAttribute('URI', "#binaryToken")
        
        # Add Reference to body so that it can be included in the signature
        soapWriter.body.node.setAttribute('wsu:Id', "body")
        soapWriter.body.node.setAttribute('xmlns:wsu', _WSU.UTILITY)

        # Serialize and re-parse prior to reference generation - calculating
        # canonicalization based on soapWriter.dom.node seems to give an
        # error: the order of wsu:Id attribute is not correct
        docNode = Reader().fromString(str(soapWriter))
        
        # Namespaces for XPath searches
        processorNss = \
        {
            'ds':     DSIG.BASE, 
            'wsu':    _WSU.UTILITY, 
            'wsse':   OASIS.WSSE, 
            'soapenv':"http://schemas.xmlsoap.org/soap/envelope/" 
        }
        ctxt = Context(docNode, processorNss=processorNss)
        idNodes = xpath.Evaluate('//*[@wsu:Id]', 
                                 contextNode=docNode, 
                                 context=ctxt)
        
        # Leave out token
        #idNodes = [idNodes[1]]

        # 1) Reference Generation
        #
        # Find references
        c14nKw = {}
        c14nKw['unsuppressedPrefixes'] = ['xmlns', 'xsi', 'xsd', 'SOAP-ENV', 'wsu', 'wsse', 'ns1']
        for idNode in idNodes:
            
            # Set URI attribute to point to reference to be signed
            #uri = u"#" + idNode.getAttribute('wsu:Id')
            uri = u"#" + idNode.attributes[(_WSU.UTILITY, 'Id')].value
            
            # Canonicalize reference
            c14nRef = Canonicalize(idNode, **c14nKw)
            
            # Calculate digest for reference and base 64 encode
            #
            # Nb. encodestring adds a trailing newline char
            digestValue = base64.encodestring(sha(c14nRef).digest()).strip()


            # Add a new reference element to SignedInfo
            refElem = signedInfoElem.createAppendElement(DSIG.BASE, 
                                                         'Reference')
            refElem.node.setAttribute('URI', uri)
            
            # Use ds:Transforms or wsse:TransformationParameters?
            transformsElem = refElem.createAppendElement(DSIG.BASE, 
                                                        'Transforms')
            transformElem = transformsElem.createAppendElement(DSIG.BASE, 
                                                               'Transform')
#            transformElem.node.setAttribute('Algorithm', DSIG.C14N)
            transformElem.node.setAttribute('Algorithm', DSIG.C14N_EXCL)

            inclNamespacesElem = transformElem.createAppendElement(\
							DSIG.C14N_EXCL,
                                                       'InclusiveNamespaces')
            inclNamespacesElem.node.setAttribute('PrefixList',
				' '.join(c14nKw['unsuppressedPrefixes']))
            
            # Digest Method 
            digestMethodElem = refElem.createAppendElement(DSIG.BASE, 
                                                           'DigestMethod')
            digestMethodElem.node.setAttribute('Algorithm', DSIG.DIGEST_SHA1)
            
            # Digest Value
            digestValueElem = refElem.createAppendElement(DSIG.BASE, 
                                                          'DigestValue')
            digestValueElem.createAppendTextNode(digestValue)

   
        # 2) Signature Generation
        #

        # Test against signature generated by pyXMLSec version
        #xmlTxt = open('./wsseSign-xmlsec-res.xml').read()
        #dom = NonvalidatingReader.parseStream(StringIO(xmlTxt))
        
        # Canonicalize the signedInfo node
        #
        # Nb. When extracted the code adds the namespace attribute to the
        # signedInfo!  This has important consequences for validation -
        #
        # 1) Do you strip the namespace attribute before taking the digest to 
        # ensure the text is exactly the same as what is displayed in the 
        # message?
        #
        # 2) Leave it in and assume the validation algorithm will expect to 
        # add in the namespace attribute?!
        #
        # http://www.w3.org/TR/xml-c14n#NoNSPrefixRewriting implies you need 
        # to include namespace declarations for namespaces referenced in a doc
        # subset - yes to 2)
        #c14nSignedInfo = signedInfoElem.canonicalize()
        c14nSignedInfo = Canonicalize(signedInfoElem.node, **signedInfoC14nKw)

        # Calculate digest of SignedInfo
        signedInfoDigestValue = sha(c14nSignedInfo).digest().strip()
        
        # Read Private key to sign with    
        priKeyFile = BIO.File(open(self.__priKeyFilePath))                                            
        priKey = RSA.load_key_bio(priKeyFile, 
                                  callback=lambda *ar, **kw: self.__priKeyPwd)
        
        # Sign using the private key and base 64 encode the result
        signatureValue = priKey.sign(signedInfoDigestValue)
        b64EncSignatureValue = base64.encodestring(signatureValue).strip()

        # Add to <SignatureValue>
        signatureValueElem.createAppendTextNode(b64EncSignatureValue)
        
        # Extract RSA public key from the cert
        rsaPubKey = x509Cert.get_pubkey().get_rsa()
        
        # Check the signature 
#        verify = bool(rsaPubKey.verify(signedInfoDigestValue, signatureValue))
#        
#        open('soap.xml', 'w').write(str(soapWriter))
        import pdb;pdb.set_trace() 
        print "Signature Generated"
        print str(soapWriter)


    def verify(self, parsedSOAP):
        """Verify signature"""
        
        processorNss = \
        {
            'ds':     DSIG.BASE, 
            'wsu':    _WSU.UTILITY, 
            'wsse':   OASIS.WSSE, 
            'soapenv':"http://schemas.xmlsoap.org/soap/envelope/" 
        }
        ctxt = Context(parsedSOAP.dom, processorNss=processorNss)
        

        signatureNodes = xpath.Evaluate('//ds:Signature', 
                                        contextNode=parsedSOAP.dom, 
                                        context=ctxt)
        if len(signatureNodes) > 1:
            raise VerifyError, 'Multiple ds:Signature elements found'
        
        try:
            signatureNodes = signatureNodes[0]
        except:
            # Message wasn't signed
            return
        
        # Two stage process: reference validation followed by signature 
        # validation 
        
        # 1) Reference Validation
        
        # Check for canonicalization set via ds:CanonicalizationMethod -
        # Use this later as a back up in case no Canonicalization was set in 
        # the transforms elements
        c14nMethodNode = xpath.Evaluate('//ds:CanonicalizationMethod', 
                                        contextNode=parsedSOAP.dom, 
                                        context=ctxt)[0]
        
        refNodes = xpath.Evaluate('//ds:Reference', 
                                  contextNode=parsedSOAP.dom, 
                                  context=ctxt)
           
        for refNode in refNodes:
            # Get the URI for the reference
            refURI = refNode.getAttributeNodeNS(None, 'URI').value
                            
            try:
                transformsNode = getElements(refNode, "Transforms")[0]
                transforms = getElements(transformsNode, "Transform")
    
                refAlgorithm = transforms[0].getAttributeNodeNS(None, 
                                                         "Algorithm").value
            except Exception, e:
                raise VerifyError, \
            'failed to get transform algorithm for <ds:Reference URI="%s">'%\
                        (refURI, str(e))
                
            # Add extra keyword for Exclusive canonicalization method
            c14nKw = {}
            if refAlgorithm == DSIG.C14N_EXCL:
                try:
                    inclusiveNS = getElements(transforms[0], 
                                              "InclusiveNamespaces")
                    
                    pfxListAttNode = inclusiveNS[0].getAttributeNodeNS(None, 
                                                               'PrefixList')
                    c14nKw['unsuppressedPrefixes'] = \
                                                pfxListAttNode.value.split()
                except:
                    raise VerifyError, \
                'failed to handle transform (%s) in <ds:Reference URI="%s">'%\
                        (transforms[0], refURI)
        
            # Canonicalize the reference data and calculate the digest
            if refURI[0] != "#":
                raise VerifyError, \
                    "Expecting # identifier for Reference URI \"%s\"" % refURI
                    
            # XPath reference
            uriXPath = '//*[@wsu:Id="%s"]' % refURI[1:]
            uriNode = xpath.Evaluate(uriXPath, 
                                     contextNode=parsedSOAP.dom, 
                                     context=ctxt)[0]

            c14nRef = Canonicalize(uriNode, **c14nKw)
            digestValue = base64.encodestring(sha(c14nRef).digest()).strip()
            
            # Extract the digest value that was stored            
            digestNode = getElements(refNode, "DigestValue")[0]
            nodeDigestValue = str(digestNode.childNodes[0].nodeValue).strip()   
            
            # Reference validates if the two digest values are the same
            if digestValue != nodeDigestValue:
                raise VerifyError, \
                        'Digest Values do not match for URI: "%s"' % refURI
                
        # 2) Signature Validation
        signedInfoNode = xpath.Evaluate('//ds:SignedInfo',
                                        contextNode=parsedSOAP.dom, 
                                        context=ctxt)[0]

        #import pdb;pdb.set_trace()
        # Get algorithm used for canonicalization of the SignedInfo 
        # element.  Nb. This is NOT necessarily the same as that used to
        # canonicalize the reference elements checked above!
        signedInfoC14nAlg = c14nMethodNode.getAttributeNodeNS(None, 
                                                         "Algorithm").value
        signedInfoC14nKw = {}
        if signedInfoC14nAlg == DSIG.C14N_EXCL:
            try:
                inclusiveNS = getElements(c14nMethodNode,
                                          "InclusiveNamespaces")
                
                pfxListAttNode = inclusiveNS[0].getAttributeNodeNS(None, 
                                                           'PrefixList')
                signedInfoC14nKw['unsuppressedPrefixes'] = \
                                            pfxListAttNode.value.split()
            except Exception, e:
                raise VerifyError, \
            'failed to handle exclusive canonicalisation for SignedInfo: %s'%\
                        str(e)

        # Canonicalize the SignedInfo node and take digest
        c14nSignedInfo = Canonicalize(signedInfoNode, **signedInfoC14nKw)        
        signedInfoDigestValue = sha(c14nSignedInfo).digest()
        
        # Get the signature value in order to check against the digest just
        # calculated
        signatureValueNode = xpath.Evaluate('//ds:SignatureValue',
                                            contextNode=parsedSOAP.dom, 
                                            context=ctxt)[0]

        # Remove base 64 encoding
        b64EncSignatureValue = \
                    str(signatureValueNode.childNodes[0].nodeValue).strip()
                    
        signatureValue = base64.decodestring(b64EncSignatureValue)


        # Look for X.509 Cert in wsse:BinarySecurityToken node
        try:
            binSecTokNode = xpath.Evaluate('//wsse:BinarySecurityToken',
                                           contextNode=parsedSOAP.dom,
                                           context=ctxt)[0]
            x509str = binSecTokNode.childNodes[0]._get_nodeValue()
            #import pdb;pdb.set_trace()
#            x509strAlt = ''
#            i = 0
#            while i < len(x509str):
#                x509strAlt += "%s\n" % x509str[i:i+64]
#                i += 64
    
    	    raise Exception, "Try reading from file"
            x509Cert = X509.load_cert_string(x509strAlt)
        except:
            # If not, check cert file    
            x509Cert = X509.load_cert(self.__certFilePath)
        
        # Extract RSA public key from the cert
        rsaPubKey = x509Cert.get_pubkey().get_rsa()
        
        # Apply the signature verification
        try:
            verify = bool(rsaPubKey.verify(signedInfoDigestValue, 
                                           signatureValue))
        except RSA.RSAError:
            raise VerifyError, "Error in Signature"
        
        if not verify:
            raise VerifyError, "Invalid signature"
        
#        import pdb;pdb.set_trace()
        print "Signature OK"


class EncryptionError(Exception):
    """Flags an error in the encryption process"""

class DecryptionError(Exception):
    """Raised from EncryptionHandler.decrypt if an error occurs with the
    decryption process"""


class EncryptionHandler(object):
    """Encrypt/Decrypt SOAP messages using WS-Security""" 
    
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
                 chkSecurityTokRef=False,
                 encrNS=_ENCRYPTION.BLOCK_AES256):
#                 encrNS=_ENCRYPTION.BLOCK_TRIPLEDES):
        
        self.__certFilePath = certFilePath
        self.__priKeyFilePath = priKeyFilePath
        self.__priKeyPwd = priKeyPwd
        
        self.__chkSecurityTokRef = chkSecurityTokRef
        
        # Algorithm for shared key encryption
        try:
            self.__encrAlg = self.cryptoAlg[encrNS]
            
        except KeyError:
            raise EncryptionError, \
        'Input encryption algorithm namespace "%s" is not supported' % encrNS

        self.__encrNS = encrNS
        
        
    def encrypt(self, soapWriter):
        """Encrypt an outbound SOAP message
        
        Use Key Wrapping - message is encrypted using a shared key which 
        itself is encrypted with the public key provided by the X.509 cert.
        certFilePath"""
        
        # Use X.509 Cert to encrypt
        x509Cert = X509.load_cert(self.__certFilePath)
        
        x509CertPat = re.compile(\
            '-----BEGIN CERTIFICATE-----\n?(.*?)\n?-----END CERTIFICATE-----',
            re.S)
        x509CertStr = x509CertPat.findall(x509Cert.as_pem())[0]


        soapWriter.dom.setNamespaceAttribute('wsse', OASIS.WSSE)
        soapWriter.dom.setNamespaceAttribute('xenc', _ENCRYPTION.BASE)
        soapWriter.dom.setNamespaceAttribute('ds', DSIG.BASE)
        
        # TODO: Put in a check to make sure <wsse:security> isn't already 
        # present in header
        wsseElem = soapWriter._header.createAppendElement(OASIS.WSSE, 
                                                         'Security')
        wsseElem.node.setAttribute('SOAP-ENV:mustUnderstand', "1")
        
        encrKeyElem = wsseElem.createAppendElement(_ENCRYPTION.BASE, 
                                                   'EncryptedKey')
        
        # Encryption method used to encrypt the shared key
        keyEncrMethodElem = encrKeyElem.createAppendElement(_ENCRYPTION.BASE, 
                                                        'EncryptionMethod')
        
        keyEncrMethodElem.node.setAttribute('Algorithm', 
                                            _ENCRYPTION.KT_RSA_1_5)


        # Key Info
        KeyInfoElem = encrKeyElem.createAppendElement(DSIG.BASE, 'KeyInfo')
        
        secTokRefElem = KeyInfoElem.createAppendElement(OASIS.WSSE, 
                                                  'SecurityTokenReference')
        keyIdElem = secTokRefElem.createAppendElement(OASIS.WSSE,
                                                      'KeyIdentifier')
        #import pdb;pdb.set_trace()
        # Change value and encoding types to suite WebSphere
        valueType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier"
        keyIdElem.node.setAttribute('ValueType', valueType)
        encodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
        keyIdElem.node.setAttribute('EncodingType', encodingType)
        
        # Add ID so that the binary token can be included in the signature
        #keyIdElem.node.setAttribute('wsu:Id', "binaryToken")

        keyIdElem.createAppendTextNode(x509CertStr)
        
#        x509IssSerialElem = secTokRefElem.createAppendElement(DSIG.BASE, 
#                                                          'X509IssuerSerial')
#
#        
#        x509IssNameElem = x509IssSerialElem.createAppendElement(DSIG.BASE, 
#                                                          'X509IssuerName')
#        x509IssNameElem.createAppendTextNode(x509Cert.get_issuer().as_text())
#
#        
#        x509IssSerialNumElem = x509IssSerialElem.createAppendElement(
#                                                  DSIG.BASE, 
#                                                  'X509IssuerSerialNumber')
#        
#        x509IssSerialNumElem.createAppendTextNode(
#                                          str(x509Cert.get_serial_number()))

        # References to what has been encrypted
        encrKeyCiphDataElem = encrKeyElem.createAppendElement(
                                                          _ENCRYPTION.BASE,
                                                          'CipherData')
        
        encrKeyCiphValElem = encrKeyCiphDataElem.createAppendElement(
                                                          _ENCRYPTION.BASE,
                                                          'CipherValue')

        # References to what has been encrypted
        refListElem = encrKeyElem.createAppendElement(_ENCRYPTION.BASE,
                                                      'ReferenceList')
        
        dataRefElem = refListElem.createAppendElement(_ENCRYPTION.BASE,
                                                      'DataReference')
        dataRefElem.node.setAttribute('URI', "#encrypted")

                     
        # Add Encrypted data to SOAP body
        encrDataElem = soapWriter.body.createAppendElement(_ENCRYPTION.BASE, 
                                                           'EncryptedData')
        encrDataElem.node.setAttribute('Id', 'encrypted')
        encrDataElem.node.setAttribute('Type', _ENCRYPTION.BASE)  
              
        # Encryption method used to encrypt the target data
        dataEncrMethodElem = encrDataElem.createAppendElement(
                                                      _ENCRYPTION.BASE, 
                                                      'EncryptionMethod')
        
        dataEncrMethodElem.node.setAttribute('Algorithm', self.__encrNS)
        
        # Cipher data
        ciphDataElem = encrDataElem.createAppendElement(_ENCRYPTION.BASE,
                                                        'CipherData')
        
        ciphValueElem = ciphDataElem.createAppendElement(_ENCRYPTION.BASE,
                                                         'CipherValue')


        # Get elements from SOAP body for encryption
        dataElem = soapWriter.body.node.childNodes[0]
        data = dataElem.toxml()
     
        # Pad data to nearest multiple of encryption algorithm's block size    
        modData = len(data) % self.__encrAlg['blockSize']
        nPad = modData and self.__encrAlg['blockSize'] - modData or 0
        
        # PAd with random junk but ...
        data += os.urandom(nPad-1)
        
        # Last byte should be number of padding bytes
        # (http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block)
        data += chr(nPad)       
        
        # Generate shared key and input vector - for testing use hard-coded 
        # values to allow later comparison              
        sharedKey = os.urandom(self.__encrAlg['blockSize'])
        iv = os.urandom(self.__encrAlg['blockSize'])
        #iv = os.urandom(8)
        
        alg = self.__encrAlg['module'].new(sharedKey,
                                           self.__encrAlg['mode'],
                                           iv)
 
        # Encrypt required elements - prepend input vector
        encryptedData = alg.encrypt(iv + data)
        dataCiphValue = base64.encodestring(encryptedData).strip()

        ciphValueElem.createAppendTextNode(dataCiphValue)
        
        
        # ! Delete unencrypted message body elements !
        soapWriter.body.node.removeChild(dataElem)

        
        # Use X.509 cert public key to encrypt the shared key - Extract key
        # from the cert
        rsaPubKey = x509Cert.get_pubkey().get_rsa()
        
        # Encrypt the shared key
        encryptedSharedKey = rsaPubKey.public_encrypt(sharedKey, 
                                                      RSA.pkcs1_padding)
        
        encrKeyCiphVal = base64.encodestring(encryptedSharedKey).strip()
        
        # Add the encrypted shared key to the EncryptedKey section in the SOAP
        # header
        encrKeyCiphValElem.createAppendTextNode(encrKeyCiphVal)

        print soapWriter.dom.node.toprettyxml()
#        import pdb;pdb.set_trace()
        
        
    def decrypt(self, parsedSOAP):
        """Decrypt an inbound SOAP message"""
        
        processorNss = \
        {
            'xenc':   _ENCRYPTION.BASE,
            'ds':     DSIG.BASE, 
            'wsu':    _WSU.UTILITY, 
            'wsse':   OASIS.WSSE, 
            'soapenv':"http://schemas.xmlsoap.org/soap/envelope/" 
        }
        ctxt = Context(parsedSOAP.dom, processorNss=processorNss)
        
        refListNodes = xpath.Evaluate('//xenc:ReferenceList', 
                                      contextNode=parsedSOAP.dom, 
                                      context=ctxt)
        if len(refListNodes) > 1:
            raise DecryptionError, 'Expecting a single ReferenceList element'
        
        try:
            refListNode = refListNodes[0]
        except:
            # Message wasn't encrypted - is this OK or is a check needed for
            # encryption info in SOAP body - enveloped form?
            return


        # Check for wrapped key encryption
        encrKeyNodes = xpath.Evaluate('//xenc:EncryptedKey', 
                                      contextNode=parsedSOAP.dom, 
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

        
        # Check encryption method
        keyEncrMethodNode = getElements(encrKeyNode, 'EncryptionMethod')[0]     
        keyAlgorithm = keyEncrMethodNode.getAttributeNodeNS(None, 
                                                            "Algorithm").value
        if keyAlgorithm != _ENCRYPTION.KT_RSA_1_5:
            raise DecryptionError, \
            'Encryption algorithm for wrapped key is "%s", expecting "%s"' % \
                (keyAlgorithm, _ENCRYPTION.KT_RSA_1_5)

                                                            
        if self.__chkSecurityTokRef and self.__certFilePath:
             
            # Check input cert. against SecurityTokenReference
            securityTokRefXPath = '/ds:KeyInfo/wsse:SecurityTokenReference'
            securityTokRefNode = xpath.Evaluate(securityTokRefXPath, 
                                                contextNode=encrKeyNode, 
                                                context=ctxt)
            # TODO: Look for ds:X509* elements to check against X.509 cert 
            # input


        # Look for cipher data for wrapped key
        keyCiphDataNode = getElements(encrKeyNode, 'CipherData')[0]
        keyCiphValNode = getElements(keyCiphDataNode, 'CipherValue')[0]

        keyCiphVal = str(keyCiphValNode.childNodes[0].nodeValue)
        encryptedKey = base64.decodestring(keyCiphVal)

        # Read RSA Private key in order to decrypt wrapped key  
        priKeyFile = BIO.File(open(self.__priKeyFilePath))                                            
        priKey = RSA.load_key_bio(priKeyFile, 
                                  callback=lambda *ar, **kw: self.__priKeyPwd)
        
        sharedKey = priKey.private_decrypt(encryptedKey, RSA.pkcs1_padding)
        

        # Check list of data elements that have been encrypted
        for dataRefNode in refListNode.childNodes:

            # Get the URI for the reference
            dataRefURI = dataRefNode.getAttributeNodeNS(None, 'URI').value                            
            if dataRefURI[0] != "#":
                raise VerifyError, \
                    "Expecting # identifier for DataReference URI \"%s\"" % \
                    dataRefURI

            # XPath reference - need to check for wsu namespace qualified?
            #encrNodeXPath = '//*[@wsu:Id="%s"]' % dataRefURI[1:]
            encrNodeXPath = '//*[@Id="%s"]' % dataRefURI[1:]
            encrNode = xpath.Evaluate(encrNodeXPath, 
                                      contextNode=parsedSOAP.dom, 
                                      context=ctxt)[0]
                
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
        
            dataCiphVal = str(dataCiphValNode.childNodes[0].nodeValue)
            encryptedData = base64.decodestring(dataCiphVal)
            
            alg = CryptoAlg['module'].new(sharedKey, CryptoAlg['mode'])
            decryptedData = alg.decrypt(encryptedData)
            
            # Strip prefix - assume is block size
            decryptedData = decryptedData[CryptoAlg['blockSize']:]
            
            # Strip any padding suffix - Last byte should be number of padding
            # bytes
            # (http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block)
            lastChar = decryptedData[-1]
            nPad = ord(lastChar)
            
            # Sanity check - there may be no padding at all - the last byte 
            # being the end of the encrypted XML?
            #
            # TODO: are there better sanity checks than this?!
            if nPad < CryptoAlg['blockSize'] and nPad > 0 and \
               lastChar != '\n' and lastChar != '>':
                
                # Follow http://www.w3.org/TR/xmlenc-core/#sec-Alg-Block -
                # last byte gives number of padding bytes
                decryptedData = decryptedData[:-nPad]


            # Parse the encrypted data - inherit from Reader as a fudge to 
            # enable relevant namespaces to be added prior to parse
            processorNss.update({'xsi': SCHEMA.XSI3, 'ns1': 'urn:ZSI:examples'})
            class _Reader(Reader):
                def initState(self, ownerDoc=None):
                    Reader.initState(self, ownerDoc=ownerDoc)
                    self._namespaces.update(processorNss)
                    
            rdr = _Reader()
            dataNode = rdr.fromString(decryptedData, ownerDoc=parsedSOAP.dom)
            
            # Add decrypted element to parent and remove encrypted one
            parentNode = encrNode._get_parentNode()
            parentNode.appendChild(dataNode)
            parentNode.removeChild(encrNode)
            
            from xml.dom.ext import ReleaseNode
            ReleaseNode(encrNode)
            
            # Ensure body_root attribute is up to date in case it was
            # previously encrypted
            parsedSOAP.body_root = parsedSOAP.body.childNodes[0]
            print decryptedData
            #import pdb;pdb.set_trace()
           


        
if __name__ == "__main__":
    import sys
    txt = None
    
    e = EncryptionHandler(certFilePath='../../Junk-cert.pem',
                          priKeyFilePath='../../Junk-key.pem',
                          priKeyPwd=open('../../tmp2').read().strip())
    
    encryptedData = e.encrypt(None)
    print e.decrypt(None, encryptedData)
    
