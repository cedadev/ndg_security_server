#!/usr/bin/env python

from ZSI.wstools.Namespaces import DSIG, ENCRYPTION, OASIS, WSU, WSA200403, \
                                   SOAP, SCHEMA # last included for xsi

# Canonicalization
from ZSI.wstools.c14n import Canonicalize

# Include for re-parsing doc ready for canonicalization in sign method - see
# associated note
from xml.dom.ext.reader.PyExpat import Reader
from xml.xpath.Context import Context
from xml import xpath
#import Ft.Xml.XPath as xpath

def test():
    
    inf = open('./ChargeAmountReq_unpatched.xml')
    xml = inf.read()
    
    # Namespaces for XPath searches
    processorNss = \
    {
        'wsu':    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
    }

    docNode = Reader().fromString(xml)
    ctxt = Context(docNode, processorNss=processorNss)
    refNodes = xpath.Evaluate('//*[@wsu:Id]', 
                              contextNode=docNode, 
                              context=ctxt)
    for refNode in refNodes:
        # Get ref node and all it's children
        refSubsetList = getChildNodes(refNode, [refNode])
        refExclC14nWithPfx = Canonicalize(docNode, None, subset=refSubsetList,
                               unsuppressedPrefixes=['SOAP-ENV', 'SOAP-ENC',
                               'ZSI', 'ns1', 'wsu', 'xsd', 'xsi', 'ds', 'ec'])
        refExclC14n = Canonicalize(docNode, None, subset=refSubsetList,
                               unsuppressedPrefixes=[])
        refInclC14n1 = Canonicalize(docNode, None, subset=refSubsetList)
        refInclC14n2 = Canonicalize(refNode)

	# For inclusive C14N either form of call to Canonicalize above will
        # give the same result:
        assert(refInclC14n1==refInclC14n2)

        # Expected to be different as Exclusive omits surperfluous ancestor
        # namespace declarations
        assert(refExclC14n != refInclC14n1)

        # If the right namespace declarations are explicitly included, Exclusive
        # C14N gives the same result as inclusive C14N
        assert(refInclC14n2==refExclC14nWithPfx)

def getChildNodes(node, nodeList=None):

    if node.attributes is not None:
        nodeList += node.attributes.values() 
    nodeList += node.childNodes
    for childNode in node.childNodes:
        getChildNodes(childNode, nodeList)
    return nodeList

if __name__ == "__main__":
    test()
