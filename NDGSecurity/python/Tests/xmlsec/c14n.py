#! /usr/bin/env python
'''XML C14N

Perform XML Canonicalization.  Not fully conformant to the spec
in a couple of ways (mostly minor):
    Comments are always stripped
    Whitespace preservation/stripping not totally correct
    Processing Instruction nodes aren't handled
    The nodeset must start with an element and includes all descendants
Fixing the last one would be non-trivial.
'''

_copyright = '''Copyright 2001, Zolera Systems Inc.  All Rights Reserved.
Distributed under the terms of the Python 2.0 Copyright.'''

from xml.dom import Node
import re
import StringIO

_attrs = lambda E: E._get_attributes() or []
_children = lambda E: E._get_childNodes() or []
_sorter = lambda n1, n2: cmp(n1._get_nodeName(), n2._get_nodeName())
xmlns_base = "http://www.w3.org/2000/xmlns/"

class _implementation:

    # Handlers for each node, by node type.
    handlers = {}

    # pattern/replacement list for whitespace stripping.
    repats = (
    ( re.compile(r'^[ \t]+', re.MULTILINE), '' ),
    ( re.compile(r'[ \t]+$', re.MULTILINE), '' ),
    ( re.compile(r'[\r\n]+'), '\n' ),
    )

    def __init__(self, node, write, nsdict={}, stripspace=0):
        '''Create and run the implementation.'''
        if node._get_nodeType() != Node.ELEMENT_NODE:
            raise TypeError, 'Non-element node'
        self.write, self.ns_stack, self.stripspace = \
            write, [nsdict], stripspace
        self._do_element(node)
        self.ns_stack.pop()

    def _do_text(self, node):
        'Output a text node in canonical form.'
        s = node._get_data() \
            .replace("\015", "&#xD;") \
            .replace("&", "&amp;") \
            .replace("<", "&lt;") \
            .replace(">", "&gt;")
        if self.stripspace:
            for pat,repl in _implementation.repats:
                s = re.sub(pat, repl, s)
        if s: self.write(s)
    handlers[Node.TEXT_NODE] =_do_text
    handlers[Node.CDATA_SECTION_NODE] =_do_text

    def _do_pi(self, node):
        'Output a processing instruction in canonical form.'
        pass    # XXX
        handlers[Node.PROCESSING_INSTRUCTION_NODE] =_do_pi

    def _do_comment(self, node):
        'Output a comment node in canonical form.'
        pass    # XXX
        handlers[Node.COMMENT_NODE] =_do_comment

    def _do_attr(self, n, value):
        'Output an attribute in canonical form.'
        W = self.write
        W(' ')
        W(n)
        W('="')
        s = value \
            .replace("&", "&amp;") \
            .replace("<", "&lt;") \
            .replace('"', '&quot;') \
            .replace('\011', '&#9') \
            .replace('\012', '&#A') \
            .replace('\015', '&#D')
        W(s)
        W('"')

    def _do_element(self, node):
        'Output an element (and its children) in canonical form.'
        name = node._get_nodeName()
        parent_ns = self.ns_stack[-1]
        my_ns = { 'xmlns': parent_ns.get('xmlns', '') }
        W = self.write
        W('<')
        W(name)
    
        # Divide attributes to NS definitions and others.
        nsnodes, others = [], []
        for a in _attrs(node):
            if a._get_namespaceURI() == xmlns_base:
                nsnodes.append(a)
            else:
                others.append(a)
    
        # Namespace attributes: update dictionary; if not already
        # in parent, output it.
        nsnodes.sort(_sorter)
        for a in nsnodes:
            n = a._get_nodeName()
            if n == "xmlns:":
                key, n = "", "xmlns"
            else:
                key = a._get_localName()
            v = my_ns[key] = a._get_nodeValue()
            pval = parent_ns.get(key, None)
            if v != pval: self._do_attr(n, v)
    
        # Other attributes: sort and output.
        others.sort(_sorter)
        for a in others:
            self._do_attr(a._get_nodeName(), a._get_value())
        W('>')
    
        self.ns_stack.append(my_ns)
        for c in _children(node):
            handler = _implementation.handlers.get(c._get_nodeType(), None)
            if handler: handler(self, c)
        self.ns_stack.pop()
        W('</%s>' % (name,))
    handlers[Node.ELEMENT_NODE] =_do_element

def XMLC14N(node, output=None, **kw):
    '''Canonicalize a DOM element node and everything underneath it.
    Return the text; if output is specified then output.write will
    be called to output the text and the return value will be None.
    Keyword parameters:
    stripspace -- remove extra (almost all) whitespace from text nodes
    nsdict -- a dictionary of prefix/uri namespace entries assumed
        to exist in the surrounding context.
    '''

    if output:
        s = None
    else:
        output = s = StringIO.StringIO()

    _implementation(node,
    output.write,
    stripspace=kw.get('stripspace', 0),
    nsdict=kw.get('nsdict', {})
    )
    if s: return (s.getvalue(), s.close())[0]
    return None
    if s == None: return None
    ret = s.getvalue()
    s.close()
    return ret

if __name__ == '__main__':
    text = '''<SOAP-ENV:Envelope
      xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
      xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:spare='foo'
      SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <SOAP-ENV:Body xmlns='test-uri'><?MYPI spenser?>
        <Price xsi:type='xsd:integer'>34</Price>    <!-- 0 -->
        <SOAP-ENC:byte>44</SOAP-ENC:byte>    <!-- 1 -->
        <Name>This is the name</Name>    <!-- 2 -->
        <n2><![CDATA[<greeting>Hello</greeting>]]></n2> <!-- 3 -->
        <n3 href='#zzz' xsi:type='SOAP-ENC:string'/>        <!-- 4 -->
        <n64>a GVsbG8=</n64>        <!-- 5 -->
        <SOAP-ENC:string>Red</SOAP-ENC:string>    <!-- 6 -->
        <a2 href='#tri2'/>        <!-- 7 -->
        <a2 xmlns:f='z' xmlns:aa='zz'><i xmlns:f='z'>12</i><t>rich salz</t></a2> <!-- 8 -->
        <xsd:hexBinary>3F2041</xsd:hexBinary> <!-- 9 -->
        <nullint xsi:nil='1'/> <!-- 10 -->
    </SOAP-ENV:Body>
      <z xmlns='myns' id='zzz'>The value of n3</z>
      <zz xmlns:spare='foo' xmlns='myns2' id='tri2'><inner>content</inner></zz>
    </SOAP-ENV:Envelope>'''

    print _copyright
    from xml.dom.ext.reader import PyExpat
    reader = PyExpat.Reader()
    dom = reader.fromString(text)
    for e in _children(dom):
        if e._get_nodeType() != Node.ELEMENT_NODE: continue
        for ee in _children(e):
            if ee._get_nodeType() != Node.ELEMENT_NODE: continue
            print '\n', '=' * 60
            print XMLC14N(ee, nsdict={'spare':'foo'}, stripspace=1)
            print '-' * 60
            print XMLC14N(ee, stripspace=0)
            print '=' * 60