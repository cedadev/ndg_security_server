/*
 * An XML document type.
 * Localname: echo
 * Namespace: http://sample04.samples.rampart.apache.org
 * Java type: org.apache.rampart.samples.sample04.EchoDocument
 *
 * Automatically generated - do not modify.
 */
package org.apache.rampart.samples.sample04;


/**
 * A document containing one echo(@http://sample04.samples.rampart.apache.org) element.
 *
 * This is a complex type.
 */
public interface EchoDocument extends org.apache.xmlbeans.XmlObject {
    public static final org.apache.xmlbeans.SchemaType type = (org.apache.xmlbeans.SchemaType) org.apache.xmlbeans.XmlBeans.typeSystemForClassLoader(EchoDocument.class.getClassLoader(),
            "schemaorg_apache_xmlbeans.system.s4D921BF3690B37F5157CE09768043A44")
                                                                                                                           .resolveHandle("echof216doctype");

    /**
     * Gets the "echo" element
     */
    org.apache.rampart.samples.sample04.EchoDocument.Echo getEcho();

    /**
     * Sets the "echo" element
     */
    void setEcho(org.apache.rampart.samples.sample04.EchoDocument.Echo echo);

    /**
     * Appends and returns a new empty "echo" element
     */
    org.apache.rampart.samples.sample04.EchoDocument.Echo addNewEcho();

    /**
     * An XML echo(@http://sample04.samples.rampart.apache.org).
     *
     * This is a complex type.
     */
    public interface Echo extends org.apache.xmlbeans.XmlObject {
        public static final org.apache.xmlbeans.SchemaType type = (org.apache.xmlbeans.SchemaType) org.apache.xmlbeans.XmlBeans.typeSystemForClassLoader(Echo.class.getClassLoader(),
                "schemaorg_apache_xmlbeans.system.s4D921BF3690B37F5157CE09768043A44")
                                                                                                                               .resolveHandle("echo4697elemtype");

        /**
         * Gets the "param0" element
         */
        java.lang.String getParam0();

        /**
         * Gets (as xml) the "param0" element
         */
        org.apache.xmlbeans.XmlString xgetParam0();

        /**
         * Tests for nil "param0" element
         */
        boolean isNilParam0();

        /**
         * True if has "param0" element
         */
        boolean isSetParam0();

        /**
         * Sets the "param0" element
         */
        void setParam0(java.lang.String param0);

        /**
         * Sets (as xml) the "param0" element
         */
        void xsetParam0(org.apache.xmlbeans.XmlString param0);

        /**
         * Nils the "param0" element
         */
        void setNilParam0();

        /**
         * Unsets the "param0" element
         */
        void unsetParam0();

        /**
         * A factory class with static methods for creating instances
         * of this type.
         */
        public static final class Factory {
            private Factory() {
            } // No instance of this class allowed

            public static org.apache.rampart.samples.sample04.EchoDocument.Echo newInstance() {
                return (org.apache.rampart.samples.sample04.EchoDocument.Echo) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                           .newInstance(type,
                    null);
            }

            public static org.apache.rampart.samples.sample04.EchoDocument.Echo newInstance(
                org.apache.xmlbeans.XmlOptions options) {
                return (org.apache.rampart.samples.sample04.EchoDocument.Echo) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                           .newInstance(type,
                    options);
            }
        }
    }

    /**
     * A factory class with static methods for creating instances
     * of this type.
     */
    public static final class Factory {
        private Factory() {
        } // No instance of this class allowed

        public static org.apache.rampart.samples.sample04.EchoDocument newInstance() {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .newInstance(type,
                null);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument newInstance(
            org.apache.xmlbeans.XmlOptions options) {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .newInstance(type,
                options);
        }

        /** @param xmlAsString the string value to parse */
        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            java.lang.String xmlAsString)
            throws org.apache.xmlbeans.XmlException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(xmlAsString,
                type, null);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            java.lang.String xmlAsString, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(xmlAsString,
                type, options);
        }

        /** @param file the file from which to load an xml document */
        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            java.io.File file)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(file,
                type, null);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            java.io.File file, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(file,
                type, options);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            java.net.URL u)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(u,
                type, null);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            java.net.URL u, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(u,
                type, options);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            java.io.InputStream is)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(is,
                type, null);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            java.io.InputStream is, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(is,
                type, options);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            java.io.Reader r)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(r,
                type, null);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            java.io.Reader r, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(r,
                type, options);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            javax.xml.stream.XMLStreamReader sr)
            throws org.apache.xmlbeans.XmlException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(sr,
                type, null);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            javax.xml.stream.XMLStreamReader sr,
            org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(sr,
                type, options);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            org.w3c.dom.Node node) throws org.apache.xmlbeans.XmlException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(node,
                type, null);
        }

        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            org.w3c.dom.Node node, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(node,
                type, options);
        }

        /** @deprecated {@link XMLInputStream} */
        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            org.apache.xmlbeans.xml.stream.XMLInputStream xis)
            throws org.apache.xmlbeans.XmlException,
                org.apache.xmlbeans.xml.stream.XMLStreamException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(xis,
                type, null);
        }

        /** @deprecated {@link XMLInputStream} */
        public static org.apache.rampart.samples.sample04.EchoDocument parse(
            org.apache.xmlbeans.xml.stream.XMLInputStream xis,
            org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException,
                org.apache.xmlbeans.xml.stream.XMLStreamException {
            return (org.apache.rampart.samples.sample04.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                  .parse(xis,
                type, options);
        }

        /** @deprecated {@link XMLInputStream} */
        public static org.apache.xmlbeans.xml.stream.XMLInputStream newValidatingXMLInputStream(
            org.apache.xmlbeans.xml.stream.XMLInputStream xis)
            throws org.apache.xmlbeans.XmlException,
                org.apache.xmlbeans.xml.stream.XMLStreamException {
            return org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                               .newValidatingXMLInputStream(xis,
                type, null);
        }

        /** @deprecated {@link XMLInputStream} */
        public static org.apache.xmlbeans.xml.stream.XMLInputStream newValidatingXMLInputStream(
            org.apache.xmlbeans.xml.stream.XMLInputStream xis,
            org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException,
                org.apache.xmlbeans.xml.stream.XMLStreamException {
            return org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                               .newValidatingXMLInputStream(xis,
                type, options);
        }
    }
}
