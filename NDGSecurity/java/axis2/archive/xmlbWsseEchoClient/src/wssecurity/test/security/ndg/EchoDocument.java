/*
 * An XML document type.
 * Localname: Echo
 * Namespace: urn:ndg:security:test:wssecurity
 * Java type: wssecurity.test.security.ndg.EchoDocument
 *
 * Automatically generated - do not modify.
 */
package wssecurity.test.security.ndg;


/**
 * A document containing one Echo(@urn:ndg:security:test:wssecurity) element.
 *
 * This is a complex type.
 */
public interface EchoDocument extends org.apache.xmlbeans.XmlObject {
    public static final org.apache.xmlbeans.SchemaType type = (org.apache.xmlbeans.SchemaType) org.apache.xmlbeans.XmlBeans.typeSystemForClassLoader(EchoDocument.class.getClassLoader(),
            "schemaorg_apache_xmlbeans.system.s3DA68D7A84A554D69AC47599823F860E")
                                                                                                                           .resolveHandle("echo6adedoctype");

    /**
     * Gets the "Echo" element
     */
    wssecurity.test.security.ndg.EchoDocument.Echo getEcho();

    /**
     * Sets the "Echo" element
     */
    void setEcho(wssecurity.test.security.ndg.EchoDocument.Echo echo);

    /**
     * Appends and returns a new empty "Echo" element
     */
    wssecurity.test.security.ndg.EchoDocument.Echo addNewEcho();

    /**
     * An XML Echo(@urn:ndg:security:test:wssecurity).
     *
     * This is a complex type.
     */
    public interface Echo extends org.apache.xmlbeans.XmlObject {
        public static final org.apache.xmlbeans.SchemaType type = (org.apache.xmlbeans.SchemaType) org.apache.xmlbeans.XmlBeans.typeSystemForClassLoader(Echo.class.getClassLoader(),
                "schemaorg_apache_xmlbeans.system.s3DA68D7A84A554D69AC47599823F860E")
                                                                                                                               .resolveHandle("echo10bfelemtype");

        /**
         * Gets the "EchoIn" element
         */
        java.lang.String getEchoIn();

        /**
         * Gets (as xml) the "EchoIn" element
         */
        org.apache.xmlbeans.XmlString xgetEchoIn();

        /**
         * True if has "EchoIn" element
         */
        boolean isSetEchoIn();

        /**
         * Sets the "EchoIn" element
         */
        void setEchoIn(java.lang.String echoIn);

        /**
         * Sets (as xml) the "EchoIn" element
         */
        void xsetEchoIn(org.apache.xmlbeans.XmlString echoIn);

        /**
         * Unsets the "EchoIn" element
         */
        void unsetEchoIn();

        /**
         * A factory class with static methods for creating instances
         * of this type.
         */
        public static final class Factory {
            private Factory() {
            } // No instance of this class allowed

            public static wssecurity.test.security.ndg.EchoDocument.Echo newInstance() {
                return (wssecurity.test.security.ndg.EchoDocument.Echo) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                    .newInstance(type,
                    null);
            }

            public static wssecurity.test.security.ndg.EchoDocument.Echo newInstance(
                org.apache.xmlbeans.XmlOptions options) {
                return (wssecurity.test.security.ndg.EchoDocument.Echo) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
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

        public static wssecurity.test.security.ndg.EchoDocument newInstance() {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .newInstance(type,
                null);
        }

        public static wssecurity.test.security.ndg.EchoDocument newInstance(
            org.apache.xmlbeans.XmlOptions options) {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .newInstance(type,
                options);
        }

        /** @param xmlAsString the string value to parse */
        public static wssecurity.test.security.ndg.EchoDocument parse(
            java.lang.String xmlAsString)
            throws org.apache.xmlbeans.XmlException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(xmlAsString,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoDocument parse(
            java.lang.String xmlAsString, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(xmlAsString,
                type, options);
        }

        /** @param file the file from which to load an xml document */
        public static wssecurity.test.security.ndg.EchoDocument parse(
            java.io.File file)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(file,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoDocument parse(
            java.io.File file, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(file,
                type, options);
        }

        public static wssecurity.test.security.ndg.EchoDocument parse(
            java.net.URL u)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(u,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoDocument parse(
            java.net.URL u, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(u,
                type, options);
        }

        public static wssecurity.test.security.ndg.EchoDocument parse(
            java.io.InputStream is)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(is,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoDocument parse(
            java.io.InputStream is, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(is,
                type, options);
        }

        public static wssecurity.test.security.ndg.EchoDocument parse(
            java.io.Reader r)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(r,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoDocument parse(
            java.io.Reader r, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(r,
                type, options);
        }

        public static wssecurity.test.security.ndg.EchoDocument parse(
            javax.xml.stream.XMLStreamReader sr)
            throws org.apache.xmlbeans.XmlException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(sr,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoDocument parse(
            javax.xml.stream.XMLStreamReader sr,
            org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(sr,
                type, options);
        }

        public static wssecurity.test.security.ndg.EchoDocument parse(
            org.w3c.dom.Node node) throws org.apache.xmlbeans.XmlException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(node,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoDocument parse(
            org.w3c.dom.Node node, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(node,
                type, options);
        }

        /** @deprecated {@link XMLInputStream} */
        public static wssecurity.test.security.ndg.EchoDocument parse(
            org.apache.xmlbeans.xml.stream.XMLInputStream xis)
            throws org.apache.xmlbeans.XmlException,
                org.apache.xmlbeans.xml.stream.XMLStreamException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                           .parse(xis,
                type, null);
        }

        /** @deprecated {@link XMLInputStream} */
        public static wssecurity.test.security.ndg.EchoDocument parse(
            org.apache.xmlbeans.xml.stream.XMLInputStream xis,
            org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException,
                org.apache.xmlbeans.xml.stream.XMLStreamException {
            return (wssecurity.test.security.ndg.EchoDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
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
