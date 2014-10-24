/*
 * An XML document type.
 * Localname: EchoResponse
 * Namespace: urn:ndg:security:test:wssecurity
 * Java type: wssecurity.test.security.ndg.EchoResponseDocument
 *
 * Automatically generated - do not modify.
 */
package wssecurity.test.security.ndg;


/**
 * A document containing one EchoResponse(@urn:ndg:security:test:wssecurity) element.
 *
 * This is a complex type.
 */
public interface EchoResponseDocument extends org.apache.xmlbeans.XmlObject {
    public static final org.apache.xmlbeans.SchemaType type = (org.apache.xmlbeans.SchemaType) org.apache.xmlbeans.XmlBeans.typeSystemForClassLoader(EchoResponseDocument.class.getClassLoader(),
            "schemaorg_apache_xmlbeans.system.s3DA68D7A84A554D69AC47599823F860E")
                                                                                                                           .resolveHandle("echoresponsea09ddoctype");

    /**
     * Gets the "EchoResponse" element
     */
    wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse getEchoResponse();

    /**
     * Sets the "EchoResponse" element
     */
    void setEchoResponse(
        wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse echoResponse);

    /**
     * Appends and returns a new empty "EchoResponse" element
     */
    wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse addNewEchoResponse();

    /**
     * An XML EchoResponse(@urn:ndg:security:test:wssecurity).
     *
     * This is a complex type.
     */
    public interface EchoResponse extends org.apache.xmlbeans.XmlObject {
        public static final org.apache.xmlbeans.SchemaType type = (org.apache.xmlbeans.SchemaType) org.apache.xmlbeans.XmlBeans.typeSystemForClassLoader(EchoResponse.class.getClassLoader(),
                "schemaorg_apache_xmlbeans.system.s3DA68D7A84A554D69AC47599823F860E")
                                                                                                                               .resolveHandle("echoresponse7adfelemtype");

        /**
         * Gets the "EchoResult" element
         */
        java.lang.String getEchoResult();

        /**
         * Gets (as xml) the "EchoResult" element
         */
        org.apache.xmlbeans.XmlString xgetEchoResult();

        /**
         * True if has "EchoResult" element
         */
        boolean isSetEchoResult();

        /**
         * Sets the "EchoResult" element
         */
        void setEchoResult(java.lang.String echoResult);

        /**
         * Sets (as xml) the "EchoResult" element
         */
        void xsetEchoResult(org.apache.xmlbeans.XmlString echoResult);

        /**
         * Unsets the "EchoResult" element
         */
        void unsetEchoResult();

        /**
         * A factory class with static methods for creating instances
         * of this type.
         */
        public static final class Factory {
            private Factory() {
            } // No instance of this class allowed

            public static wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse newInstance() {
                return (wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                                    .newInstance(type,
                    null);
            }

            public static wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse newInstance(
                org.apache.xmlbeans.XmlOptions options) {
                return (wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
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

        public static wssecurity.test.security.ndg.EchoResponseDocument newInstance() {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .newInstance(type,
                null);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument newInstance(
            org.apache.xmlbeans.XmlOptions options) {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .newInstance(type,
                options);
        }

        /** @param xmlAsString the string value to parse */
        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            java.lang.String xmlAsString)
            throws org.apache.xmlbeans.XmlException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(xmlAsString,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            java.lang.String xmlAsString, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(xmlAsString,
                type, options);
        }

        /** @param file the file from which to load an xml document */
        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            java.io.File file)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(file,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            java.io.File file, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(file,
                type, options);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            java.net.URL u)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(u,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            java.net.URL u, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(u,
                type, options);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            java.io.InputStream is)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(is,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            java.io.InputStream is, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(is,
                type, options);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            java.io.Reader r)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(r,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            java.io.Reader r, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException, java.io.IOException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(r,
                type, options);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            javax.xml.stream.XMLStreamReader sr)
            throws org.apache.xmlbeans.XmlException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(sr,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            javax.xml.stream.XMLStreamReader sr,
            org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(sr,
                type, options);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            org.w3c.dom.Node node) throws org.apache.xmlbeans.XmlException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(node,
                type, null);
        }

        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            org.w3c.dom.Node node, org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(node,
                type, options);
        }

        /** @deprecated {@link XMLInputStream} */
        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            org.apache.xmlbeans.xml.stream.XMLInputStream xis)
            throws org.apache.xmlbeans.XmlException,
                org.apache.xmlbeans.xml.stream.XMLStreamException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
                                                                                                   .parse(xis,
                type, null);
        }

        /** @deprecated {@link XMLInputStream} */
        public static wssecurity.test.security.ndg.EchoResponseDocument parse(
            org.apache.xmlbeans.xml.stream.XMLInputStream xis,
            org.apache.xmlbeans.XmlOptions options)
            throws org.apache.xmlbeans.XmlException,
                org.apache.xmlbeans.xml.stream.XMLStreamException {
            return (wssecurity.test.security.ndg.EchoResponseDocument) org.apache.xmlbeans.XmlBeans.getContextTypeLoader()
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
