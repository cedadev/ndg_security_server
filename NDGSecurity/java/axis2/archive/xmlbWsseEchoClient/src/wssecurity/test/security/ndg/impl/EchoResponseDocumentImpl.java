/*
 * An XML document type.
 * Localname: EchoResponse
 * Namespace: urn:ndg:security:test:wssecurity
 * Java type: wssecurity.test.security.ndg.EchoResponseDocument
 *
 * Automatically generated - do not modify.
 */
package wssecurity.test.security.ndg.impl;

/**
 * A document containing one EchoResponse(@urn:ndg:security:test:wssecurity) element.
 *
 * This is a complex type.
 */
public class EchoResponseDocumentImpl extends org.apache.xmlbeans.impl.values.XmlComplexContentImpl
    implements wssecurity.test.security.ndg.EchoResponseDocument {
    private static final javax.xml.namespace.QName ECHORESPONSE$0 = new javax.xml.namespace.QName("urn:ndg:security:test:wssecurity",
            "EchoResponse");

    public EchoResponseDocumentImpl(org.apache.xmlbeans.SchemaType sType) {
        super(sType);
    }

    /**
     * Gets the "EchoResponse" element
     */
    public wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse getEchoResponse() {
        synchronized (monitor()) {
            check_orphaned();

            wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse target =
                null;
            target = (wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse) get_store()
                                                                                          .find_element_user(ECHORESPONSE$0,
                    0);

            if (target == null) {
                return null;
            }

            return target;
        }
    }

    /**
     * Sets the "EchoResponse" element
     */
    public void setEchoResponse(
        wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse echoResponse) {
        synchronized (monitor()) {
            check_orphaned();

            wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse target =
                null;
            target = (wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse) get_store()
                                                                                          .find_element_user(ECHORESPONSE$0,
                    0);

            if (target == null) {
                target = (wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse) get_store()
                                                                                              .add_element_user(ECHORESPONSE$0);
            }

            target.set(echoResponse);
        }
    }

    /**
     * Appends and returns a new empty "EchoResponse" element
     */
    public wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse addNewEchoResponse() {
        synchronized (monitor()) {
            check_orphaned();

            wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse target =
                null;
            target = (wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse) get_store()
                                                                                          .add_element_user(ECHORESPONSE$0);

            return target;
        }
    }

    /**
     * An XML EchoResponse(@urn:ndg:security:test:wssecurity).
     *
     * This is a complex type.
     */
    public static class EchoResponseImpl extends org.apache.xmlbeans.impl.values.XmlComplexContentImpl
        implements wssecurity.test.security.ndg.EchoResponseDocument.EchoResponse {
        private static final javax.xml.namespace.QName ECHORESULT$0 = new javax.xml.namespace.QName("urn:ndg:security:test:wssecurity",
                "EchoResult");

        public EchoResponseImpl(org.apache.xmlbeans.SchemaType sType) {
            super(sType);
        }

        /**
         * Gets the "EchoResult" element
         */
        public java.lang.String getEchoResult() {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.SimpleValue target = null;
                target = (org.apache.xmlbeans.SimpleValue) get_store()
                                                               .find_element_user(ECHORESULT$0,
                        0);

                if (target == null) {
                    return null;
                }

                return target.getStringValue();
            }
        }

        /**
         * Gets (as xml) the "EchoResult" element
         */
        public org.apache.xmlbeans.XmlString xgetEchoResult() {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.XmlString target = null;
                target = (org.apache.xmlbeans.XmlString) get_store()
                                                             .find_element_user(ECHORESULT$0,
                        0);

                return target;
            }
        }

        /**
         * True if has "EchoResult" element
         */
        public boolean isSetEchoResult() {
            synchronized (monitor()) {
                check_orphaned();

                return get_store().count_elements(ECHORESULT$0) != 0;
            }
        }

        /**
         * Sets the "EchoResult" element
         */
        public void setEchoResult(java.lang.String echoResult) {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.SimpleValue target = null;
                target = (org.apache.xmlbeans.SimpleValue) get_store()
                                                               .find_element_user(ECHORESULT$0,
                        0);

                if (target == null) {
                    target = (org.apache.xmlbeans.SimpleValue) get_store()
                                                                   .add_element_user(ECHORESULT$0);
                }

                target.setStringValue(echoResult);
            }
        }

        /**
         * Sets (as xml) the "EchoResult" element
         */
        public void xsetEchoResult(org.apache.xmlbeans.XmlString echoResult) {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.XmlString target = null;
                target = (org.apache.xmlbeans.XmlString) get_store()
                                                             .find_element_user(ECHORESULT$0,
                        0);

                if (target == null) {
                    target = (org.apache.xmlbeans.XmlString) get_store()
                                                                 .add_element_user(ECHORESULT$0);
                }

                target.set(echoResult);
            }
        }

        /**
         * Unsets the "EchoResult" element
         */
        public void unsetEchoResult() {
            synchronized (monitor()) {
                check_orphaned();
                get_store().remove_element(ECHORESULT$0, 0);
            }
        }
    }
}
