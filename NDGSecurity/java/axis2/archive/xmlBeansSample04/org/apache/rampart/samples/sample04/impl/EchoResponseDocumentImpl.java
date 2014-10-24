/*
 * An XML document type.
 * Localname: echoResponse
 * Namespace: http://sample04.samples.rampart.apache.org
 * Java type: org.apache.rampart.samples.sample04.EchoResponseDocument
 *
 * Automatically generated - do not modify.
 */
package org.apache.rampart.samples.sample04.impl;

/**
 * A document containing one echoResponse(@http://sample04.samples.rampart.apache.org) element.
 *
 * This is a complex type.
 */
public class EchoResponseDocumentImpl extends org.apache.xmlbeans.impl.values.XmlComplexContentImpl
    implements org.apache.rampart.samples.sample04.EchoResponseDocument {
    private static final javax.xml.namespace.QName ECHORESPONSE$0 = new javax.xml.namespace.QName("http://sample04.samples.rampart.apache.org",
            "echoResponse");

    public EchoResponseDocumentImpl(org.apache.xmlbeans.SchemaType sType) {
        super(sType);
    }

    /**
     * Gets the "echoResponse" element
     */
    public org.apache.rampart.samples.sample04.EchoResponseDocument.EchoResponse getEchoResponse() {
        synchronized (monitor()) {
            check_orphaned();

            org.apache.rampart.samples.sample04.EchoResponseDocument.EchoResponse target =
                null;
            target = (org.apache.rampart.samples.sample04.EchoResponseDocument.EchoResponse) get_store()
                                                                                                 .find_element_user(ECHORESPONSE$0,
                    0);

            if (target == null) {
                return null;
            }

            return target;
        }
    }

    /**
     * Sets the "echoResponse" element
     */
    public void setEchoResponse(
        org.apache.rampart.samples.sample04.EchoResponseDocument.EchoResponse echoResponse) {
        synchronized (monitor()) {
            check_orphaned();

            org.apache.rampart.samples.sample04.EchoResponseDocument.EchoResponse target =
                null;
            target = (org.apache.rampart.samples.sample04.EchoResponseDocument.EchoResponse) get_store()
                                                                                                 .find_element_user(ECHORESPONSE$0,
                    0);

            if (target == null) {
                target = (org.apache.rampart.samples.sample04.EchoResponseDocument.EchoResponse) get_store()
                                                                                                     .add_element_user(ECHORESPONSE$0);
            }

            target.set(echoResponse);
        }
    }

    /**
     * Appends and returns a new empty "echoResponse" element
     */
    public org.apache.rampart.samples.sample04.EchoResponseDocument.EchoResponse addNewEchoResponse() {
        synchronized (monitor()) {
            check_orphaned();

            org.apache.rampart.samples.sample04.EchoResponseDocument.EchoResponse target =
                null;
            target = (org.apache.rampart.samples.sample04.EchoResponseDocument.EchoResponse) get_store()
                                                                                                 .add_element_user(ECHORESPONSE$0);

            return target;
        }
    }

    /**
     * An XML echoResponse(@http://sample04.samples.rampart.apache.org).
     *
     * This is a complex type.
     */
    public static class EchoResponseImpl extends org.apache.xmlbeans.impl.values.XmlComplexContentImpl
        implements org.apache.rampart.samples.sample04.EchoResponseDocument.EchoResponse {
        private static final javax.xml.namespace.QName RETURN$0 = new javax.xml.namespace.QName("http://sample04.samples.rampart.apache.org",
                "return");

        public EchoResponseImpl(org.apache.xmlbeans.SchemaType sType) {
            super(sType);
        }

        /**
         * Gets the "return" element
         */
        public java.lang.String getReturn() {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.SimpleValue target = null;
                target = (org.apache.xmlbeans.SimpleValue) get_store()
                                                               .find_element_user(RETURN$0,
                        0);

                if (target == null) {
                    return null;
                }

                return target.getStringValue();
            }
        }

        /**
         * Gets (as xml) the "return" element
         */
        public org.apache.xmlbeans.XmlString xgetReturn() {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.XmlString target = null;
                target = (org.apache.xmlbeans.XmlString) get_store()
                                                             .find_element_user(RETURN$0,
                        0);

                return target;
            }
        }

        /**
         * Tests for nil "return" element
         */
        public boolean isNilReturn() {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.XmlString target = null;
                target = (org.apache.xmlbeans.XmlString) get_store()
                                                             .find_element_user(RETURN$0,
                        0);

                if (target == null) {
                    return false;
                }

                return target.isNil();
            }
        }

        /**
         * True if has "return" element
         */
        public boolean isSetReturn() {
            synchronized (monitor()) {
                check_orphaned();

                return get_store().count_elements(RETURN$0) != 0;
            }
        }

        /**
         * Sets the "return" element
         */
        public void setReturn(java.lang.String xreturn) {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.SimpleValue target = null;
                target = (org.apache.xmlbeans.SimpleValue) get_store()
                                                               .find_element_user(RETURN$0,
                        0);

                if (target == null) {
                    target = (org.apache.xmlbeans.SimpleValue) get_store()
                                                                   .add_element_user(RETURN$0);
                }

                target.setStringValue(xreturn);
            }
        }

        /**
         * Sets (as xml) the "return" element
         */
        public void xsetReturn(org.apache.xmlbeans.XmlString xreturn) {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.XmlString target = null;
                target = (org.apache.xmlbeans.XmlString) get_store()
                                                             .find_element_user(RETURN$0,
                        0);

                if (target == null) {
                    target = (org.apache.xmlbeans.XmlString) get_store()
                                                                 .add_element_user(RETURN$0);
                }

                target.set(xreturn);
            }
        }

        /**
         * Nils the "return" element
         */
        public void setNilReturn() {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.XmlString target = null;
                target = (org.apache.xmlbeans.XmlString) get_store()
                                                             .find_element_user(RETURN$0,
                        0);

                if (target == null) {
                    target = (org.apache.xmlbeans.XmlString) get_store()
                                                                 .add_element_user(RETURN$0);
                }

                target.setNil();
            }
        }

        /**
         * Unsets the "return" element
         */
        public void unsetReturn() {
            synchronized (monitor()) {
                check_orphaned();
                get_store().remove_element(RETURN$0, 0);
            }
        }
    }
}
