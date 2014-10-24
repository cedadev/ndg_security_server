/*
 * An XML document type.
 * Localname: Echo
 * Namespace: urn:ndg:security:test:wssecurity
 * Java type: wssecurity.test.security.ndg.EchoDocument
 *
 * Automatically generated - do not modify.
 */
package wssecurity.test.security.ndg.impl;

/**
 * A document containing one Echo(@urn:ndg:security:test:wssecurity) element.
 *
 * This is a complex type.
 */
public class EchoDocumentImpl extends org.apache.xmlbeans.impl.values.XmlComplexContentImpl
    implements wssecurity.test.security.ndg.EchoDocument {
    private static final javax.xml.namespace.QName ECHO$0 = new javax.xml.namespace.QName("urn:ndg:security:test:wssecurity",
            "Echo");

    public EchoDocumentImpl(org.apache.xmlbeans.SchemaType sType) {
        super(sType);
    }

    /**
     * Gets the "Echo" element
     */
    public wssecurity.test.security.ndg.EchoDocument.Echo getEcho() {
        synchronized (monitor()) {
            check_orphaned();

            wssecurity.test.security.ndg.EchoDocument.Echo target = null;
            target = (wssecurity.test.security.ndg.EchoDocument.Echo) get_store()
                                                                          .find_element_user(ECHO$0,
                    0);

            if (target == null) {
                return null;
            }

            return target;
        }
    }

    /**
     * Sets the "Echo" element
     */
    public void setEcho(wssecurity.test.security.ndg.EchoDocument.Echo echo) {
        synchronized (monitor()) {
            check_orphaned();

            wssecurity.test.security.ndg.EchoDocument.Echo target = null;
            target = (wssecurity.test.security.ndg.EchoDocument.Echo) get_store()
                                                                          .find_element_user(ECHO$0,
                    0);

            if (target == null) {
                target = (wssecurity.test.security.ndg.EchoDocument.Echo) get_store()
                                                                              .add_element_user(ECHO$0);
            }

            target.set(echo);
        }
    }

    /**
     * Appends and returns a new empty "Echo" element
     */
    public wssecurity.test.security.ndg.EchoDocument.Echo addNewEcho() {
        synchronized (monitor()) {
            check_orphaned();

            wssecurity.test.security.ndg.EchoDocument.Echo target = null;
            target = (wssecurity.test.security.ndg.EchoDocument.Echo) get_store()
                                                                          .add_element_user(ECHO$0);

            return target;
        }
    }

    /**
     * An XML Echo(@urn:ndg:security:test:wssecurity).
     *
     * This is a complex type.
     */
    public static class EchoImpl extends org.apache.xmlbeans.impl.values.XmlComplexContentImpl
        implements wssecurity.test.security.ndg.EchoDocument.Echo {
        private static final javax.xml.namespace.QName ECHOIN$0 = new javax.xml.namespace.QName("urn:ndg:security:test:wssecurity",
                "EchoIn");

        public EchoImpl(org.apache.xmlbeans.SchemaType sType) {
            super(sType);
        }

        /**
         * Gets the "EchoIn" element
         */
        public java.lang.String getEchoIn() {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.SimpleValue target = null;
                target = (org.apache.xmlbeans.SimpleValue) get_store()
                                                               .find_element_user(ECHOIN$0,
                        0);

                if (target == null) {
                    return null;
                }

                return target.getStringValue();
            }
        }

        /**
         * Gets (as xml) the "EchoIn" element
         */
        public org.apache.xmlbeans.XmlString xgetEchoIn() {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.XmlString target = null;
                target = (org.apache.xmlbeans.XmlString) get_store()
                                                             .find_element_user(ECHOIN$0,
                        0);

                return target;
            }
        }

        /**
         * True if has "EchoIn" element
         */
        public boolean isSetEchoIn() {
            synchronized (monitor()) {
                check_orphaned();

                return get_store().count_elements(ECHOIN$0) != 0;
            }
        }

        /**
         * Sets the "EchoIn" element
         */
        public void setEchoIn(java.lang.String echoIn) {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.SimpleValue target = null;
                target = (org.apache.xmlbeans.SimpleValue) get_store()
                                                               .find_element_user(ECHOIN$0,
                        0);

                if (target == null) {
                    target = (org.apache.xmlbeans.SimpleValue) get_store()
                                                                   .add_element_user(ECHOIN$0);
                }

                target.setStringValue(echoIn);
            }
        }

        /**
         * Sets (as xml) the "EchoIn" element
         */
        public void xsetEchoIn(org.apache.xmlbeans.XmlString echoIn) {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.XmlString target = null;
                target = (org.apache.xmlbeans.XmlString) get_store()
                                                             .find_element_user(ECHOIN$0,
                        0);

                if (target == null) {
                    target = (org.apache.xmlbeans.XmlString) get_store()
                                                                 .add_element_user(ECHOIN$0);
                }

                target.set(echoIn);
            }
        }

        /**
         * Unsets the "EchoIn" element
         */
        public void unsetEchoIn() {
            synchronized (monitor()) {
                check_orphaned();
                get_store().remove_element(ECHOIN$0, 0);
            }
        }
    }
}
