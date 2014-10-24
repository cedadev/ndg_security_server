/*
 * An XML document type.
 * Localname: echo
 * Namespace: http://sample04.samples.rampart.apache.org
 * Java type: org.apache.rampart.samples.sample04.EchoDocument
 *
 * Automatically generated - do not modify.
 */
package org.apache.rampart.samples.sample04.impl;

/**
 * A document containing one echo(@http://sample04.samples.rampart.apache.org) element.
 *
 * This is a complex type.
 */
public class EchoDocumentImpl extends org.apache.xmlbeans.impl.values.XmlComplexContentImpl
    implements org.apache.rampart.samples.sample04.EchoDocument {
    private static final javax.xml.namespace.QName ECHO$0 = new javax.xml.namespace.QName("http://sample04.samples.rampart.apache.org",
            "echo");

    public EchoDocumentImpl(org.apache.xmlbeans.SchemaType sType) {
        super(sType);
    }

    /**
     * Gets the "echo" element
     */
    public org.apache.rampart.samples.sample04.EchoDocument.Echo getEcho() {
        synchronized (monitor()) {
            check_orphaned();

            org.apache.rampart.samples.sample04.EchoDocument.Echo target = null;
            target = (org.apache.rampart.samples.sample04.EchoDocument.Echo) get_store()
                                                                                 .find_element_user(ECHO$0,
                    0);

            if (target == null) {
                return null;
            }

            return target;
        }
    }

    /**
     * Sets the "echo" element
     */
    public void setEcho(
        org.apache.rampart.samples.sample04.EchoDocument.Echo echo) {
        synchronized (monitor()) {
            check_orphaned();

            org.apache.rampart.samples.sample04.EchoDocument.Echo target = null;
            target = (org.apache.rampart.samples.sample04.EchoDocument.Echo) get_store()
                                                                                 .find_element_user(ECHO$0,
                    0);

            if (target == null) {
                target = (org.apache.rampart.samples.sample04.EchoDocument.Echo) get_store()
                                                                                     .add_element_user(ECHO$0);
            }

            target.set(echo);
        }
    }

    /**
     * Appends and returns a new empty "echo" element
     */
    public org.apache.rampart.samples.sample04.EchoDocument.Echo addNewEcho() {
        synchronized (monitor()) {
            check_orphaned();

            org.apache.rampart.samples.sample04.EchoDocument.Echo target = null;
            target = (org.apache.rampart.samples.sample04.EchoDocument.Echo) get_store()
                                                                                 .add_element_user(ECHO$0);

            return target;
        }
    }

    /**
     * An XML echo(@http://sample04.samples.rampart.apache.org).
     *
     * This is a complex type.
     */
    public static class EchoImpl extends org.apache.xmlbeans.impl.values.XmlComplexContentImpl
        implements org.apache.rampart.samples.sample04.EchoDocument.Echo {
        private static final javax.xml.namespace.QName PARAM0$0 = new javax.xml.namespace.QName("http://sample04.samples.rampart.apache.org",
                "param0");

        public EchoImpl(org.apache.xmlbeans.SchemaType sType) {
            super(sType);
        }

        /**
         * Gets the "param0" element
         */
        public java.lang.String getParam0() {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.SimpleValue target = null;
                target = (org.apache.xmlbeans.SimpleValue) get_store()
                                                               .find_element_user(PARAM0$0,
                        0);

                if (target == null) {
                    return null;
                }

                return target.getStringValue();
            }
        }

        /**
         * Gets (as xml) the "param0" element
         */
        public org.apache.xmlbeans.XmlString xgetParam0() {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.XmlString target = null;
                target = (org.apache.xmlbeans.XmlString) get_store()
                                                             .find_element_user(PARAM0$0,
                        0);

                return target;
            }
        }

        /**
         * Tests for nil "param0" element
         */
        public boolean isNilParam0() {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.XmlString target = null;
                target = (org.apache.xmlbeans.XmlString) get_store()
                                                             .find_element_user(PARAM0$0,
                        0);

                if (target == null) {
                    return false;
                }

                return target.isNil();
            }
        }

        /**
         * True if has "param0" element
         */
        public boolean isSetParam0() {
            synchronized (monitor()) {
                check_orphaned();

                return get_store().count_elements(PARAM0$0) != 0;
            }
        }

        /**
         * Sets the "param0" element
         */
        public void setParam0(java.lang.String param0) {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.SimpleValue target = null;
                target = (org.apache.xmlbeans.SimpleValue) get_store()
                                                               .find_element_user(PARAM0$0,
                        0);

                if (target == null) {
                    target = (org.apache.xmlbeans.SimpleValue) get_store()
                                                                   .add_element_user(PARAM0$0);
                }

                target.setStringValue(param0);
            }
        }

        /**
         * Sets (as xml) the "param0" element
         */
        public void xsetParam0(org.apache.xmlbeans.XmlString param0) {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.XmlString target = null;
                target = (org.apache.xmlbeans.XmlString) get_store()
                                                             .find_element_user(PARAM0$0,
                        0);

                if (target == null) {
                    target = (org.apache.xmlbeans.XmlString) get_store()
                                                                 .add_element_user(PARAM0$0);
                }

                target.set(param0);
            }
        }

        /**
         * Nils the "param0" element
         */
        public void setNilParam0() {
            synchronized (monitor()) {
                check_orphaned();

                org.apache.xmlbeans.XmlString target = null;
                target = (org.apache.xmlbeans.XmlString) get_store()
                                                             .find_element_user(PARAM0$0,
                        0);

                if (target == null) {
                    target = (org.apache.xmlbeans.XmlString) get_store()
                                                                 .add_element_user(PARAM0$0);
                }

                target.setNil();
            }
        }

        /**
         * Unsets the "param0" element
         */
        public void unsetParam0() {
            synchronized (monitor()) {
                check_orphaned();
                get_store().remove_element(PARAM0$0, 0);
            }
        }
    }
}
