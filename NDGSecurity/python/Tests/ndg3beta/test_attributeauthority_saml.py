#!/usr/bin/env python
import logging
logging.basicConfig(level=logging.DEBUG)
import unittest

from ndg.security.test.unit.attributeauthorityclient.\
test_attributeauthorityclient import AttributeAuthoritySAMLInterfaceTestCase

import os
os.environ['NDGSEC_AACLNT_UNITTEST_DIR'] = os.path.abspath(
                                                    os.path.dirname(__file__))
                                                                                                          
if __name__ == "__main__":
    unittest.main()
