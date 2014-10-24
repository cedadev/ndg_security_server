#!/usr/bin/env python
"""Test script django app with paster.
"""
__author__ = "P J Kershaw"
__date__ = "25/10/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
logging.basicConfig(level=logging.DEBUG)
from os import path

THIS_DIR = path.abspath(path.dirname(__file__))
INI_FILENAME = 'service.ini'
ini_filepath = path.join(THIS_DIR, INI_FILENAME) 

from paste.script.serve import ServeCommand

ServeCommand("serve").run([ini_filepath])
