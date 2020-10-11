#!/usr/bin/env python
"""
ViperMonkey: Read in document metadata item.

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

# For Python 2+3 support:
from __future__ import print_function, absolute_import

from six import ensure_str
import logging
import subprocess

from vipermonkey.core.logger import log

class FakeMeta(object):
    pass

def get_metadata_exif(filename):

    # Use exiftool to get the document metadata.
    output = None
    try:
        output = ensure_str(subprocess.check_output(["exiftool", filename]))
    except Exception as e:
        log.error("Cannot read metadata with exiftool. " + str(e))
        return {}

    # Sanity check results.
    if (log.getEffectiveLevel() == logging.DEBUG):
        log.debug("exiftool output: '" + str(output) + "'")
    if (":" not in output):
        log.warning("Cannot read metadata with exiftool.")
        return {}
    
    # Store the metadata in an object.
    lines = output.split("\n")
    r = FakeMeta()
    for line in lines:
        line = line.strip()
        if ((len(line) == 0) or (":" not in line)):
            continue        
        field = line[:line.index(":")].strip().lower()
        val = line[line.index(":") + 1:].strip().replace("...", "\r\n")
        setattr(r, field, val)

    # Done.
    return r
