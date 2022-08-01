#!/usr/bin/env pypy3

"""@package vipermonkey.export_all_excel_sheets Export all of the
sheets of an Excel file as separate CSV files. This is Python 3.

"""

import sys
import os
import subprocess
import codecs
import string
import json
import pathlib

from core.logger import log
from core.utils import safe_str_convert

def strip_unprintable(the_str):
    """Strip out unprinatble chars from a string.

    @param the_str (str) The string to strip.

    @return (str) The given string with unprintable chars stripped
    out.

    """
    
    # Grr. Python2 unprintable stripping.
    r = the_str
    if ((isinstance(r, str)) or (not isinstance(r, bytes))):
        r = ''.join([x for x in r if x in string.printable])
        
    # Grr. Python3 unprintable stripping.
    else:
        tmp_r = ""
        for char_code in [x for x in r if chr(x) in string.printable]:
            tmp_r += chr(char_code)
        r = tmp_r

    # Done.
    return r

def to_str(s):
    """
    Convert a bytes like object to a str.

    param s (bytes) The string to convert to str. If this is already str
    the original string will be returned.

    @return (str) s as a str.
    """

    # Needs conversion?
    if (isinstance(s, bytes)):
        try:
            return s.decode()
        except UnicodeDecodeError:
            return strip_unprintable(s)
    return s

def is_excel_file(maldoc):
    """Check to see if the given file is an Excel file.

    @param maldoc (str) The name of the file to check.

    @return (bool) True if the file is an Excel file, False if not.

    """
    typ = subprocess.check_output(["file", maldoc])
    if ((b"Excel" in typ) or (b"Microsoft OOXML" in typ)):
        return True
    try:
        typ = subprocess.check_output(["exiftool", maldoc])
        return (b"vnd.ms-excel" in typ)
    except subprocess.CalledProcessError:
        # Probably caused by a "Error reading FAT from sector..." error
        # with exiftool. Punt and assume this is not a readable Excel
        # file.
        return False

def fix_file_name(fname):
    """
    Replace non-printable ASCII characters in the given file name.
    """
    r = ""
    for c in fname:
        if ((ord(c) < 48) or (ord(c) > 122)):
            r += hex(ord(c))
            continue
        r += c

    return r

def convert_csv(fname):
    """Convert all of the sheets in a given Excel spreadsheet to CSV
    files. Also get the name of the currently active sheet.

    @param fname (str) The name of the Excel file.
    
    @return (list) A list where the 1st element is the name of the
    currently active sheet ("NO_ACTIVE_SHEET" if no sheets are active)
    and the rest of the elements are the names (str) of the CSV sheet
    files.

    """

    # Make sure this is an Excel file.
    if (not is_excel_file(fname)):

        # Not Excel, so no sheets.
        return []

    # The LibreOffice macro only works on absolute paths. Get the absolute path
    # of the input file.
    full_fname = safe_str_convert(pathlib.Path(fname).resolve())
    
    # Run LibreOffice macros to dump all the sheets as CSV files.
    #macro = "'macro:///Standard.Module1.ExportSheetsFromFile(\"" + fname + "\")'"
    macro = "macro:///Standard.Module1.ExportSheetsFromFile(\"" + full_fname + "\")"
    cmd = ["timeout", "20", "libreoffice", "--invisible",
           "--nofirststartwizard", "--headless",
           "--norestore", macro]
    out = None
    try:
        out = subprocess.check_call(cmd)
    except Exception as e:
        log.error("Headless run of libreoffice to export Excel sheets failed. " + str(e))
        return []

    # Can't get stdout from running the macro, so we have to hard code where to look
    # for the file of info about the CSV export.
    info_fname = full_fname
    if ("/" in info_fname):
        info_fname = info_fname[info_fname.rindex("/") + 1:]
    info_fname = "/tmp/sheet_" + info_fname + "_info.json"

    # Read in the active sheet name and names of CSV files (JSON).
    r = None
    try:

        # Read in JSON data.
        f = open(info_fname, "r")
        r = json.load(f)
        f.close()

        # We have the data, clean up the info file.
        os.remove(info_fname)
        
    except IOError as e:
        log.error("Exporting " + safe_str_convert(fname) + " to CSV with LibreOffice failed. " + str(e))
        return []
    
    # Done.
    return r

###########################################################################
## Main Program
###########################################################################
if __name__ == '__main__':
    r = to_str(str(convert_csv(sys.argv[1])))
    print(r)
