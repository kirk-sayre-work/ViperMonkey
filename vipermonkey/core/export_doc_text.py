#!/usr/bin/env pypy3

"""@package vipermonkey.export_doc_text Export the document
text/tables of a Word document with LibreOffice.  This is Python 3.

"""

import subprocess
import time
import argparse
import json
import os
import signal
import re
import pathlib

from core.utils import safe_str_convert
from core.logger import log

###################################################################################################
def is_word_file(fname):
    """Check to see if the given file is a Word file.

    @param fname (str) The path of the file to check.

    @return (bool) True if the file is a Word file, False if not.

    """

    # Easy case. The file commands tells us this is a Word file.
    typ = subprocess.check_output(["file", fname])
    if ((b"Microsoft Office Word" in typ) or
        (b"Word 2007+" in typ) or
        (b"Microsoft OOXML" in typ)):
        return True

    # Harder case. This could be a Word file saved as XML.
    if (b"XML 1.0 document" not in typ):
        return False
    contents = None
    try:
        f = open(fname, "r")
        contents = f.read()
        f.close()
    except IOError:
        return False
    return ('<?mso-application progid="Word.Document"?>' in contents)

###################################################################################################
def get_tables(fname):
    """Get the text tables embedded in the Word doc.

    @param fname (str) The name of the Word file.

    @return (list) List of 2D arrays containing text content of all
    cells in all text tables of the document

    """

    # The LibreOffice macro only works on absolute paths. Get the absolute path
    # of the input file.
    full_fname = safe_str_convert(pathlib.Path(fname).resolve())
    
    # Run LibreOffice macros to dump all the tables.
    macro = "macro:///Standard.Module1.ExportTablesFromFile(\"" + full_fname + "\")"
    cmd = ["timeout", "20", "libreoffice", "--invisible",
           "--nofirststartwizard", "--headless",
           "--norestore", macro]
    out = None
    try:
        out = subprocess.check_call(cmd)
    except Exception as e:
        log.error("Headless run of libreoffice to export Document tables failed. " + str(e))
        return []        

    # Can't get stdout from running the macro, so we have to hard code where to look
    # for the file of info about the doc tables.
    info_fname = full_fname
    if ("/" in info_fname):
        info_fname = info_fname[info_fname.rindex("/") + 1:]
    info_fname = "/tmp/doc_tables_" + info_fname + ".txt"

    # In outfile:
    #
    # Table: ::START_TABLE::...::END_TABLE::
    # Row in Table: ::START_ROW::...::END_ROW::
    # Cell in Row in Table: ::START_CELL::...::END_CELL::

    # Parse text from macro results file into a list of lists with the
    # table data.
    data = None
    try:
        f = open(info_fname, "r")
        data = f.read()
        f.close()
        os.remove(info_fname)
    except (IOError,UnicodeDecodeError) as e:
        log.error("Read of file containing libreoffice exported Document tables failed. " + str(e))
        return []
    table_pat = r"::START_TABLE::.*?::END_TABLE::"
    row_pat = r"::START_ROW::.*?::END_ROW::"
    cell_pat = r"::START_CELL::(.*?)::END_CELL::"
    r = []
    for table_str in re.findall(table_pat, data, re.DOTALL):
        curr_table = []
        for row_str in re.findall(row_pat, table_str, re.DOTALL):
            curr_row = []
            for cell_str in re.findall(cell_pat, row_str, re.DOTALL):
                curr_row.append(cell_str)
            curr_table.append(curr_row)
        r.append(curr_table)

    # Done
    return r

###########################################################################
def get_text(fname):
    """Get the text of a Word document using LibreOffice.

    @param fname (str) The name of the Word file.

    @return (str) The document text on success, None on failure.

    """

    # Run headless LibreOffice to save the Word document as text.
    cmd = ["timeout", "20", "libreoffice", "--invisible",
           "--nofirststartwizard", "--headless",
           "--norestore", "--convert-to", "txt", fname]
    if ("/" in fname):
        out_dir = fname[:fname.rindex("/")]
        cmd.append("--outdir")
        cmd.append(out_dir)
    out = None
    try:
        out = subprocess.check_call(cmd)
    except Exception as e:
        log.error("Headless run of libreoffice to export Document text failed. " + str(e))
        return None
        
    # Get the contexts of the text file.
    out_fname = fname
    if ("." in out_fname):
        out_fname = out_fname[:out_fname.rindex(".")]
    out_fname = out_fname + ".txt"
    r = None
    try:

        # Read text.
        f = open(out_fname, "rb")
        r = safe_str_convert(f.read())
        f.close()

        # Clean up text file.
        os.remove(out_fname)
        
    except IOError as e:
        log.error("Read of file containing libreoffice exported Document text failed. " + str(e))
        return None

    # Done.
    return r

###########################################################################
## Main Program
###########################################################################
if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description="export text from various properties in a Word "
                                         "document via the LibreOffice API")
    arg_parser.add_argument("--tables", action="store_true",
                            help="export a list of 2D lists containing the cell contents"
                            "of each text table in the document")
    arg_parser.add_argument("--text", action="store_true",
                            help="export a string containing the document text")
    arg_parser.add_argument("-f", "--file", action="store", required=True,
                            help="path to the word doc")
    args = arg_parser.parse_args()

    # Make sure this is a word file.
    if (not is_word_file(args.file)):
    
        # Not Word, so no text.
        exit()

    # Get doc text or tables.
    if args.text:
        print((get_text(args.file)))
    elif args.tables:
        print((json.dumps(get_tables(args.file))))
