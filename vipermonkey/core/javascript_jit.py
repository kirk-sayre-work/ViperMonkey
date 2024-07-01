"""@package vipermonkey.core.javascript_jit Core functions for converting
VBScript/VBA to JavaScript.

"""

# pylint: disable=pointless-string-statement
"""
ViperMonkey: Core functions for converting VBScript/VBA to JavaScript.

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

# === LICENSE ==================================================================

# ViperMonkey is copyright (c) 2015-2016 Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

__version__ = '0.03'

# --- IMPORTS ------------------------------------------------------------------
import hashlib
import traceback
import re
import sys
import datetime

from core.curses_ascii import isprint
import pyparsing
import logging
from core.logger import log

from core.utils import safe_print, safe_str_convert
from core.vba_context import Context
from core.vba_object import VBA_Object, VbaLibraryFunc
from core.function_call_visitor import function_call_visitor
from core import utils
from core.lhs_var_visitor import lhs_var_visitor
from core.var_in_expr_visitor import var_in_expr_visitor
from core.let_statement_visitor import let_statement_visitor

def _boilerplate_to_javascript(indent):
    """Get starting boilerplate code for VB to JavaScript code.

    @param indent (int) The number of spaces to indent the generated
    JavaScript code.
    
    @return (str) The boilerplate JavaScript code for the beginning of a
    JavaScript code block.

    """
    indent_str = " " * indent
    boilerplate = ""
    boilerplate += indent_str + "function CLng(s) {\n"
    boilerplate += indent_str + "\n"
    boilerplate += indent_str + "    // Only converting strings.\n"
    boilerplate += indent_str + "    if (typeof(s) !== \"string\") return s;\n"
    boilerplate += indent_str + "\n"
    boilerplate += indent_str + "    // Handle VB hex strings.\n"
    boilerplate += indent_str + "    if (s.startsWith(\"&H\")) {\n"
    boilerplate += indent_str + "	s = s.slice(2);\n"
    boilerplate += indent_str + "	return parseInt(s, 16);\n"
    boilerplate += indent_str + "    }\n"
    boilerplate += indent_str + "\n"
    boilerplate += indent_str + "    // Assume regular int.\n"
    boilerplate += indent_str + "    return parseInt(s);\n"
    boilerplate += indent_str + "}\n"
    boilerplate += "\n"
    boilerplate += indent_str + "function StrReverse(str) {\n"
    boilerplate += indent_str + '    return str.split("").reverse().join("");\n'
    boilerplate += indent_str + "}\n"
    boilerplate += "\n"
    boilerplate += indent_str + "function Replace(s, sub, rep) {\n"
    boilerplate += indent_str + "    return s.replaceAll(sub, rep);\n"
    boilerplate += indent_str + "}\n"
    boilerplate += "\n"
    return boilerplate
    
def transpile_javascript(arg):
    """Transpile the parsed VB code to Javascript. This is the top level
    function for doing the transpiling.

    @param arg (VBA_Object object) The code for which to generate
    JavaScript code.

    @return (str) The Javascript code for the given VB.

    """

    # Add in JS for some JS implementations of VB functions.
    r = _boilerplate_to_javascript(0)

    # Add in JS for actual VB program.
    r += to_javascript(arg)

    # Done.
    return r
    
def to_javascript(arg, params=None, indent=0, statements=False):
    """Call arg.to_javascript() if arg is a VBAObject, otherwise just return
    arg as a str.

    @param arg (VBA_Object object) The code for which to generate
    JavaScript code.

    @param params (list) Any VB params used by the given VBA_Object.

    @param indent (int) The number of spaces to indent the generated
    JavaScript code.

    @param statements (boolean) If True the value given in the arg
    parameter is a list of VB statements (VBA_Object) to convert to
    JavaScript, if False arg is just a single item to convert as a unit.

    @return (str) The Javascript code for the given VB.
    """
        
    # VBA Object?
    r = None
    #print(type(arg))
    #print(hasattr(arg, "to_javascript"))
    if (hasattr(arg, "to_javascript") and
        ((safe_str_convert(type(arg.to_javascript)) == "<type 'method'>") or
         (safe_str_convert(type(arg.to_javascript)) == "<class 'method'>") or
         (safe_str_convert(type(arg.to_javascript)) == "<type 'instancemethod'>") or
         (safe_str_convert(type(arg.to_javascript)) == "<class 'instancemethod'>"))):
        r = arg.to_javascript(params=params, indent=indent)

    # Datetime object?
    elif (isinstance(arg, datetime.datetime)):

        # For now just treat this as a string.
        r = '"' + str(arg) + '"'

    # Boolean literal?
    elif (isinstance(arg, bool)):
        if arg:
            r = "true"
        else:
            r = "false"
            
    # String literal?
    elif (isinstance(arg, str)):

        # Escape some characters.
        the_str = safe_str_convert(arg)
        the_str = safe_str_convert(the_str).\
                  replace("\\", "\\\\").\
                  replace('"', '\\"').\
                  replace("\n", "\\n").\
                  replace("\t", "\\t").\
                  replace("\r", "\\r")
        for i in range(0, 9):
            repl = hex(i).replace("0x", "")
            if (len(repl) == 1):
                repl = "0" + repl
            repl = "\\x" + repl
            the_str = the_str.replace(chr(i), repl)
        for i in range(11, 13):
            repl = hex(i).replace("0x", "")
            if (len(repl) == 1):
                repl = "0" + repl
            repl = "\\x" + repl
            the_str = the_str.replace(chr(i), repl)
        for i in range(14, 32):
            repl = hex(i).replace("0x", "")
            if (len(repl) == 1):
                repl = "0" + repl
            repl = "\\x" + repl
            the_str = the_str.replace(chr(i), repl)
        for i in range(127, 255):
            repl = hex(i).replace("0x", "")
            if (len(repl) == 1):
                repl = "0" + repl
            repl = "\\x" + repl
            the_str = the_str.replace(chr(i), repl)
        r = " " * indent + '"' + the_str + '"'

    # List of statements?
    elif (isinstance(arg, (list, pyparsing.ParseResults)) and statements):
        r = ""
        for statement in arg:
            try:
                r += to_javascript(statement, indent=indent) + "\n"
            except Exception as e:
                #print(statement)
                #print(e)
                #traceback.print_exc(file=sys.stdout)
                #sys.exit(0)
                return "ERROR! to_javascript failed! " + safe_str_convert(e)

    # Some other literal?
    else:
        arg_str = None
        try:
            arg_str = safe_str_convert(arg)
        except UnicodeEncodeError:
            arg_str = list(filter(isprint, arg))
        r = " " * indent + arg_str
        
    #print("--- to_javascript() ---")
    #print(arg)
    #print(type(arg))
    #print(r)
        
    # Done.
    return r
