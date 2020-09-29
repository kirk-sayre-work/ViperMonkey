#!/usr/bin/env python
"""
ViperMonkey: VBA Grammar - Base class for all VBA objects

ViperMonkey is a specialized engine to parse, analyze and interpret Microsoft
VBA macros (Visual Basic for Applications), mainly for malware analysis.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

# === LICENSE ==================================================================

# ViperMonkey is copyright (c) 2015-2019 Philippe Lagadec (http://www.decalage.info)
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

# For Python 2+3 support:
from __future__ import print_function, absolute_import

# ------------------------------------------------------------------------------
# CHANGELOG:
# 2015-02-12 v0.01 PL: - first prototype
# 2015-2016        PL: - many updates
# 2016-06-11 v0.02 PL: - split vipermonkey into several modules

__version__ = '0.08'

# ------------------------------------------------------------------------------
# TODO:

# --- IMPORTS ------------------------------------------------------------------

import logging
import base64
import re
import traceback
import string
import gc
import hashlib

from inspect import getouterframes, currentframe
import sys
from datetime import datetime
import pyparsing
from six import text_type, string_types, iteritems

from vipermonkey.core.logger import log
from vipermonkey.core.curses_ascii import isprint
from vipermonkey.core import expressions
from vipermonkey.core.var_in_expr_visitor import *
from vipermonkey.core.lhs_var_visitor import *
from vipermonkey.core.utils import safe_print
from vipermonkey.core import utils
from vipermonkey.core.let_statement_visitor import *
from vipermonkey.core.vba_context import *

max_emulation_time = None

class VbaLibraryFunc(object):
    """
    Marker class to tell if a class implements a VBA function.
    """

    def num_args(self):
        """
        Get the # of arguments (minimum) required by the functio.
        """
        log.warning("Using default # args of 1 for " + str(type(self)))
        return 1

    def return_type(self):
        """
        Get the python type returned from the emulated function ('INTEGER' or 'STRING').
        """
        log.warning("Using default return type of 'INTEGER' for " + str(type(self)))
        return "INTEGER"

def excel_col_letter_to_index(x): 
    return (reduce(lambda s,a:s*26+ord(a)-ord('A')+1, x, 0) - 1)

def limits_exceeded(throw_error=False):
    """
    Check to see if we are about to exceed the maximum recursion depth. Also check to 
    see if emulation is taking too long (if needed).
    """

    # Check to see if we are approaching the recursion limit.
    level = len(getouterframes(currentframe()))
    recursion_exceeded = (level > (sys.getrecursionlimit() * .50))
    time_exceeded = False

    # Check to see if we have exceeded the time limit.
    if (max_emulation_time is not None):
        time_exceeded = (datetime.now() > max_emulation_time)

    if (recursion_exceeded):
        log.error("Call recursion depth approaching limit.")
        if (throw_error):
            raise RuntimeError("The ViperMonkey recursion depth will be exceeded. Aborting analysis.")
    if (time_exceeded):
        log.error("Emulation time exceeded.")
        if (throw_error):
            raise RuntimeError("The ViperMonkey emulation time limit was exceeded. Aborting analysis.")
        
    return (recursion_exceeded or time_exceeded)

class VBA_Object(object):
    """
    Base class for all VBA objects that can be evaluated.
    """

    # Upper bound for loop iterations. 0 or less means unlimited.
    loop_upper_bound = 10000000
    
    def __init__(self, original_str, location, tokens):
        """
        VBA_Object constructor, to be called as a parse action by a pyparsing parser

        :param original_str: original string matched by the parser
        :param location: location of the match
        :param tokens: tokens extracted by the parser
        :return: nothing
        """
        self.original_str = original_str
        self.location = location
        self.tokens = tokens
        self._children = None
        self.is_useless = False
        self.is_loop = False
        
    def eval(self, context, params=None):
        """
        Evaluate the current value of the object.

        :param context: Context for the evaluation (local and global variables)
        :return: current value of the object
        """
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug(self)
        # raise NotImplementedError

    def full_str(self):
        return str(self)
        
    def get_children(self):
        """
        Return the child VBA objects of the current object.
        """

        # Check for timeouts.
        limits_exceeded(throw_error=True)
        
        # The default behavior is to count any VBA_Object attribute as
        # a child.
        if ((hasattr(self, "_children")) and (self._children is not None)):
            return self._children
        r = []
        for _, value in iteritems(self.__dict__):
            if (isinstance(value, VBA_Object)):
                r.append(value)
            if ((isinstance(value, list)) or
                (isinstance(value, pyparsing.ParseResults))):
                for i in value:
                    if (isinstance(i, VBA_Object)):
                        r.append(i)
            if (isinstance(value, dict)):
                for i in value.values():
                    if (isinstance(i, VBA_Object)):
                        r.append(i)
        self._children = r
        return r
                        
    def accept(self, visitor, no_embedded_loops=False):
        """
        Visitor design pattern support. Accept a visitor.
        """

        # Check for timeouts.
        limits_exceeded(throw_error=True)
        
        # Skipping visiting embedded loops? Check to see if we are already
        # in a loop and the current VBA object is a loop.
        if (no_embedded_loops and
            hasattr(visitor, "in_loop") and
            visitor.in_loop and
            self.is_loop):
            #print("SKIPPING LOOP!!")
            #print(self)
            return

        # Set initial in loop status of visitor if needed.
        if (not hasattr(visitor, "in_loop")):
            visitor.in_loop = self.is_loop

        # Have we moved into a loop?
        if ((not visitor.in_loop) and (self.is_loop)):
            visitor.in_loop = True

        # Visit the current item.
        visit_status = visitor.visit(self)
        if (not visit_status):
            return

        # Save the in loop status so we can restore it after visiting the children.
        old_in_loop = visitor.in_loop
        
        # Visit all the children.
        for child in self.get_children():
            child.accept(visitor, no_embedded_loops=no_embedded_loops)

        # Back in current VBA object. Restore the in loop status.
        visitor.in_loop = old_in_loop

    def to_python(self, context, params=None, indent=0):
        """
        JIT compile this VBA object to Python code for direct emulation.
        """
        raise NotImplementedError("to_python() not implemented in " + str(type(self)))

def _read_from_excel(arg, context):
    """
    Try to evaluate an argument by reading from the loaded Excel spreadsheet.
    """

    # Try handling reading value from an Excel spreadsheet cell.
    # ThisWorkbook.Sheets('YHRPN').Range('J106').Value
    arg_str = str(arg)
    if (("MemberAccessExpression" in str(type(arg))) and
        ("sheets(" in arg_str.lower()) and
        (("range(" in arg_str.lower()) or ("cells(" in arg_str.lower()))):
        
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Try as Excel cell read...")
        
        # Pull out the sheet name.
        tmp_arg_str = arg_str.lower()
        start = tmp_arg_str.index("sheets(") + len("sheets(")
        end = start + tmp_arg_str[start:].index(")")
        sheet_name = arg_str[start:end].strip().replace('"', "").replace("'", "").replace("//", "")
        
        # Pull out the cell index.
        start = None
        if ("range(" in arg_str.lower()):
            start = tmp_arg_str.index("range(") + len("range(")
        else:
            start = tmp_arg_str.index("cells(") + len("cells(")
        end = start + tmp_arg_str[start:].index(")")
        cell_index = arg_str[start:end].strip().replace('"', "").replace("'", "").replace("//", "")
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Sheet name = '" + sheet_name + "', cell index = " + cell_index)
        
        try:
            
            # Load the sheet.
            sheet = context.loaded_excel.sheet_by_name(sheet_name)
            
            # Pull out the cell column and row.

            # Do we have something like '10, 30'?
            index_pat = r"(\d+)\s*,\s*(\d+)"
            if (re.search(index_pat, cell_index) is not None):
                indices = re.findall(index_pat, cell_index)[0]
                row = int(indices[0]) - 1
                col = int(indices[1]) - 1

            # Maybe something like 'A4:B7' ?
            else:
                col = ""
                row = ""
                for c in cell_index:
                    if (c.isalpha()):
                        col += c
                    else:
                        row += c
                    
                # Convert the row and column to numeric indices for xlrd.
                row = int(row) - 1
                col = excel_col_letter_to_index(col)
            
            # Pull out the cell value.
            val = str(sheet.cell_value(row, col))
            
            # Return the cell value.
            log.info("Read cell (" + str(cell_index) + ") from sheet " + str(sheet_name))
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("Cell value = '" + str(val) + "'")
            return val
        
        except Exception as e:
            context.report_general_error("Cannot read cell from Excel spreadsheet. " + str(e))

def _read_from_object_text(arg, context):
    """
    Try to read in a value from the text associated with a object like a Shape.
    """

    # Do we have an object text access?
    arg_str = str(arg)
    arg_str_low = arg_str.lower().strip()

    # Shapes('test33').      TextFrame.TextRange.text
    # Shapes('FrXXBbPlWaco').TextFrame.TextRange
    #
    # Make sure not to pull out Shapes() references that appear as arguments to function
    # calls.
    if (("shapes(" in arg_str_low) and (not isinstance(arg, expressions.Function_Call))):

        # Yes we do. 
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: Try to get as ....TextFrame.TextRange.Text value: " + arg_str.lower())

        # Handle member access?
        lhs = "Shapes('1')"
        if ("inlineshapes" in arg_str_low):
            lhs = "InlineShapes('1')"
        if ("MemberAccessExpression" in str(type(arg))):

            # Drop off ActiveDocument prefix.
            lhs = arg.lhs
            if ((str(lhs) == "ActiveDocument") or (str(lhs) == "ThisDocument")):
                lhs = arg.rhs[0]
        
            # Eval the leftmost prefix element of the member access expression first.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_obj_text: Old member access lhs = " + str(lhs))
            if ((hasattr(lhs, "eval")) and
                (not isinstance(lhs, pyparsing.ParseResults))):
                lhs = lhs.eval(context)
            else:

                # Look this up as a variable name.
                var_name = str(lhs)
                try:
                    lhs = context.get(var_name)
                except KeyError:
                    lhs = var_name

            if (lhs == "NULL"):
                lhs = "Shapes('1')"
            if ("inlineshapes" in arg_str_low):
                lhs = "InlineShapes('1')"
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_obj_text: Evaled member access lhs = " + str(lhs))
        
        # Try to get this as a doc var.
        doc_var_name = str(lhs) + ".TextFrame.TextRange.Text"
        doc_var_name = doc_var_name.replace(".TextFrame.TextFrame", ".TextFrame")
        if (("InlineShapes(" in doc_var_name) and (not doc_var_name.startswith("InlineShapes("))):
            doc_var_name = doc_var_name[doc_var_name.index("InlineShapes("):]
        elif (("Shapes(" in doc_var_name) and
              (not doc_var_name.startswith("Shapes(")) and
              ("InlineShapes(" not in doc_var_name)):
            doc_var_name = doc_var_name[doc_var_name.index("Shapes("):]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_obj_text: Looking for object text " + str(doc_var_name))
        val = context.get_doc_var(doc_var_name.lower())
        if (val is not None):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_obj_text: Found " + str(doc_var_name) + " = " + str(val))
            return val

        # Not found. Try looking for the object with index 1.
        lhs_str = str(lhs)
        if ("'" not in lhs_str):
            return None
        new_lhs = lhs_str[:lhs_str.index("'") + 1] + "1" + lhs_str[lhs_str.rindex("'"):]
        doc_var_name = new_lhs + ".TextFrame.TextRange.Text"
        doc_var_name = doc_var_name.replace(".TextFrame.TextFrame", ".TextFrame")
        if (("InlineShapes(" in doc_var_name) and (not doc_var_name.startswith("InlineShapes("))):
            doc_var_name = doc_var_name[doc_var_name.index("InlineShapes("):]
        elif (("Shapes(" in doc_var_name) and
              (not doc_var_name.startswith("Shapes(")) and
              ("InlineShapes(" not in doc_var_name)):
            doc_var_name = doc_var_name[doc_var_name.index("Shapes("):]
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: Fallback, looking for object text " + str(doc_var_name))
        val = context.get_doc_var(doc_var_name.lower())
        return val
    
constant_expr_cache = {}

def get_cached_value(arg):
    """
    Get the cached value of an all constant numeric expression if we have it.
    """

    # Don't do any more work if this is already a resolved value.
    if (isinstance(arg, int)):
        return arg

    # This is not already resolved to an int. See if we computed this before.
    arg_str = str(arg)
    if (arg_str not in constant_expr_cache.keys()):
        return None
    return constant_expr_cache[arg_str]

def set_cached_value(arg, val):
    """
    Set the cached value of an all constant numeric expression.
    """

    # We should be setting this to a numeric expression
    if ((not isinstance(val, int)) and
        (not isinstance(val, float)) and
        (not isinstance(val, complex))):
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.warning("Expression '" + str(val) + "' is a " + str(type(val)) + ", not an int. Not caching.")
        return

    # We have a number. Cache it.
    arg_str = str(arg)
    try:
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Cache value of " + arg_str + " = " + str(val))
    except UnicodeEncodeError:
        pass
    constant_expr_cache[arg_str] = val
    
def is_constant_math(arg):
    """
    See if a given expression is a simple math expression with all literal numbers.
    """

    # Sanity check. If there are variables in the expression it is not all literals.
    if (isinstance(arg, VBA_Object)):
        var_visitor = var_in_expr_visitor()
        arg.accept(var_visitor)
        if (len(var_visitor.variables) > 0):
            return False
    
    # Speed this up with the rure regex library if it is installed.
    try:
        import rure as local_re
    except ImportError:
        import re as local_re

    base_pat = "(?:\\s*\\d+(?:\\.\\d+)?\\s*[+\\-\\*/]\\s*)*\\s*\\d+"
    paren_pat = base_pat + "|(?:\\((?:\\s*" + base_pat + "\\s*[+\\-\\*\\\\]\\s*)*\\s*" + base_pat + "\\))"
    arg_str = str(arg).strip()
    try:
        arg_str = text_type(arg_str)
    except UnicodeDecodeError:
        arg_str = filter(isprint, arg_str)
        arg_str = text_type(arg_str)
    return (local_re.match(text_type(paren_pat), arg_str) is not None)

meta = None

def _boilerplate_to_python(indent):
    """
    Get starting boilerplate code for VB to Python JIT code.
    """
    indent_str = " " * indent
    boilerplate = indent_str + "from vipermonkey.core import vba_library\n"
    boilerplate += indent_str + "from vipermonkey.core.utils import safe_print\n"
    boilerplate += indent_str + "from vipermonkey.core import utils\n"
    boilerplate += indent_str + "from vipermonkey.core.vba_object import update_array\n"
    boilerplate += indent_str + "from vipermonkey.core.vba_object import coerce_to_num\n"
    boilerplate += indent_str + "from vipermonkey.core.vba_object import coerce_to_int\n"
    boilerplate += indent_str + "from vipermonkey.core.vba_object import coerce_to_string\n"
    boilerplate += indent_str + "from vipermonkey.core.vba_object import coerce_to_int_list\n\n"
    boilerplate += indent_str + "try:\n"
    boilerplate += indent_str + " " * 4 + "vm_context\n"
    boilerplate += indent_str + "except NameError:\n"
    boilerplate += indent_str + " " * 4 + "vm_context = context\n"
    return boilerplate

def _infer_type_of_expression(expr):
    """
    Try to determine if a given expression is an "INTEGER" or "STRING" expression.
    """

    from vipermonkey.core import operators
    from vipermonkey.core import vba_library

    #print(expr)
    #print(type(expr))

    # Function with a hard coded type?
    if (hasattr(expr, "return_type")):
        return expr.return_type()

    # Call of builtin function?
    if (isinstance(expr, expressions.Function_Call) and
        (expr.name.lower() in vba_library.VBA_LIBRARY)):
        builtin = vba_library.VBA_LIBRARY[expr.name.lower()]
        if (hasattr(builtin, "return_type")):
            return builtin.return_type()
    
    # Easy cases. These have to be integers.
    if (isinstance(expr, operators.Xor) or
        isinstance(expr, operators.And) or
        isinstance(expr, operators.Or) or
        isinstance(expr, operators.Not) or
        isinstance(expr, operators.Neg) or
        isinstance(expr, operators.Subtraction) or
        isinstance(expr, operators.Multiplication) or
        isinstance(expr, operators.Power) or
        isinstance(expr, operators.Division) or
        isinstance(expr, operators.MultiDiv) or
        isinstance(expr, operators.FloorDivision) or
        isinstance(expr, operators.Mod) or        
        isinstance(expr, operators.Xor)):
        return "INTEGER"

    # Must be a string.
    if (isinstance(expr, operators.Concatenation)):
        return "STRING"
    
    # Harder case. This could be an int or a str (or some other numeric type, but
    # we're not handling that).
    if (isinstance(expr, operators.AddSub)):

        # If we are doing subtraction we need numeric types.
        if ("-" in expr.operators):
            return "INTEGER"
        
        # We have only '+'. Try to figure out the type based on the parts of the expression.
        for child in expr.get_children():
            child_type = _infer_type_of_expression(child)
            if (child_type is not None):
                return child_type

    # Can't figure out the type.
    return None
    
def _infer_type(var, code_chunk, context):
    """
    Try to infer the type of an undefined variable based on how it is used ("STRING" or "INTEGER").

    This is currently purely a heuristic.
    """

    # Get all the assignments in the code chunk.
    visitor = let_statement_visitor(var)
    code_chunk.accept(visitor)

    # Look at each assignment statement and check out the ones where the current
    # variable is assigned.
    str_funcs = ["cstr(", "chr(", "left(", "right(", "mid(", "join(", "lcase(",
                 "replace(", "trim(", "ucase(", "chrw(", " & "]
    for assign in visitor.let_statements:

        # Try to infer the type somewhat logically.
        poss_type = _infer_type_of_expression(assign.expression)
        if (poss_type is not None):
            return poss_type
        
        # Does a VBA function that returns a string appear on the RHS?
        rhs = str(assign.expression).lower()
        for str_func in str_funcs:
            if (str_func in rhs):
                return "STRING"

    # Does not look like a string, assume int.
    return "INTEGER"

def _get_var_vals(item, context, global_only=False):
    """
    Get the current values for all of the referenced VBA variables that appear in the 
    given VBA object.

    Returns a dict mapping var names to values.
    """

    from vipermonkey.core import procedures

    # Get all the variables.

    # Vars on RHS.
    var_visitor = var_in_expr_visitor(context)
    item.accept(var_visitor, no_embedded_loops=False)
    var_names = var_visitor.variables

    # Vars on LHS.
    lhs_visitor = lhs_var_visitor()
    item.accept(lhs_visitor, no_embedded_loops=False)
    lhs_var_names = lhs_visitor.variables

    # Handle member access expressions.
    var_names = var_names.union(lhs_var_names)
    tmp = set()
    for var in var_names:
        tmp.add(var)
        if ("." in var):
            tmp.add(var[:var.index(".")])
    var_names = tmp
    
    # Get a value for each variable.
    r = {}
    zero_arg_funcs = set()
    for var in var_names:

        # Do we already know the variable value?        
        val = None
        orig_val = None
        try:

            # Try to get the current value.
            val = context.get(var, global_only=global_only)
            orig_val = val
            
            # We have been kind of fuzzing the distinction between global and
            # local variables, so tighten down on globals only by just picking
            # up VB constants.
            if (global_only and
                (var not in context.vb_constants) and
                (var.lower() not in context.vb_constants)):
                continue
            
            # Do not set function arguments to new values.
            # Do not set loop index variables to new values.
            if ((val == "__FUNC_ARG__") or
                (val == "__ALREADY_SET__") or
                (val == "__LOOP_VAR__")):
                continue
            
            # Function definitions are not valid values.
            if (isinstance(val, procedures.Function) or
                isinstance(val, procedures.Sub) or
                isinstance(val, VbaLibraryFunc)):

                # Don't use the function definition as the value.
                val = None
                
                # 0 arg func calls should only appear on the RHS
                if (var not in lhs_var_names):
                    zero_arg_funcs.add(var)

                    # Don't treat these function calls as variables and
                    # assign initial values to them.
                    context.set("__ORIG__" + var, orig_val, force_local=True)
                    context.set("__ORIG__" + var, orig_val, force_global=True)
                    continue

            # 'inf' is not a valid value.
            if ((str(val).strip() == "inf") or
                (str(val).strip() == "-inf")):
                val = None

            # 'NULL' is not a valid value.
            if (str(val).strip() == "NULL"):
                val = None

            # Weird bug.
            if ("fvba_library.run_function" in str(val)):
                val = 0
            
        # Unedfined variable.
        except KeyError:
            if global_only:
                continue

        # Got a valid value for the variable?
        if (val is None):

            # Variable is not defined. Try to infer the type based on how it is used.
            var_type = _infer_type(var, item, context)
            if (var_type == "INTEGER"):
                val = 0
            elif (var_type == "STRING"):
                val = ""
            else:
                raise ValueError("Type " + str(var_type) + " not handled.")

        # Rename some vars that overlap with python builtins.
        var = utils.fix_python_overlap(var)
            
        # Save the variable value.
        r[var] = val

        # Mark this variable as being set in the Python code to avoid
        # embedded loop Python code generation stomping on the value.
        context.set(var, "__ALREADY_SET__", force_local=True)
        context.set(var, "__ALREADY_SET__", force_global=True)
        
        # Save the original value so we know it's data type for later use in JIT
        # code generation.
        if (orig_val is None):
            orig_val = val
        context.set("__ORIG__" + var, orig_val, force_local=True)
        context.set("__ORIG__" + var, orig_val, force_global=True)
        
    # Done.
    return (r, zero_arg_funcs)

def _loop_vars_to_python(loop, context, indent):
    """
    Set up initialization of variables used in a loop in Python.
    """
    indent_str = " " * indent
    loop_init = ""
    init_vals, _ = _get_var_vals(loop, context)
    sorted_vars = list(init_vals.keys())
    sorted_vars.sort()
    for var in sorted_vars:
        val = to_python(init_vals[var], context)
        loop_init += indent_str + str(var).replace(".", "") + " = " + val + "\n"
    try:
        hash_object = hashlib.md5(str(loop).encode())
    except UnicodeDecodeError:
        hash_object = hashlib.md5(filter(isprint, str(loop)).encode())

    prog_var = "pct_" + hash_object.hexdigest()
    loop_init += indent_str + prog_var + " = 0\n"
    loop_init = indent_str + "# Initialize variables read in the loop.\n" + loop_init
    return (loop_init, prog_var)

def to_python(arg, context, params=None, indent=0, statements=False):
    """
    Call arg.to_python() if arg is a VBAObject, otherwise just return arg as a str.
    """

    #print("--- to_python() ---")
    #print(arg)
    #print(type(arg))
        
    # VBA Object?
    r = None
    if (hasattr(arg, "to_python") and
        ((str(type(arg.to_python)) == "<type 'method'>") or
         (str(type(arg.to_python)) == "<type 'instancemethod'>"))):
        r = arg.to_python(context, params=params, indent=indent)

    # String literal?
    elif (isinstance(arg, str)):

        # Escape some characters.
        the_str = str(arg)
        the_str = str(the_str).\
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
    elif ((isinstance(arg, list) or
           isinstance(arg, pyparsing.ParseResults)) and statements):
        r = ""
        indent_str = " " * indent
        for statement in arg:
            r += indent_str + "try:\n"
            try:
                r += to_python(statement, context, indent=indent+4) + "\n"
            except Exception as e:
                #print(statement)
                #print(e)
                #traceback.print_exc(file=sys.stdout)
                #sys.exit(0)
                return "ERROR! to_python failed! " + str(e)
            r += indent_str + "except Exception as e:\n"
            if (log.getEffectiveLevel() == logging.DEBUG):
                r += indent_str + " " * 4 + "safe_print(\"ERROR: \" + str(e))\n"
            else:
                r += indent_str + " " * 4 + "pass\n"

    # Some other literal?
    else:
        r = " " * indent + str(arg)

    # Done.
    return r

def _check_for_iocs(loop, context, indent):
    """
    Check the variables modified in a loop to see if they were
    set to interesting IOCs.
    """
    indent_str = " " * indent
    lhs_visitor = lhs_var_visitor()
    loop.accept(lhs_visitor)
    lhs_var_names = lhs_visitor.variables
    ioc_str = indent_str + "# Check for IOCs in intermediate variables.\n"
    for var in lhs_var_names:
        py_var = utils.fix_python_overlap(var)
        ioc_str += indent_str + "try:\n"
        ioc_str += indent_str + " "*4 + "vm_context.save_intermediate_iocs(" + py_var + ")\n"
        ioc_str += indent_str + "except:\n"
        ioc_str += indent_str + " "* 4 + "pass\n"
    return ioc_str

def _updated_vars_to_python(loop, context, indent):
    """
    Save the variables updated in a loop in Python.
    """
    indent_str = " " * indent
    lhs_visitor = lhs_var_visitor()
    loop.accept(lhs_visitor)
    lhs_var_names = lhs_visitor.variables
    var_dict_str = "{"
    first = True
    for var in lhs_var_names:
        py_var = utils.fix_python_overlap(var)
        if (not first):
            var_dict_str += ", "
        first = False
        var = var.replace(".", "")
        var_dict_str += '"' + var + '" : ' + py_var
    var_dict_str += "}"
    save_vals = indent_str + "try:\n"
    save_vals += indent_str + " " * 4 + "var_updates\n"
    save_vals += indent_str + " " * 4 + "var_updates.update(" + var_dict_str + ")\n"
    save_vals += indent_str + "except NameError:\n"
    save_vals += indent_str + " " * 4 + "var_updates = " + var_dict_str + "\n"
    save_vals = indent_str + "# Save the updated variables for reading into ViperMonkey.\n" + save_vals
    if (log.getEffectiveLevel() == logging.DEBUG):
        save_vals += indent_str + "print(\"UPDATED VALS!!\")\n"
        save_vals += indent_str + "print(var_updates)\n"
    return save_vals

def _eval_python(loop, context, params=None, add_boilerplate=False, namespace=None):
    """
    Convert the loop to Python and emulate the loop directly in Python.
    """

    # Are we actually doing this?
    if (not context.do_jit):
        return False

    # Emulating full VB programs in Python is difficult, so for now skip loops
    # that Execute() dynamic VB.
    code_vba = str(loop).replace("\n", "\\n")[:20]
    log.info("Starting JIT emulation of '" + code_vba + "...' ...")
    if (("Execute(" in str(loop)) or
        ("ExecuteGlobal(" in str(loop)) or
        ("Eval(" in str(loop))):
        log.warning("Loop Execute()s dynamic code. Not JIT emulating.")
        return False
    
    # Generate the Python code for the VB code and execute the generated Python code.
    # TODO: Remove dangerous functions from what can be exec'ed.
    code_python = ""
    try:

        # For JIT handling we modify the values of certain variables to
        # handle recursive python code generation, so make a copy of the
        # original context.
        tmp_context = Context(context=context, _locals=context.locals, copy_globals=True)
        
        # Get the Python code for the loop.
        code_python = to_python(loop, tmp_context)
        if add_boilerplate:
            var_inits, _ = _loop_vars_to_python(loop, tmp_context, 0)
            code_python = _boilerplate_to_python(0) + "\n" + \
                          var_inits + "\n" + \
                          code_python + "\n" + \
                          _check_for_iocs(loop, tmp_context, 0) + "\n" + \
                          _updated_vars_to_python(loop, tmp_context, 0)
        if (log.getEffectiveLevel() == logging.DEBUG):
            safe_print("JIT CODE!!")
            safe_print(code_python)

        # Extended ASCII strings are handled differently in VBScript and VBA.
        # Punt if we are emulating VBA and we have what appears to be extended ASCII
        # strings. For performance we are not handling the MS VBA extended ASCII in the python
        # JIT code.
        if (not context.is_vbscript):
            
            # Look for non-ASCII strings.
            non_ascii_pat = r'"[^"]*[\x7f-\xff][^"]*"'
            if (re.search(non_ascii_pat, code_python) is not None):
                log.warning("VBA code contains Microsoft specific extended ASCII strings. Not JIT emulating.")
                return False

        # Check for dynamic code execution in called functions.
        if (('"Execute", ' in code_python) or
            ('"ExecuteGlobal", ' in code_python) or
            ('"Eval", ' in code_python)):
            log.warning("Functions called by loop Execute() dynamic code. Not JIT emulating.")
            return False
            
        # Run the Python code.
        if (namespace is None):
            # Magic. For some reason exec'ing in locals() makes the dynamically generated
            # code recognize functions defined in the dynamic code. I don't know why.
            exec(code_python, locals())
        else:
            exec(code_python, namespace)
            var_updates = namespace["var_updates"]
        log.info("Done JIT emulation of '" + code_vba + "...' .")

        # Update the context with the variable values from the JIT code execution.
        for updated_var in var_updates.keys():
            context.set(updated_var, var_updates[updated_var])

    except NotImplementedError as e:
        log.error("JIT emulation failed. " + str(e))
        #safe_print("REMOVE THIS!!")
        #raise e
        return False

    except Exception as e:

        # If we bombed out due to a potential infinite loop we
        # are done.
        if ("Infinite Loop" in str(e)):
            log.warning("Detected infinite loop. Terminating loop.")
            return True

        # We had some other error. Emulating the loop in Python failed.
        log.error("JIT emulation failed. " + str(e))
        traceback.print_exc(file=sys.stdout)
        safe_print("-*-*-*-*-\n" + code_python + "\n-*-*-*-*-")
        return False

    # Done.
    return True

def eval_arg(arg, context, treat_as_var_name=False):
    """
    evaluate a single argument if it is a VBA_Object, otherwise return its value
    """

    # pypy seg faults sometimes if the recursion depth is exceeded. Try to
    # avoid that. Also check to see if emulation has taken too long.
    limits_exceeded(throw_error=True)

    if (log.getEffectiveLevel() == logging.DEBUG):
        log.debug("try eval arg: %s (%s, %s, %s)" % (arg, type(arg), isinstance(arg, VBA_Object), treat_as_var_name))

    # Is this a constant math expression?
    got_constant_math = is_constant_math(arg)
    
    # Do we have the cached value of this expression?
    cached_val = get_cached_value(arg)
    if (cached_val is not None):
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: Got cached value %r = %r" % (arg, cached_val))
        return cached_val
    
    # Try handling reading value from an Excel spreadsheet cell.
    excel_val = _read_from_excel(arg, context)
    if (excel_val is not None):
        if got_constant_math: set_cached_value(arg, excel_val)
        return excel_val

    # Short circuit the checks and see if we are accessing some object text first.
    obj_text_val = _read_from_object_text(arg, context)
    if (obj_text_val is not None):
        if got_constant_math: set_cached_value(arg, obj_text_val)
        return obj_text_val
    
    # Not reading from an Excel cell. Try as a VBA object.
    if ((isinstance(arg, VBA_Object)) or (isinstance(arg, VbaLibraryFunc))):

        # Handle cases where wscriptshell.run() is being called and there is a local run() function.
        if ((".run(" in str(arg).lower()) and (context.contains("run"))):

            # Resolve the run() call.
            if ("MemberAccessExpression" in str(type(arg))):
                arg_evaled = arg.eval(context)
                if got_constant_math: set_cached_value(arg, arg_evaled)
                return arg_evaled

        # Handle as a regular VBA object.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: eval as VBA_Object %s" % arg)
        r = arg.eval(context=context)

        # Is this a Shapes() access that still needs to be handled?
        poss_shape_txt = ""
        try:
            poss_shape_txt = str(r)
        except:
            pass
        if ((poss_shape_txt.startswith("Shapes(")) or (poss_shape_txt.startswith("InlineShapes("))):
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: Handling intermediate Shapes() access for " + str(r))
            r = eval_arg(r, context)
            if got_constant_math: set_cached_value(arg, r)
            return r
        
        # Regular VBA object.
        if got_constant_math: set_cached_value(arg, r)
        return r

    # Not a VBA object.
    else:
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: not a VBA_Object: %r" % arg)

        # Might this be a special type of variable lookup?
        if (isinstance(arg, str)):

            # Simple case first. Is this a variable?
            try:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval_arg: Try as variable name: %r" % arg)
                r = context.get(arg)
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval_arg: Got %r = %r" % (arg, r))
                if got_constant_math: set_cached_value(arg, r)
                return r
            except:
                    
                # No it is not. Try more complicated cases.
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval_arg: Not found as variable name: %r" % arg)
                pass
            else:
                if (log.getEffectiveLevel() == logging.DEBUG):
                    log.debug("eval_arg: Do not try as variable name: %r" % arg)

            # This is a hack to get values saved in the .text field of objects.
            # To do this properly we need to save "FOO.text" as a variable and
            # return the value of "FOO.text" when getting "FOO.nodeTypedValue".
            if ("nodetypedvalue" in arg.lower()):
                try:
                    tmp = arg.lower().replace("nodetypedvalue", "text")
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("eval_arg: Try to get as " + tmp + "...")
                    val = context.get(tmp)
    
                    # It looks like maybe this magically does base64 decode? Try that.
                    try:
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("eval_arg: Try base64 decode of '" + val + "'...")
                        base64_str = filter(isprint, str(base64_str).strip())
                        val_decode = base64.b64decode(str(val)).replace(chr(0), "")
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("eval_arg: Base64 decode success: '" + val_decode + "'...")
                        if got_constant_math: set_cached_value(arg, val_decode)
                        return val_decode
                    except Exception as e:
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("eval_arg: Base64 decode fail. " + str(e))
                        if got_constant_math: set_cached_value(arg, val)
                        return val
                except KeyError:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("eval_arg: Not found as .text.")
                    pass

            # This is a hack to get values saved in the .rapt.Value field of objects.
            elif (".selecteditem" in arg.lower()):
                try:
                    tmp = arg.lower().replace(".selecteditem", ".rapt.value")
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("eval_arg: Try to get as " + tmp + "...")
                    val = context.get(tmp)
                    if got_constant_math: set_cached_value(arg, val)
                    return val

                except KeyError:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("eval_arg: Not found as .rapt.value.")
                    pass

            # Is this trying to access some VBA form variable?
            elif ("." in arg.lower()):

                # Try easy button first. See if this is just a doc var.
                doc_var_val = context.get_doc_var(arg)
                if (doc_var_val is not None):
                    if got_constant_math: set_cached_value(arg, doc_var_val)
                    return doc_var_val

                # Peel off items seperated by a '.', trying them as functions.
                arg_peeled = arg
                while ("." in arg_peeled):
                
                    # Try it as a form variable.
                    curr_var_attempt = arg_peeled.lower()
                    try:
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("eval_arg: Try to load as variable " + curr_var_attempt + "...")
                        val = context.get(curr_var_attempt)
                        if (val != str(arg)):
                            if got_constant_math: set_cached_value(arg, val)
                            return val

                    except KeyError:
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("eval_arg: Not found as variable")
                        pass

                    arg_peeled = arg_peeled[arg_peeled.index(".") + 1:]

                # Try it as a function
                func_name = arg.lower()
                func_name = func_name[func_name.rindex(".")+1:]
                try:

                    # Lookp and execute the function.
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("eval_arg: Try to run as function '" + func_name + "'...")
                    func = context.get(func_name)
                    r = func
                    from vipermonkey.core import procedures
                    if (isinstance(func, procedures.Function) or
                        isinstance(func, procedures.Sub) or
                        ('fvba_library.' in str(type(func)))):
                        r = eval_arg(func, context, treat_as_var_name=True)
                        
                    # Did the function resolve to a value?
                    if (r != func):

                        # Yes it did. Return the function result.
                        if got_constant_math: set_cached_value(arg, r)
                        return r

                    # The function did to resolve to a value. Return as the
                    # original string.
                    if got_constant_math: set_cached_value(arg, arg)
                    return arg

                except KeyError:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("eval_arg: Not found as function")

                except Exception as e:
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("eval_arg: Failed. Not a function. " + str(e))
                    traceback.print_exc()

                # Are we trying to load some document meta data?
                tmp = arg.lower().strip()
                if (tmp.startswith("activedocument.item(")):

                    # Try to pull the result from the document meta data.
                    prop = tmp.replace("activedocument.item(", "").replace(")", "").replace("'","").strip()

                    # Make sure we read in the metadata.
                    if (meta is None):
                        log.error("BuiltInDocumentProperties: Metadata not read.")
                        return ""
                
                    # See if we can find the metadata attribute.
                    if (not hasattr(meta, prop.lower())):
                        log.error("BuiltInDocumentProperties: Metadata field '" + prop + "' not found.")
                        return ""

                    # We have the attribute. Return it.
                    r = getattr(meta, prop.lower())
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("BuiltInDocumentProperties: return %r -> %r" % (prop, r))
                    return r

                # Are we trying to load some document data?
                if ((tmp.startswith("thisdocument.builtindocumentproperties(")) or
                    (tmp.startswith("activeworkbook.builtindocumentproperties("))):

                    # Try to pull the result from the document data.
                    var = tmp.replace("thisdocument.builtindocumentproperties(", "").replace(")", "").replace("'","").strip()
                    var = var.replace("activeworkbook.builtindocumentproperties(", "")
                    val = context.get_doc_var(var)
                    if (val is not None):
                        return val

                    # Try getting from meta data.
                    val = context.read_metadata_item(var)
                    if (val is not None):
                        return val
                    
                # Are we loading a document variable?
                if (tmp.startswith("activedocument.variables(")):

                    # ActiveDocument.Variables("ER0SNQAWT").Value
                    # Try to pull the result from the document variables.
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("eval_arg: handle expression as doc var lookup '" + tmp + "'")
                    var = tmp.replace("activedocument.variables(", "").\
                          replace(")", "").\
                          replace("'","").\
                          replace('"',"").\
                          replace('.value',"").\
                          replace("(", "").\
                          strip()
                    if (log.getEffectiveLevel() == logging.DEBUG):
                        log.debug("eval_arg: look for '" + var + "' as document variable...")
                    val = context.get_doc_var(var)
                    if (val is not None):
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("eval_arg: got it as document variable.")
                        return val
                    else:
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("eval_arg: did NOT get it as document variable.")

                # Are we loading a custom document property?
                if (tmp.startswith("activedocument.customdocumentproperties(")):

                    # ActiveDocument.CustomDocumentProperties("l3qDvt3B53wxeXu").Value
                    # Try to pull the result from the custom properties.
                    var = tmp.replace("activedocument.customdocumentproperties(", "").\
                          replace(")", "").\
                          replace("'","").\
                          replace('"',"").\
                          replace('.value',"").\
                          replace("(", "").\
                          strip()
                    val = context.get_doc_var(var)
                    if (val is not None):
                        return val
                    
                # As a last resort try reading it as a wildcarded form variable.
                wild_name = tmp[:tmp.index(".")] + "*"
                for i in range(0, 11):
                    tmp_name = wild_name + str(i)
                    try:
                        val = context.get(tmp_name)
                        if (log.getEffectiveLevel() == logging.DEBUG):
                            log.debug("eval_arg: Found '" + tmp + "' as wild card form variable '" + tmp_name + "'")
                        return val
                    except:
                        pass


        # Should this be handled as a variable? Must be a valid var name to do this.
        if (treat_as_var_name and (re.match(r"[a-zA-Z_][\w\d]*", str(arg)) is not None)):

            # We did not resolve the variable. Treat it as unitialized.
            if (log.getEffectiveLevel() == logging.DEBUG):
                log.debug("eval_arg: return 'NULL'")
            return "NULL"

        # Are we referring to a form element that we cannot find?
        if ((str(arg).lower().endswith(".tag")) or
            (str(arg).lower().endswith(".boundvalue")) or
            (str(arg).lower().endswith(".column")) or
            (str(arg).lower().endswith(".caption")) or
            (str(arg).lower().endswith(".groupname")) or
            (str(arg).lower().endswith(".seltext")) or
            (str(arg).lower().endswith(".controltiptext")) or
            (str(arg).lower().endswith(".passwordchar")) or
            (str(arg).lower().endswith(".controlsource")) or
            (str(arg).lower().endswith(".value"))):
            return ""
        
        # The .text hack did not work.
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("eval_arg: return " + str(arg))
        return arg

def eval_args(args, context, treat_as_var_name=False):
    """
    Evaluate a list of arguments if they are VBA_Objects, otherwise return their value as-is.
    Return the list of evaluated arguments.
    """
    try:
        iterator = iter(args)
    except TypeError:
        return args

    # Short circuit check to see if there are any VBA objects.
    got_vba_objects = False
    for arg in args:
        if (isinstance(arg, VBA_Object)):
            got_vba_objects = True
    if (not got_vba_objects):
        return args
    r = list(map(lambda arg: eval_arg(arg, context=context, treat_as_var_name=treat_as_var_name), args))
    return r

def update_array(old_array, index, val):
    """
    Add an item to a Python list.
    """

    # Sanity check.
    if (not isinstance(old_array, list)):
        old_array = []
    
    # Do we need to extend the length of the list to include the indices?
    if (index >= len(old_array)):
        old_array.extend([0] * (index - len(old_array) + 1))
    old_array[index] = val
    return old_array

def coerce_to_int_list(obj):
    """
    Coerce a constant string VBA object to a list of ASCII codes.
    :param obj: VBA object
    :return: list
    """

    # Already have a list?
    if (isinstance(obj, list)):
        return obj
    
    # Make sure we have a string.
    s = coerce_to_string(obj)

    # Convert this to a list of ASCII char codes.
    r = []
    for c in s:
        r.append(ord(c))
    return r

def coerce_to_string(obj):
    """
    Coerce a constant VBA object (integer, Null, etc) to a string.
    :param obj: VBA object
    :return: string
    """

    # in VBA, Null/None is equivalent to an empty string
    if obj in (None, 'NULL', b'NULL'):
        return ''

    # Not NULL. We have data.

    # Easy case. Is this already a string?
    if (isinstance(obj, string_types)):

        # Try to convert unicode to str.
        try:
            return ensure_str(obj)
        except:
            # Conversion failed. Just leave the unicode string as-is and hope for the best.
            pass
            
        return obj
    
    # Do we have a list of byte values? If so convert the bytes to chars.
    if (isinstance(obj, list)):
        r = ""
        bad = False
        for c in obj:

            # Skip null bytes.
            if (c == 0):
                continue
            try:
                r += chr(c)
            except:

                # Invalid character value. Don't do string
                # conversion of array.
                bad = True
                break

        # Return the byte array as a string if it makes sense.
        if (not bad):
            return r

    # Not a character byte array. Punt.
    try:
        return str(obj)
    except:
        return ''

def coerce_args_to_str(args):
    """
    Coerce a list of arguments to strings.
    Return the list of evaluated arguments.
    """
    # TODO: None should be converted to "", not "None"
    return [coerce_to_string(arg) for arg in args]
    # return map(lambda arg: str(arg), args)

def coerce_to_int(obj):
    """
    Coerce a constant VBA object (integer, Null, etc) to a int.
    :param obj: VBA object
    :return: int
    """
    # in VBA, Null/None is equivalent to 0
    if ((obj is None) or (obj == "NULL")):
        return 0

    # Already have int?
    if (isinstance(obj, int)):
        return obj
    
    # Do we have a float string?
    if (isinstance(obj, str)):

        # Do we have a null byte string?
        if (obj.count('\x00') == len(obj)):
            return 0
        
        # No NULLS.
        obj = obj.replace("\x00", "")
        
        # Float string?
        if ("." in obj):
            try:
                obj = float(obj)
                return int(obj)
            except:
                pass
            
        # Hex string?
        hex_pat = r"&h[0-9a-f]+"
        if (re.match(hex_pat, obj.lower()) is not None):
            return int(obj.lower().replace("&h", "0x"), 16)

    # Try regular int.
    return int(obj)

def coerce_to_num(obj):
    """
    Coerce a constant VBA object (integer, Null, etc) to a int or float.
    :param obj: VBA object
    :return: int
    """
    # in VBA, Null/None is equivalent to 0
    if ((obj is None) or (obj == "NULL")):
        return 0

    # Already have float or int?
    if ((isinstance(obj, float)) or (isinstance(obj, int))):
        return obj
    
    # Do we have a string?
    if (isinstance(obj, str)):

        # Stupid "123,456,7890" string where everything after the
        # 1st comma is ignored?
        dumb_pat = r"(?:\d+,)+\d+"
        if (re.match(dumb_pat, obj) is not None):
            obj = obj[:obj.index(",")]
        
        # Float string?
        if ("." in obj):
            try:
                obj = float(obj)
                return obj
            except:
                pass

        # Do we have a null byte string?
        if (obj.count('\x00') == len(obj)):
            return 0

        # Hex string?
        hex_pat = r"&h[0-9a-f]+"
        if (re.match(hex_pat, obj.lower()) is not None):
            return int(obj.lower().replace("&h", "0x"), 16)

    # Try regular int.
    return int(obj)

def coerce_args_to_int(args):
    """
    Coerce a list of arguments to ints.
    Return the list of evaluated arguments.
    """
    return [coerce_to_int(arg) for arg in args]

def coerce_args(orig_args, preferred_type=None):
    """
    Coerce all of the arguments to either str or int based on the most
    common arg type.

    preferred_type = Preferred type to coerce things if possible.
    """

    # Sanity check.
    if (len(orig_args) == 0):
        return orig_args

    # Convert args with None value to 'NULL'.
    args = []
    for arg in orig_args:
        if (arg is None):
            args.append("NULL")
        else:
            args.append(arg)
            
    # Find the 1st type in the arg list.
    first_type = None
    have_other_type = False
    all_null = True
    all_types = set()
    for arg in args:

        # Skip NULL values since they can be int or str based on context.
        if (arg == "NULL"):
            continue
        all_null = False
        if (isinstance(arg, str)):
            all_types.add("str")
            if (first_type is None):
                first_type = "str"
            continue
        elif (isinstance(arg, int)):
            all_types.add("int")
            if (first_type is None):
                first_type = "int"
            continue
        else:
            have_other_type = True
            break

    # If everything is NULL lets treat this as an int.
    if (all_null):
        first_type = "int"
        
    # Leave things alone if we have any non-int or str args.
    if (have_other_type):
        return args

    # Leave things alone if we cannot figure out the type to which to coerce.
    if (first_type is None):
        return args

    # If we have more than 1 possible type and one of these types is the
    # preferred type, use that type.
    if (preferred_type in all_types):
        first_type = preferred_type
    
    # Do conversion based on type of 1st arg in the list.
    if (first_type == "str"):

        # Replace unititialized values.
        new_args = []
        for arg in args:
            if (args == "NULL"):
                new_args.append('')
            else:
                new_args.append(arg)

        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Coerce to str " + str(new_args))
        return coerce_args_to_str(new_args)

    else:

        # Replace unititialized values.
        new_args = []
        for arg in args:
            if (args == "NULL"):
                new_args.append(0)
            else:
                new_args.append(arg)
                
        if (log.getEffectiveLevel() == logging.DEBUG):
            log.debug("Coerce to int " + str(new_args))
        return coerce_args_to_int(new_args)

def int_convert(arg, leave_alone=False):
    """
    Convert a VBA expression to an int, handling VBA NULL.
    """

    # Easy case.
    if (isinstance(arg, int)):
        return arg
    
    # NULLs are 0.
    if (arg == "NULL"):
        return 0

    # Empty strings are NULL.
    if (arg == ""):
        return "NULL"
    
    # Leave the wildcard matching value alone.
    if (arg == "**MATCH ANY**"):
        return arg

    # Convert float to int?
    if (isinstance(arg, float)):
        arg = int(round(arg))

    # Convert hex to int?
    if (isinstance(arg, str) and (arg.strip().lower().startswith("&h"))):
        hex_str = "0x" + arg.strip()[2:]
        try:
            return int(hex_str, 16)
        except:
            log.error("Cannot convert hex '" + str(arg) + "' to int. Defaulting to 0. " + str(e))
            return 0
            
    arg_str = str(arg)
    if ("." in arg_str):
        arg_str = arg_str[:arg_str.index(".")]
    try:
        return int(arg_str)
    except Exception as e:
        if (not leave_alone):
            log.error("Cannot convert '" + str(arg_str) + "' to int. Defaulting to 0. " + str(e))
            return 0
        log.error("Cannot convert '" + str(arg_str) + "' to int. Leaving unchanged. " + str(e))
        return arg_str

def str_convert(arg):
    """
    Convert a VBA expression to an str, handling VBA NULL.
    """
    if (arg == "NULL"):
        return ''
    try:
        return str(arg)
    except Exception as e:
        if (isinstance(arg, text_type)):
            return ''.join(filter(lambda x:x in string.printable, arg))
        log.error("Cannot convert given argument to str. Defaulting to ''. " + str(e))
        return ''

def strip_nonvb_chars(s):
    """
    Strip invalid VB characters from a string.
    """

    # Sanity check.
    if (not isinstance(s, str)):
        return s

    # Strip non-ascii printable characters.
    r = ""
    for c in s:
        if ((ord(c) > 8) and (ord(c) < 127)):
            r += c

    # Strip multiple 'NULL' substrings from the string.
    if (r.count("NULL") > 10):
        r = r.replace("NULL", "")
    return r
