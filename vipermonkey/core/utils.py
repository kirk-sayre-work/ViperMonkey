"""@package vipermonkey.core.utils Utility functions.

"""

# pylint: disable=pointless-string-statement
"""
ViperMonkey - Utility functions.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

Project Repository:
https://github.com/decalage2/ViperMonkey
"""

#=== LICENSE ==================================================================

# ViperMonkey is copyright (c) 2015-2018 Philippe Lagadec (http://www.decalage.info)
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

import re
from core.curses_ascii import isascii, isprint
import base64
import string

import logging

# for logging
try:
    from core.logger import log
except ImportError:
    from logger import log
try:
    from core.logger import CappedFileHandler
except ImportError:
    from logger import CappedFileHandler
from logging import LogRecord
from logging import FileHandler

def _test_char(c):
    if isinstance(c, int):
        c = chr(c)
    return (isprint(c) or (c in "\t\n"))
        
def safe_str_convert(s, strict=False):
    """Convert a string to ASCII without throwing a unicode decode error.

    @param s (any) The thing to convert to a str.

    @param strict (boolean) If True make sure that there are no
    unprintable characters in the given string (if s is a str). If
    False do no modification of a given str.

    @return (str) The given thing as a string.

    """

    # Handle Excel strings.
    if (isinstance(s, dict) and ("value" in s)):
        s = s["value"]
        
    # Do the actual string conversion.
    try:

        # Handle bytes-like objects.
        if isinstance(s, bytes):
            s = s.decode('latin-1')            

        # Strip unprintable characters if needed.
        if (strict and isinstance(s, str)):
            s = ''.join(list(filter(_test_char, s)))

        # Done.
        return str(s)
    
    except (UnicodeDecodeError, UnicodeEncodeError, SystemError):
        if isinstance(s, bytes):
            r = ""
            for c in s:
                curr_char = chr(c)
                if (isprint(curr_char)):
                    r += curr_char
            return r
        return ''.join(list(filter(_test_char, s)))

    except TypeError as e:

        # Weird pyparsing error (see https://github.com/chimpler/pyhocon/issues/220).
        # Punt if this happens rather than crashing.
        log.error("safe_str_convert() failed. " + str(e))
        return ""
    
class Infix(object):
    """Used to define our own infix operators.

    """
    def __init__(self, function):
        self.function = function
    def __ror__(self, other):
        return Infix(lambda x, self=self, other=other: self.function(other, x))
    def __or__(self, other):
        return self.function(other)
    def __rlshift__(self, other):
        return Infix(lambda x, self=self, other=other: self.function(other, x))
    def __rshift__(self, other):
        return self.function(other)
    def __call__(self, value1, value2):
        return self.function(value1, value2)

def wild_not(x, wildcard_val):
    """
    A definition of boolean not that handles ViperMonkey wildcard boolean
    value strings.
    
    @param x (bool or str) The value to negate. Can be the "**MATCH ANY**"
    wildcard string.
    
    @param wildcard_val (bool) The boolean value to use for the "**MATCH ANY**"
    string.
    
    @retval (bool) The negation of the given value.
    """
    
    # Handle wildcard matching.
    wildcards = ["CURRENT_FILE_NAME", "SOME_FILE_NAME", "**MATCH ANY**"]
    if (x in wildcards):
        x = wildcard_val

    # Negate the parameter.
    return (not x)

# Boolean negation that handles ViperMonkey boolean wildcard values.
# pylint: disable=unnecessary-lambda
bool_not=Infix(lambda x,y: wild_not(x, y))

def safe_plus(x,y):
    """Handle "x + y" where x and y could be some combination of ints and
    strs.

    @param x (any) LHS of the addition.
    @param y (any) RHS of the addition.

    @return (str, float, or int) The result of x+y based on the types
    of x and y.

    """

    # Handle Excel Cell objects. Grrr.
    from core import excel
    if excel.is_cell_dict(x):
        x = x["value"]
    if excel.is_cell_dict(y):
        y = y["value"]
    
    # Handle NULLs.
    if (y == "NULL"):
        y = 0
    if (x == "NULL"):

        # Ugh. If x is uninitialized and we are adding a string to it
        # it looks like maybe VB makes this whole thing a string?
        if isinstance(y, str):
            x = ""
        else:
            x = 0

    # Loosely typed languages are terrible. 1 + "3" == 4 while "1" + 3
    # = "13". The type of the 1st argument drives the dynamic type
    # casting (I think) minus variable type information (Dim a as
    # String: a = 1 + "3" gets "13", we're ignoring that here). Pure
    # garbage.
    from core import vba_conversion
    if (isinstance(x, str) and (not isinstance(y, str))):
        y = vba_conversion.str_convert(y)
    if (isinstance(x, int) and (not isinstance(y, int))):
        y = vba_conversion.int_convert(y)

    # Easy case first.
    if (isinstance(x, (float, int)) and
        isinstance(y, (float, int))):
        return x + y
        
    # Fix data types.
    if (isinstance(y, str)):

        # NULL string in VB.
        if (x == 0):
            x = ""

        # String concat.
        return str(x) + y

    if (isinstance(x, str)):

        # NULL string in VB.
        if (y == 0):
            y = ""

        # String concat.
        return x + str(y)

    # Punt. We are not doing pure numeric addition and
    # we have already handled string concatentaion. Just
    # convert things to strings and hope for the best.
    return str(x) + str(y)


# Safe plus infix operator. Ugh.
# pylint: disable=unnecessary-lambda
plus=Infix(lambda x,y: safe_plus(x, y))

def safe_equals(x,y):
    """Handle "x = y" where x and y could be some combination of ints and
    strs.

    @param x (any) LHS of the equality check.
    @param y (any) RHS of the equality check.

    @return (boolean) The result of the equality check, taking into
    account the implicit type conversions VB performs to "help" the
    programmer.

    """

    # Handle NULLs.
    if (x == "NULL"):
        x = 0
    if (y == "NULL"):
        y = 0

    # Handle equality checks on a wildcarded file name. The
    # current file name is never going to be equal to "".
    if (((x == "CURRENT_FILE_NAME") and (y == "")) or
        ((y == "CURRENT_FILE_NAME") and (x == "")) or
        ((x == "SOME_FILE_NAME") and (y == "")) or
        ((y == "SOME_FILE_NAME") and (x == ""))):
        return False
        
    # Handle wildcard matching.
    wildcards = ["CURRENT_FILE_NAME", "SOME_FILE_NAME", "**MATCH ANY**"]
    if ((x in wildcards) or (y in wildcards)):
        return True
        
    # Easy case first.
    # pylint: disable=unidiomatic-typecheck
    if (type(x) == type(y)):
        return x == y

    # Booleans and ints can be directly compared.
    if ((isinstance(x, bool) and (isinstance(y, int))) or
        (isinstance(y, bool) and (isinstance(x, int)))):
        return x == y
        
    # Punt. Just convert things to strings and hope for the best.
    return str(x) == str(y)


# Safe equals and not equals infix operators. Ugh. Loosely typed languages are terrible.
# pylint: disable=unnecessary-lambda
eq=Infix(lambda x,y: safe_equals(x, y))
neq=Infix(lambda x,y: (not safe_equals(x, y)))

def safe_gt(x,y):
    """Handle "x > y" where x and y could be some combination of ints and
    strs.

    @param x (any) LHS of the check.
    @param y (any) RHS of the check.

    @return (boolean) The result of the greater than check, taking into
    account the implicit type conversions VB performs to "help" the
    programmer.

    """

    # Handle NULLs.
    if (x == "NULL"):
        x = 0
    if (y == "NULL"):
        y = 0
        
    # Handle wildcard matching.
    wildcards = ["CURRENT_FILE_NAME", "SOME_FILE_NAME", "**MATCH ANY**"]
    if ((x in wildcards) or (y in wildcards)):
        return True
        
    # Since we are doing > both values should be numbers.
    try:
        from core.vba_conversion import coerce_to_num
        x = coerce_to_num(x)
        y = coerce_to_num(y)
    except ValueError:

        # One of them can't be converted to a number. Convert both to strings
        # and hope for the best.
        x = safe_str_convert(x)
        y = safe_str_convert(y)

    # Return the numeric comparison.
    return (x > y)

# Safe > and < infix operators. Ugh. Loosely typed languages are terrible.
# pylint: disable=unnecessary-lambda
gt=Infix(lambda x,y: safe_gt(x, y))
lt=Infix(lambda x,y: (not safe_gt(x, y)) and (not safe_equals(x,y)))
gte=Infix(lambda x,y: (safe_gt(x, y) or safe_equals(x,y)))
lte=Infix(lambda x,y: (not safe_gt(x, y) or safe_equals(x,y)))

def safe_print(text):
    """Sometimes printing large strings when running in a Docker
    container triggers exceptions.  This function just wraps a print
    in a try/except block to not crash ViperMonkey when this happens.

    @param text (any) The thing to print.

    """
    text = safe_str_convert(text)
    try:
        print(text)
    except Exception as e:
        msg = "ERROR: Printing text failed (len text = " + str(len(text)) + ". " + str(e)
        if (len(msg) > 100):
            msg = msg[:100]
        try:
            print(msg)
        except Exception:
            pass

    # if our logger has a FileHandler, we need to tee this print to a file as well
    for handler in log.handlers:
        if isinstance(handler, (FileHandler, CappedFileHandler)):
            # set the format to be like a print, not a log, then set it back
            handler.setFormatter(logging.Formatter("%(message)s"))
            handler.emit(LogRecord(log.name, logging.INFO, "", None, text, None, None, "safe_print"))
            handler.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))

def fix_python_overlap(var_name):
    """Eliminate collisions between VB variable/function names and Python
    builtin names.

    @param var_name (str) The VB variable/functio name.
    
    @return (str) The variable/function name (possibly) modified so
    that it does not collide with any Python builtin names.

    """
    builtins = set(["str", "list", "bytes", "pass"])
    if (var_name.lower() in builtins):
        var_name = "MAKE_UNIQUE_" + var_name
    var_name = var_name.replace("$", "__DOLLAR__")
    # RegExp object?
    if ((not var_name.endswith(".Pattern")) and
        (not var_name.endswith(".Global"))):
        var_name = var_name.replace(".", "")
    return var_name

def b64_encode(value):
    """Base64 encode a string.

    @param value (str) The string to encode.

    @return (str) On success return the base64 encoded string, on
    error return None.

    """
    try:
        r = safe_str_convert(base64.b64encode(safe_str_convert(value).encode("latin-1")))
        return r
    except Exception as e:
        return None

def b64_decode(value):
    """Base64 decode a string.

    @param value (str) The string to decode.

    @return (str) On success return the base64 decode results, on
    error return None.

    """

    try:
        # Make sure this is a potentially valid base64 string
        tmp_str = safe_str_convert(value).replace(" ", "").replace("\x00", "")
        b64_pat = r"^[A-Za-z0-9+/=]+$"
        if (re.match(b64_pat, tmp_str) is not None):
            
            # Pad out the b64 string if needed.
            missing_padding = len(tmp_str) % 4
            if missing_padding:
                tmp_str += b'='* (4 - missing_padding)
        
            # Return the decoded value.
            conv_val = base64.b64decode(tmp_str)
            return safe_str_convert(conv_val)
    
    # Base64 conversion error.
    except Exception:
        pass

    # No valid base64 decode.
    return None

class vb_RegExp(object):
    """Class to simulate a VBS RegEx object in python.

    """

    def __init__(self):
        self.Pattern = None
        self.Global = False
        self.match_any = ["SOME_FILE_NAME", "**MATCH ANY**"]

    def __repr__(self):
        return "<RegExp Object: Pattern = '" + str(self.Pattern) + "', Global = " + str(self.Global) + ">"
        
    def _get_python_pattern(self):
        pat = self.Pattern
        if (pat is None):
            return None
        if (pat.strip() != "."):
            pat1 = pat.replace("$", "\\$").replace("-", "\\-")
            fix_dash_pat = r"(\[.\w+)\\\-(\w+\])"
            pat1 = re.sub(fix_dash_pat, r"\1-\2", pat1)
            fix_dash_pat1 = r"\((\w+)\\\-(\w+)\)"
            pat1 = re.sub(fix_dash_pat1, r"[\1-\2]", pat1)
            pat = pat1
        return pat
        
    def Test(self, string):
        """Emulation of the VB Regex object Test() method.

        @param string (str) The string to test against the already set
        regex pattern.

        @return (boolean) True if the pattern matches, False if not.

        """
        pat = self._get_python_pattern()
        #print "PAT: '" + pat + "'"
        #print "STR: '" + string + "'"
        #print re.findall(pat, string)
        if (pat is None):
            return False
        if (string in self.match_any):
            return True
        return (re.match(pat, string) is not None)

    def Execute(self, string):
        """Emulation of the VB Regex object Execute() method.

        @param string (str) The string to test against the already set
        regex pattern.

        @return (list) List of dicts mimicing a VB Match object.

        """
        pat = self._get_python_pattern()
        #print "PAT: '" + pat + "'"
        #print "STR: '" + string + "'"
        #print re.findall(pat, string)
        if (pat is None):
            return []
        if (string in self.match_any):
            return [
                {
                    "FirstIndex" : 12,
                    "Value" : "FAKE MATCH 1"
                }
            ]
        strs = re.findall(pat, string)
        r = []
        fake_pos = 3
        for s in strs:
            r.append({
                "FirstIndex" : fake_pos,
                "Value" : s
            })
            fake_pos += 5
        return r
    
    def Replace(self, string, rep):
        """Emulation of the VB Regex object Replace() method. The already set
        regex pattern is used.

        @param string (str) The string in which to replace substrings.

        @param rep (str) The replacement value.

        @return (boolean) True if the pattern matches, False if not.

        """
        pat = self._get_python_pattern()
        if (pat is None):
            return string
        rep = re.sub(r"\$(\d)", r"\\\1", rep)
        r = string
        try:
            r = re.sub(pat, rep, string)
        except Exception:
            pass
        return r

def get_num_bytes(i):
    """Get the minimum number of bytes needed to represent a given int
    value.

    @param i (int) The integer to check.

    @return (int) The number of bytes needed to represent the given
    int.

    """
    
    # 1 byte?
    if ((i & 0x00000000FF) == i):
        return 1
    # 2 bytes?
    if ((i & 0x000000FFFF) == i):
        return 2
    # 4 bytes?
    if ((i & 0x00FFFFFFFF) == i):
        return 4
    # Lets go with 8 bytes.
    return 8

def strip_nonvb_chars(s):
    """Strip invalid VB characters from a string.

    @param s (str) The string from which to strip invalid characters.
    
    @return (str) The cleaned up string.

    """
    
    # Handle unicode strings.
    s = safe_str_convert(s)

    # Do we need to do this?
    if (re.search(r"[^\x09-\x7e]", s) is None):
        return s

    # Patch for some string values.
    s = s.replace(chr(0x90), "u")
    
    # Strip non-ascii printable characters.
    r = re.sub(r"[^\x09-\x7e]", "", s)
    
    # Strip multiple 'NULL' substrings from the string.
    if (r.count("NULL") > 10):
        r = r.replace("NULL", "")
    return r

cached_ascii = {}
def isascii(s):
    """Check if the characters in string s are in ASCII, U+0-U+7F.
    Taken from https://stackoverflow.com/questions/196345/how-to-check-if-a-string-in-python-is-in-ascii

    @param s (str) String to check.

    @return (boolean) True if all ASCII, False if not.
    """

    # The encode() operation is expensive, so cache the values of this
    # function.
    hsh = None
    if (len(s) > 1000):
        import os
        old_val = "0"
        # Set PYTHONHASHSEED to not salt the hash.
        if ("PYTHONHASHSEED" in os.environ):
            old_val = os.environ["PYTHONHASHSEED"]
        os.environ["PYTHONHASHSEED"] = "0"
        hsh = hash(s)
        os.environ["PYTHONHASHSEED"] = old_val
        if (hsh in cached_ascii):
            return cached_ascii[hsh]

    # Actually do the ASCII check.
    r = len(s) == len(s.encode())
    if (hsh is not None):
        cached_ascii[hsh] = r
    return r

def _rewrite_non_printable_chars(s):

    # Got any non-printable characters?
    if (re.search(r"[\x7f-\xff]", s) is None):
        return '"' + s + '"'

    # Got non-prinatble chars. Rewrite them.
    r = ""
    in_literal = False
    have_prev = False
    for c in s:

        # Non-extended ASCII?
        if (ord(c) <= 126):

            # Already in a printable literal chunk?
            if not in_literal:

                # Start a literal chunk.
                in_literal = True
                if have_prev:
                    r += " & "
                r += '"'
            have_prev = True
            r += c
            continue

        # Extended ASCII. Use an explicit VB Chr() call to make sure
        # we don't lose the character when processing.
        chr_expr = "Chr(&H" + hex(ord(c)).replace("0x", "") + ")"

        # If we are in a literal chunk we will need to close it out.
        if in_literal:
            r += '"'
            have_prev = True
        in_literal = False

        # If we have a previous expression we will need to add in the
        # chr() call.
        if have_prev:
            r += " & "
        have_prev = True
        r += chr_expr

    # Finish up by closing out a literal chunk if needed.
    if in_literal:
        r += '"'

    # Done.
    return r

def _delete_comments(s):
    """Delete all of the full line comments from the given VB code.

    @param s (str) The code.

    @return (str) The code with comments deleted.

    """
    r = s
    changed = True
    while changed:
        old_r = r
        if isinstance(s, bytes):
            pat = br"(?:^|(?:\r?\n)) *'[^\n]{10,}\n"
            r = re.sub(pat, b"\n", r)
        elif isinstance(s, str):
            pat = r"\r?\n\s*'[^\n]{10,}\n"
            r = re.sub(pat, "\n", r)
        changed = (len(r) < len(old_r))
    return r
    
hide_string_map = {}
def _hide_strings(s):

    # Got cached value? This operation could be compute intensive so we
    # cache the results.
    if (s in hide_string_map):
        return hide_string_map[s]
    
    # Only do this on VBS.
    import core.filetype as filetype
    if (filetype.is_office_file(s, True) or
        ("</script>" in safe_str_convert(s))):
        hide_string_map[s] = (s, {})
        return (s, {})

    # Could be a lot of comments that bog things down. Delete the
    # comments.
    s = _delete_comments(s)
    
    s = safe_str_convert(s)
    in_str_double = False
    in_comment = False
    curr_str = None
    all_strs = {}
    counter = 1000000
    r = ""
    escaped = False
    i = -1
    #print("pos\tcurr\tnext\tdbl\tesc\tcomm")
    while (i < (len(s) - 1)):

        # Can we jump to the end of a string?
        i += 1
        if (in_str_double and ('"' in s[i:])):
            next_i = i + s[i:].index('"')
            curr_str += s[i:next_i]
            i = next_i
                    
        # Start/end VB comment?
        curr_char = s[i]
        next_char = ""
        if ((i + 1) < len(s)):
            next_char = s[i + 1]
        if (not in_str_double):

            # Start?
            if (curr_char == "'"):
                in_comment = True

            # End?
            if (curr_char == "\n"):
                in_comment = False
        
        # Start/end double quoted string?
        #print(str(i) + "\t" + curr_char + "\t" + next_char + "\t" + str(in_str_double) + "\t" + str(escaped) + "\t" + str(in_comment))
        if ((curr_char == '"') and (next_char != '"') and (not escaped) and (not in_comment)):
            
            # Switch being in/out of string.
            in_str_double = not in_str_double
            
            # Finished up a string we were tracking?
            if (not in_str_double):
                str_name = "HIDE_" + str(counter)
                counter += 1
                # Ugh, Non-printable ASCII chars in string literals
                # are awful to deal with. Change those out to explicit
                # chr() calls so we can actually analyze the sample.
                curr_str = _rewrite_non_printable_chars(curr_str[1:])
                #if curr_str.startswith('"'):
                #    curr_str = curr_str[1:]
                #if curr_str.endswith('"'):
                #    curr_str = curr_str[:-1]                    
                all_strs[str_name] = curr_str
                r += '"' + str_name
            else:
                curr_str = ""

        # Track whether the current " is escaped.
        escaped = (not escaped) and (curr_char == '"') and (next_char == '"')
                
        # Save the current character if we are tracking a string.
        if in_str_double:
            curr_str += curr_char
        else:

            # Not in a string. Just save the original character in the
            # result string.
            r += curr_char
        skip = False

    # Done.
    #print(all_strs)
    #print(r)
    #import sys
    #sys.exit(0)
    hide_string_map[s] = (r, all_strs)
    return (r, all_strs)

def _unhide_strings(s, str_map):
    s = safe_str_convert(s)
    r = s
    for str_name in str_map:
        r = r.replace('"' + str_name + '"', str_map[str_name])
    return r
