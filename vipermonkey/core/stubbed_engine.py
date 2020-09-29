"""
ViperMonkey: VBA Library

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

__version__ = '0.02'

# sudo pypy -m pip install unidecode
import unidecode
import string
from six import binary_type, ensure_str

import logging
from vipermonkey.core.logger import log

class StubbedEngine(object):
    """
    Stubbed out Vipermonkey analysis engine that just supports tracking
    actions.
    """

    def __init__(self):
        self.actions = []

    def report_action(self, action, params=None, description=None):
        """
        Callback function for each evaluated statement to report macro actions
        """

        # store the action for later use:
        try:
            if (isinstance(action, binary_type)):
                action = unidecode.unidecode(action.decode('unicode-escape'))
        except UnicodeDecodeError:
            action = ''.join(filter(lambda x:x in string.printable, action))
        if (isinstance(params, binary_type)):
            try:
                decoded = params.replace(b"\\", b"#ESCAPED_SLASH#").decode('unicode-escape').replace("#ESCAPED_SLASH#", "\\")
                params = unidecode.unidecode(decoded)
            except Exception as e:
                log.warn("Unicode decode of action params failed. " + str(e))
                params = ''.join(filter(lambda x:x in string.printable, params))
        try:
            if (isinstance(description, binary_type)):
                description = unidecode.unidecode(description.decode('unicode-escape'))
        except UnicodeDecodeError as e:
            log.warn("Unicode decode of action description failed. " + str(e))
            description = ''.join(filter(lambda x:x in string.printable, description))
        self.actions.append((action, params, description))
        log.info("ACTION: %s - params %r - %s" % (action, params, description))
