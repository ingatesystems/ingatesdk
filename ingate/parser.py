import re


class ParseError(Exception):
    pass


class UnexpectedInput(ParseError):
    pass


class UnexpectedEndOfLine(UnexpectedInput):
    pass


class UnexpectedFunction(UnexpectedInput):
    pass


class InputEnded(ParseError):
    pass


class ContinuationNeeded(Exception):

    def __init__(self, unfinished_token_start, data_end):
        Exception.__init__(self, unfinished_token_start, data_end)
        self.unfinished_token_start = unfinished_token_start
        self.data_end = data_end


class EndInsideQuotedString(ContinuationNeeded):
    pass


class Parser(object):

    """Class to parse a command line.

       To use, instantiate with the command line as single parameter, then
       call the do_parse() method.  The command line must be a unicode string.
       do_parse() will raise ParseError, or a sub-exception thereof, on
       error.  On success, nothing of interest will be returned, but the
       Parser instance will be updated with information about the parsed
       command.

       Important methods:
         - do_parse()	Perform parse on the command line.
         - command()	Returns the command part from the command line.
         - flags()	Returns the flags from the command line.
         - parameters()	Returns the parameter parts from the command line.
         - assignments()
                        Returns the assignments from the command line.
         - point()	Returns the current parsing position.
    """

    __h_whitespace_chars = " \t"
    __whitespace_chars = "\n" + __h_whitespace_chars
    __alpha_charclass = "a-zA-Z"
    __alphanumeric_charclass = __alpha_charclass + "0-9"
    __bareword_charclass_nodash = __alphanumeric_charclass + ".:_@/*"
    __bareword_charclass = __bareword_charclass_nodash + r"\-"
    __re_h_whitespace = re.compile("[" + __h_whitespace_chars + "]+")
    __re_no_h_whitespace = re.compile("[^" + __h_whitespace_chars + "]+")

    def __init__(self, commandline):
        self.__data = commandline
        self.__i = None
        self.__command = None
        self.__flags = set()
        self.__parameters = []
        self.__assignments = {}

    def command(self):
        return self.__command

    def flags(self):
        return self.__flags

    def parameters(self):
        return self.__parameters

    def assignments(self):
        return self.__assignments

    def point(self):
        return self.__i

    def unparsed_data(self):
        return self.__data[self.__i:]

    def set_command(self, command):
        if self.__command is not None:
            raise RuntimeError("Command already set", self.__command)
        if not command:
            raise ValueError("Bad command", command)
        self.__command = command

    def add_flag(self, flag):
        if flag in self.__flags:
            raise RuntimeError("Flag already set", flag)
            return
        self.__flags.add(flag)

    def add_parameter(self, parameter):
        self.__parameters.append(parameter)

    def add_assignment(self, name, value):
        if name in self.__assignments:
            raise RuntimeError("Assignment already set", name)
            return
        self.__assignments[name] = value

    # An odd number of backslashes, possibly followed by newline, at the
    # end of the input.
    __re_continuation = re.compile(r"(\A|[^\\])(\\\\)*(?P<cont>\\" "\n?)\\Z")

    def do_parse(self):
        if self.__i is not None:
            raise RuntimeError("do_parse() already called on this instance")
        self.__i = 0
        cont = self.__re_continuation.search(self.__data)
        if cont:
            raise ContinuationNeeded(cont.start('cont'), cont.start('cont'))
        self.skip_optws_or_comment()
        if self.at_eol():
            self.__i = len(self.__data)
            return
        self.parse_command()
        self.parse_flags()
        self.parse_parameters()
        self.parse_assignments()
        self.parse_eol()

    def at_eol(self, data=None, i=None):
        if data is None:
            data = self.__data
        if i is None:
            i = self.__i
        if i >= len(data) or data[i] == "\n":
            return True
        return False

    def at_word_end(self, data=None, i=None):
        if data is None:
            data = self.__data
        if i is None:
            i = self.__i
        if (i >= len(data) or data[i] in self.__whitespace_chars
                or self.looking_at(self.__re_comment, data, i)):
            return True
        return False

    def looking_at(self, pattern, data=None, i=None):
        """Check if remaining data matches given pattern.
           Point is untouched, regardless of if the match succeeds or not.

           Parameter 'pattern' is either a string or a regular expression
           object; if it is a string, the match is made against that exact
           string, without any wildcards or anything.

           Returns the matched data if the match is successful, False if not.
        """
        if data is None:
            data = self.__data
        if i is None:
            i = self.__i
        if hasattr(pattern, 'match'):
            m = pattern.match(data, i)
            if m:
                return m.group()
            return False
        else:
            if data.startswith(pattern, i):
                return pattern
            return False

    def eat(self, pattern):
        """Match remaining data against regexp object or constant string.
           Sets current position to just after the matched data.
           Returns the matched data on success, or False on failure.
        """
        match = self.looking_at(pattern)
        if match is not False:
            self.__i += len(match)
        return match

    def consume(self, pattern, name=None, postcondition=None):
        """Match remaining data against regexp object or constant string.
           Sets current position to just after the matched data.

           Returns the matched data on successful match.
           If data didn't match, one of the following exceptions are raised:
             - InputEnded
             - UnexpectedEndOfLine
             - UnexpectedInput

           Parameters:
             - pattern	Pattern to match against; either a string or a regular
                        expression object.  If it is a string, matches against
                        exactly that string (no wildcards or anything).
             - name	A name describing what is wanted.  This is passed into
                        the exception raised when the match fails, so the
                        catcher can say "expected flag, found ``4711''".
             - postcondition
                        If set, a callable that is called after a successful
                        match.  If it returns a false value, an UnexpectedInput
                        exception is raised, and the current pointer is
                        restored to its original position.
                           The postcondition callable is called with the
                        complete data input and the position after the match
                        as parameters.  self.__i has been updated to point
                        to after the match.
        """

        start_i = self.__i
        matched_data = self.eat(pattern)
        if matched_data is False:
            if start_i == len(self.__data):
                raise InputEnded(start_i, name)
            elif self.at_eol():
                raise UnexpectedEndOfLine(start_i, name)
            else:
                raise UnexpectedInput(start_i, name)
        if postcondition and not postcondition(self.__data, self.__i):
            self.__i = start_i
            raise UnexpectedInput(start_i, name)
        return matched_data

    def skip_mandatory_whitespace(self):
        self.consume(self.__re_h_whitespace)

    def skip_opt_whitespace(self):
        m = self.__re_no_h_whitespace.search(self.__data, self.__i)
        if m:
            self.__i = m.start()

    __re_comment = re.compile(
        "#.*\n?"
        "|"
        "\\{[ " + __h_whitespace_chars + __bareword_charclass + "]*\\}")

    def skip_optws_or_comment(self):
        re_ws = self.__re_h_whitespace
        re_comm = self.__re_comment
        while self.eat(re_ws) or self.eat(re_comm):
            continue

    __re_command = re.compile("[a-z\\-]+")

    def parse_command(self):
        self.skip_optws_or_comment()
        cmd = self.consume(self.__re_command, "command", self.at_word_end)
        self.set_command(cmd)
        self.skip_optws_or_comment()

    __re_flag = re.compile("--[0-9a-zA-Z][0-9a-zA-Z\\-]*")

    def parse_flags(self):
        while self.looking_at("--"):
            flag = self.consume(self.__re_flag, "flag", self.at_word_end)
            self.add_flag(flag)
            self.skip_optws_or_comment()

    __re_bareword = re.compile(
        "("
        + ("[" + __bareword_charclass_nodash + "]"
            "[" + __bareword_charclass + "]*")
        + "|"
        + ("-"
            "[" + __bareword_charclass_nodash + "]"
            "[" + __bareword_charclass + "]*")
        + "|"
        + "[" + __bareword_charclass + "]"
        + ")"
        + "(?=[^" + __bareword_charclass + "]|\\Z)"
    )

    def parse_parameters(self):
        while not self.at_eol():
            current_pos = self.__i
            try:
                param = self.consume(self.__re_bareword, "parameter",
                                     self.at_word_end)
            except UnexpectedInput as ue:
                break
            self.skip_optws_or_comment()
            if not self.at_eol() and not self.looking_at(self.__re_bareword):
                self.__i = current_pos
                break
            self.add_parameter(param)

    __re_backslash_seq_identifier = re.compile(r"\\.", re.DOTALL)
    __re_8bit_unicode = re.compile(r"[0-9a-fA-F]{2}")
    __re_16bit_unicode = re.compile(r"[0-9a-fA-F]{4}")
    __re_31bit_unicode = re.compile(r"[0-9a-fA-F]{8}")

    def read_backslash_sequence(self):
        start_i = self.__i
        try:
            bsintro = self.consume(self.__re_backslash_seq_identifier,
                                   "backslash sequence")
            if bsintro == "\\\\":
                return "\\"
            elif bsintro == '\\"':
                return '"'
            elif bsintro == "\\n":
                return "\n"
            elif bsintro == "\\x":
                hexcode = self.consume(self.__re_8bit_unicode,
                                       "2 digit hexadecimal character code")
                return unichr(int(hexcode, 16))
            elif bsintro == "\\u":
                hexcode = self.consume(self.__re_16bit_unicode,
                                       "4 digit hexadecimal character code")
                return unichr(int(hexcode, 16))
            elif bsintro == "\\U":
                hexcode = self.consume(self.__re_31bit_unicode,
                                       "8 digit hexadecimal character code")
                codepoint = int(hexcode, 16)
                if codepoint >= 0x110000:
                    raise ParseError(start_i,
                                     "unicode code-point must be <= 0010ffff")
                return unichr(codepoint)
            elif bsintro == "\\\n":
                return ""
            raise UnexpectedInput(self.__i, "valid backslash sequence")
        except UnexpectedInput as ue:
            self.__i = start_i
            raise

    __re_qstring_nonspecials = re.compile('[^"\n\\\\]*')

    def read_quoted_string(self, postcondition=None):
        start_i = self.__i
        data = self.__data
        qstring = ""
        try:
            self.consume('"', "quoted assignment value")
            while True:
                qstring += self.consume(self.__re_qstring_nonspecials)
                if self.__i >= len(data):
                    raise EndInsideQuotedString(start_i, len(data))
                nextchar = data[self.__i]
                if nextchar == '"':
                    self.consume('"', postcondition=postcondition)
                    break
                elif nextchar == "\n":
                    qstring += self.consume("\n")
                    continue
                elif nextchar == "\\":
                    qstring += self.read_backslash_sequence()
                    continue
                continue
        except (ParseError, ContinuationNeeded) as e:
            self.__i = start_i
            raise
        return qstring

    __re_assignment_target = re.compile(
        "[" + __bareword_charclass_nodash + "]"
        "[" + __bareword_charclass + "]*"
        "(?=[^" + __bareword_charclass + "]|\\Z)"
    )

    __re_function_name = re.compile(
        "("
        "[" + __alpha_charclass + "]"
        "[" + __alphanumeric_charclass + "]*"
        ")"
    )

    def dummy_encrypt(value):
        return value

    known_functions = {
        'hash': dummy_encrypt,
    }

    def read_value(self, postcondition=None):
        try:
            value = self.consume(self.__re_bareword,
                                 "assignment value",
                                 postcondition)
        except UnexpectedInput as ue:
            value = self.read_quoted_string(postcondition)
        return value

    def read_function_call(self):
        start_i = self.__i
        try:
            funcname = self.consume(self.__re_function_name, "function name")
            self.skip_optws_or_comment()
            try:
                self.consume("(")
            except InputEnded:
                raise UnexpectedInput(self.__i, None)
        except UnexpectedInput as ue:
            self.__i = start_i
            raise
        start_i = self.__i
        try:
            self.skip_optws_or_comment()
            param = self.read_value()
            self.skip_optws_or_comment()
            self.consume(")", "closing parenthesis")
        except UnexpectedInput as ue:
            self.__i = start_i
            raise ParseError(*ue.args)
        function = self.known_functions.get(funcname)
        if function is None:
            raise UnexpectedFunction(start_i, "valid value function")
        value = function(param)
        return value

    def read_assignment(self):
        start_i = self.__i
        try:
            name = self.consume(self.__re_assignment_target,
                                "assignment target")
            self.skip_optws_or_comment()
            self.consume("=", "equal sign")
            self.skip_optws_or_comment()
            value_i = self.__i
            try:
                value = self.read_function_call()
            except UnexpectedFunction:
                raise
            except UnexpectedInput as ue:
                value = self.read_value(self.at_word_end)
            self.skip_optws_or_comment()
        except (UnexpectedInput, ContinuationNeeded) as e:
            self.__i = start_i
            raise
        return (name, value)

    def parse_assignments(self):
        while not self.at_eol():
            name, value = self.read_assignment()
            self.add_assignment(name, value)

    __re_opt_eol = re.compile("\n*")

    def parse_eol(self):
        self.skip_optws_or_comment()
        self.consume(self.__re_opt_eol)

    # This class method is used by commands that want to format database
    # values into assignment values that this parser understands.  Even
    # though it is not used for parsing, it belongs here because it knows
    # what assignment values should look like to be palatable to the
    # parser.
    #
    # Note that this method returns a unicode string.  Thus it must be
    # encoded with the terminal codec when printed.
    def quote_value(cls, value, encoding=None, quote_newlines=True):
        if not isinstance(value, unicode):
            raise TypeError("data value must be unicode")
        m = cls.__re_bareword.match(value)
        if m and m.group() == value:
            return value

        value = value.replace(u"\\", u"\\\\")
        if quote_newlines:
            value = value.replace(u"\n", u"\\n")
        value = value.replace(u'"', u'\\"')
        if encoding is not None:
            value = value.encode(encoding, 'backslashreplace')
            value = value.decode(encoding)
        return u'"' + value + u'"'

    quote_value = classmethod(quote_value)
