import re

from mod_python import apache

# Enum for auth status
REQ_NO_ID        = 0
REQ_NO_AUTH      = 1
REQ_INCOMPLETE   = 2
REQ_AUTH_FAILED  = 3
REQ_AUTH_SUCCESS = 4

# Enum for access denied/granted
COMPLETE_ACC_DENIED  = 0
COMPLETE_ACC_GRANTED = 1

class HTTPAuthHeader:
    """Is used for parsing WWW-Authenticate and Authorization HTTP headers."""
    def __init__(self, header_field):
        # Find the descriptions
        self.type = header_field[0:header_field.index(' ')].strip()
        self.params = {}
        params = header_field[header_field.index(' '):].strip()
        
        # And then the params.
        quoted = False
        cur_param = ''
        cur_value = None
        for ch in range(0, len(params)):
            # Iterate through the params string, cutting out param names, then
            # the param values.
            if quoted:
                # Ignore EVERYTHING, until we're unquoted.
                # Don't forget to unescape...
                if params[ch] == "\\":
                    ch += 1
                    if ch < len(params):
                        cur_value += params[ch]
                if params[ch] == '"':
                    quoted = False
                else:
                    cur_value += params[ch]
            else:
                if cur_value == None:
                    # Ignore quotes if we haven't gotten to reading the value
                    # yet. They shouldn't be in the param name, but we're
                    # tolerant of stupidity.
                    if params[ch] == '=':
                        cur_value = ''
                    # And if we find a comma...  Well the server is still
                    # messed up so we just mark the param as EXISTING, with no
                    # value.
                    elif params[ch] == ',':
                        cur_param = cur_param.strip()
                        if not header.params.has_key(cur_param):
                            self.params[cur_param] = []
                        self.params[cur_param].append(None)
                        cur_param = ''
                    else:
                        cur_param += params[ch]
                else:
                    # Trying to read the current value.  We're a bit tolerant,
                    # and let the value enter and exit quotes repeatedly.  We
                    # just strip the bounding quotes.
                    if params[ch] == '"':
                        quoted = True
                    elif params[ch] == ',':
                        cur_param = cur_param.strip()
                        cur_value = cur_value.strip()
                        if not self.params.has_key(cur_param):
                            self.params[cur_param] = []
                        self.params[cur_param].append(cur_value)
                        cur_param = ''
                        cur_value = None
                    else:
                        cur_value += params[ch]
    
        # Don't forget to save that last param/value pair!
        cur_param = cur_param.strip()
        if cur_value != None:
            cur_value = cur_value.strip()
        if not self.params.has_key(cur_param):
            self.params[cur_param] = []
        self.params[cur_param].append(cur_value)

class Client:
    """Is used to hold credentials and identity of the client."""
    def __init__(self):
        self.document = None

def file_not_found(req, relative_uri):
    'Returns an HTTP error when no file is found locally.'
    
    # TODO: Kludgy way of doing this.  Can we do it inside Apache?
    # Write the headers, then return 404.
    req.content_type = 'text/html'
    req.status = apache.HTTP_NOT_FOUND
    req.send_http_header()
    req.write("""<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML><HEAD>
<TITLE>404 Not Found</TITLE>
</HEAD><BODY>
<H1>Not Found</H1>
The requested URL """ + relative_uri + """ was not found on this server.<P>
<HR>
""" + req.subprocess_env['SERVER_SIGNATURE'] + """
</BODY></HTML>""")

def q(str):
    'Escapes a string for use in quoted HTTP headers.'
    return re.sub(r'(["\\])', r'\\\1', str)

def request_authentication(req, auth_header):
    'Requests authentication from the client by way of a 401 error.'
    
    # TODO: Not so kludgy.  Perhaps redirect with directives?
    # Write the headers, then return 401.
    req.content_type = 'text/html'
    # TODO: Relative URI?
    req.headers_out['WWW-Authenticate'] = str(auth_header)
    req.status = apache.HTTP_UNAUTHORIZED
    req.send_http_header()
    req.write("""<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML><HEAD>
<TITLE>401 Authorization Required</TITLE>
</HEAD><BODY>
<H1>Authorization Required</H1>
This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.<P>
<HR>
""")
    req.write(req.subprocess_env['SERVER_SIGNATURE'])
    req.write('</BODY></HTML>')

