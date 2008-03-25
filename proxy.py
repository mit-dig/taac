"""This script acts as a filter to all requests for files within this
directory.  If a file is associated with a policy in policies.n3, it will
send a 401 error asking for AIR-based authentication.

This gateway requires mod_python with python 2.4 or greater and python-openid
to operate."""

# Internal imports...
import os
import os.path
import re

import sys
import traceback

# Library imports...
from mod_python import apache, util
from openid.consumer.consumer import Consumer, SUCCESS
from openid.store.filestore import FileOpenIDStore

# And tmswap imports...
from tmswap import llyn
from tmswap import myStore
from tmswap.RDFSink import SUBJ, OBJ
from tmswap import uripath

# Some globals...  You shouldn't need to change these...
POLICY_FILE = './policies.n3'
POLICY_TYPE = 'text/rdf+n3'
REIN_URI = 'http://dig.csail.mit.edu/2005/09/rein/network#'
ACCESS_POLICY_URI = REIN_URI + 'access-policy'
USE_POLICY_URI = REIN_URI + 'use-policy'
REALM_URI = REIN_URI + 'realm'
DEFAULT_REALM = 'Default Realm'
FOAF_OPENID = 'http://xmlns.com/foaf/0.1/openid'
OPENID_CACHE_DIRECTORY = 'cache'

# Definitely don't touch these
SCRIPT_INT_PATH = os.path.dirname(__file__) + '/'
REWRITE_RE = re.compile(r'/' + re.escape(os.path.basename(__file__)) + \
                        '\?(?:.*&|)file=(?P<file>[^&]*).*$')

class Header:
    def __init__(self):
        self.type = None
        self.params = {}

class Identity:
    def __init__(self):
        self.document = None

def load_policies(req):
    """Loads a list of files and their corresponding policy files and returns
    the corresponding dictionary.

    We currently use a simple Notation3-based format."""
    
    global SCRIPT_URI, SCRIPT_INT_PATH, POLICY_FILE, POLICY_TYPE, POLICY_URI, \
           DEFAULT_REALM, REALM_URI

    # Load the policies into an RDFStore for querying.
    store = llyn.RDFStore()
    myStore.setStore(store)
    try:
        context = store.load(uri=POLICY_FILE,
                             contentType=POLICY_TYPE,
                             remember=0,
                             referer = '',
                             topLevel = True)
    except:# (IOError, SyntaxError, DocumentError):
        # TODO: Actually record an error somewhere.
        raise apache.SERVER_RETURN, apache.HTTP_INTERNAL_SERVER_ERROR
#        throw_http_error(apache.HTTP_INTERNAL_SERVER_ERROR,
#                         "The AIR proxy has not been properly configured: " + \
#                         "The policies file could not be read properly.")
    # Currently voodoo magic.
    # TODO: How does rdflib work ANYWAY?
    context.reopen()
    context.stayOpen = 1

    # Okay, I assume that worked.  Let's build the dict of files and their
    # corresponding policies.
    policies = {}
    access_policy_stmts=context.statementsMatching(pred=context.newSymbol(ACCESS_POLICY_URI))
    for statement in access_policy_stmts:
        # Little bit kludgy.  SCRIPT_INT_PATH is an absolute file path, but
        # lacks the bit to make it an absolute URI.  We fix this.
        
        # Then, to translate the subject's URI to the corresponding HTTP URI,
        # we need to take the relative path and join it to SCRIPT_URI.
        controlled_file = uripath.refTo('file://' + SCRIPT_INT_PATH,
                                        statement[SUBJ].uriref())
        controlled_file = uripath.join(SCRIPT_URI, controlled_file)
        policy = uripath.refTo('file://' + SCRIPT_INT_PATH,
                               statement[OBJ].uriref())
        policy = uripath.join(SCRIPT_URI, policy)
        if not policies.has_key(controlled_file):
            policies[controlled_file] = {'file_symbol':statement[SUBJ]}
        policies[controlled_file]['access_policy'] = policy

    # Now do the same for use policies.
    use_policy_stmts=context.statementsMatching(pred=context.newSymbol(USE_POLICY_URI))
    for statement in use_policy_stmts:
        # Little bit kludgy.  SCRIPT_INT_PATH is an absolute file path, but
        # lacks the bit to make it an absolute URI.  We fix this.
        
        # Then, to translate the subject's URI to the corresponding HTTP URI,
        # we need to take the relative path and join it to SCRIPT_URI.
        controlled_file = uripath.refTo('file://' + SCRIPT_INT_PATH,
                                        statement[SUBJ].uriref())
        controlled_file = uripath.join(SCRIPT_URI, controlled_file)
        policy = uripath.refTo('file://' + SCRIPT_INT_PATH,
                               statement[OBJ].uriref())
        policy = uripath.join(SCRIPT_URI, policy)
        if not policies.has_key(controlled_file):
            policies[controlled_file] = {'file_symbol':statement[SUBJ]}
        policies[controlled_file]['use_policy'] = policy

    # Let's load the realms...
    for file in policies.keys():
        realm_syms = context.any(subj = policies[file]['file_symbol'],
                                 pred = context.newSymbol(REALM_URI))
        if realm_syms == None:
            policies[file]['realm'] = DEFAULT_REALM
        else:
            policies[file]['realm'] = str(realm_syms)

    return policies

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

def request_authentication(req, policy_dict):
    'Requests authentication from the client by way of a 401 error.'

    # TODO: Not so kludgy.  Perhaps redirect with directives?
    # Write the headers, then return 401.
    req.content_type = 'text/html'
    # TODO: Relative URI?
    auth_header = 'AIR realm="%s",policy="%s"' % \
                  (q(policy_dict['realm']),
                   q(policy_dict['access_policy']))
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

def get_auth_header(req):
    """Gets the Authorization header from the HTTPRequest req and parses it."""
    
    header = Header()
    if not req.headers_in.has_key('Authorization'):
        return None
    header_field = req.headers_in['Authorization']
    
    # Now find the descriptions
    header.type = header_field[0:header_field.index(' ')].strip()
    header.params = {}
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
                # Ignore quotes if we haven't gotten to reading the value yet.
                # They shouldn't be in the param name, but we're tolerant of
                # stupidity.
                if params[ch] == '=':
                    cur_value = ''
                # And if we find a comma...  Well the server is still messed up
                # so we just mark the param as EXISTING, with no value.
                elif params[ch] == ',':
                    cur_param = cur_param.strip()
                    if not header.params.has_key(cur_param):
                        header.params[cur_param] = []
                    header.params[cur_param].append(None)
                    cur_param = ''
                else:
                    cur_param += params[ch]
            else:
                # Trying to read the current value.  We're a bit tolerant, and
                # let the value enter and exit quotes repeatedly.  We just
                # strip the bounding quotes.
                if params[ch] == '"':
                    quoted = True
                elif params[ch] == ',':
                    cur_param = cur_param.strip()
                    cur_value = cur_value.strip()
                    if not header.params.has_key(cur_param):
                        header.params[cur_param] = []
                    header.params[cur_param].append(cur_value)
                    cur_param = ''
                    cur_value = None
                else:
                    cur_value += params[ch]
    
    # Don't forget to save that last param/value pair!
    cur_param = cur_param.strip()
    if cur_value != None:
        cur_value = cur_value.strip()
    if not header.params.has_key(cur_param):
        header.params[cur_param] = []
    header.params[cur_param].append(cur_value)
    
    return header

def transhandler(req):
    global REWRITE_RE, SCRIPT_INT_PATH
    
    result = REWRITE_RE.match(req.uri)
    if result:
        matches = result.groupdict()
        file = matches['file']
        req.filename = os.path.join(SCRIPT_INT_PATH, file)
        return apache.OK
    return apache.DECLINED

def accesshandler(req):
    global SCRIPT_URI, SCRIPT_EXT_PATH, SCRIPT_INT_PATH

    # TODO: Get rid of globals.
    # Initialize paths...
    req.add_common_vars()
    
    # Constructing the URI for this script takes time.
    # dirname strips the final /
    SCRIPT_EXT_PATH = os.path.dirname(req.uri) + '/'
    SCRIPT_URI = ''
    if req.subprocess_env.has_key('HTTPS') and \
           req.subprocess_env['HTTPS'] == 'on':
        SCRIPT_URI = "https://%s" % (req.hostname)
        if req.connection.local_addr[1] == 443:
            SCRIPT_URI += '/'
        else:
            SCRIPT_URI += ':%d/' % (req.connection.local_addr[1])
    else:
        SCRIPT_URI = "http://%s" % (req.hostname)
        if req.connection.local_addr[1] == 80:
            SCRIPT_URI += '/'
        else:
            SCRIPT_URI += ':%d/' % (req.connection.local_addr[1])
    SCRIPT_URI = uripath.join(SCRIPT_URI, SCRIPT_EXT_PATH)

    # This way, we can do something about errors...
    req.content_type = 'text/plain'

    # Change the working directory.
    os.chdir(SCRIPT_INT_PATH)
    
    # Load policies
    policies = load_policies(req)
    
    # Get the requested file.
    # TODO: How does it handle arguments?
#    if req.args == None:
#        no_file_requested(req)
#        return apache.HTTP_BAD_REQUEST
#    requested_file = [0, 0]
#    requested_file[0] = req.args.find('file=', requested_file[0])
#    while requested_file[0] > 0 and req.args[requested_file[0]] != '&':
#        requested_file[0] = req.args.find('file=', requested_file[0])
#    if requested_file[0] == -1:
#        no_file_requested(req)
#        return apache.HTTP_BAD_REQUEST
#    requested_file[0] += 5
#    requested_file[1] = req.args.find('&', requested_file[0])
#    if requested_file[1] == -1:
#        requested_file = req.args[requested_file[0]:]
#    else:
#        requested_file = req.args[requested_file[0]:requested_file[1]]

    requested_file = uripath.refTo(SCRIPT_INT_PATH, req.filename)

    # requested_file is now relative within the server hierarchy.  Hope that's
    # the same as the local hierarchy!
    
    # Does the requested file exist?
    if not os.path.exists(requested_file):
        return apache.HTTP_NOT_FOUND
#        file_not_found(req, os.path.join(SCRIPT_INT_PATH, requested_file))
#        return apache.OK

    # Let's canonicalize requested_file's URI.
    requested_uri = uripath.join(SCRIPT_URI, requested_file)
    
    # Is it covered by a policy?
    if policies.has_key(requested_uri):
        # Send the 401 error if we are and no proof was sent

        # Parse the Authorization header.
        auth_header = get_auth_header(req)

        if policies[requested_uri].has_key('access_policy') and \
               (auth_header == None \
                or not auth_header.params.has_key('identity-document')):
            # No Authorization or identity proffered?  Then send the 401.
            request_authentication(req, policies[requested_uri])
            return apache.DONE
        else:
            # Otherwise, we need to check that the identity satisfies the
            # policy.  If it doesn't we return a 403.  This is a multi-part
            # process...

            # If we don't have the openid.mode header, then we need to set up.
            # We clearly don't have the openid session ready.
            if req.args != None:
                params = util.parse_qs(req.args)
            else:
                params = {}
            params = dict(zip(params.keys(), map(lambda x: (x[0]), params.values())))
            
            # 1. Construct the proffered identity from the ident document.
            identity = Identity()
            identity.document = auth_header.params['identity-document']
            if identity.document != None:
                identity.document = identity.document[0]
            
            if not params.has_key('openid.mode'):
                # TODO: Actually check OpenID.  For now we just check that a
                # document was given.
                
                # 1.1. Try to get the OpenID associated with the ident doc.
                
                # Get the document and parse in the RDF graph...
                store = llyn.RDFStore()
                myStore.setStore(store)
                try:
                    context = store.load(uri = uripath.splitFrag(identity.document)[0],
                                         remember = 0,
                                         referer = '',
                                         topLevel = True)
                except:# (IOError, SyntaxError, DocumentError):
                    # TODO: Actually record an error somewhere.
                    apache.log_error("Unexpected error:" + traceback.format_exc(),
                                     apache.APLOG_ERR)
                    raise apache.SERVER_RETURN, \
                          apache.HTTP_INTERNAL_SERVER_ERROR
                # Currently voodoo magic.
                # TODO: How does rdflib work ANYWAY?
                context.reopen()
                context.stayOpen = 1
                
                # And then query for a foaf:openid property for the proffered
                # identity fragid.
                authid = context.any(subj=context.newSymbol(identity.document),
                                     pred=context.newSymbol(FOAF_OPENID))
                # If we don't find it, return a 401.
                if authid == None:
                    request_authentication(req, policies[requested_uri])
                    return apache.DONE
                
                # Save the openid server...
                authid = str(authid)
                
                # 2. Authenticate the OpenID...
                openid = Consumer({'identity': identity},
                                  FileOpenIDStore(OPENID_CACHE_DIRECTORY))
                auth_req = openid.begin(authid)
                redir = auth_req.redirectURL(requested_uri,
                                             requested_uri)
                
                # We actually die here, redirecting to the OpenID server.
                req.headers_out['location'] = redir
                req.status = apache.HTTP_MOVED_TEMPORARILY
                return apache.DONE
            else:
                # We have a continuation of an OpenID authentication.
                # TODO: Reason over the authorized ID.
                openid = Consumer({'identity': identity},
                                  FileOpenIDStore(OPENID_CACHE_DIRECTORY))
                openid_resp = openid.complete(params, requested_uri)

                # TODO: Handle SETUP_NEEDED?
                if openid_resp.status != SUCCESS:
                    # If the identity refuses to authenticate, return a 401.
                    request_authentication(req, policies[requested_uri])
                    return apache.DONE
                
                if policies[requested_uri].has_key('use_policy'):
                    req.headers_out['x-use-policy'] = \
                        str(policies[requested_uri]['use_policy'])
                
                # For now, fall through and don't reason over the policy and
                # identity.
                # 3. Run the AIR Reasoner over the policy and identity.
                
                # 4. Make the return based on what the reasoner concluded.
            
    # If we're proxying something not covered by a policy, we just let it thru.
    return apache.OK

# Otherwise send the file
# 1:00
# 2:00 Saturday
# 0:45 Monday
