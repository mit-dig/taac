"""
TAAC - TAAC Ain't Access Control (or TAMI Accountability/Access Control) Proxy

This script acts as a filter to all requests for files within this
directory.  If a file is associated with a policy in policies.n3, it will
send a 401 error asking for AIR-based authentication.

This gateway requires mod_python with python 2.4 or greater and python-openid
to operate."""

# Internal imports...
import os
import os.path
import string
from random import choice

import sys
import traceback
import hotshot

# Library imports...
from mod_python import apache, util
from openid.consumer.consumer import Consumer, SUCCESS
from openid.store.filestore import FileOpenIDStore
from openid.message import BARE_NS

# And tmswap imports...
from tmswap import llyn
from tmswap import myStore
from tmswap.RDFSink import SUBJ, OBJ
from tmswap import uripath
from tmswap import policyrunner

# Some globals...  You shouldn't need to change these...
import taac.config
import taac.namespaces
import taac.util
from taac.util import q
# Had to import my own copy of the uuid module.  2.4 doesn't have it.
from taac.uuid import uuid1

taac_profiling = False

class TAACServer:
    def __init__(self, base_uri, base_path):
        """Initializes this TAACServer instance with base_uri containing the
        uri from which URIs should be considered relative to, and similarly
        with base_path"""
        self.store = None
        self.base_uri = base_uri
        self.base_path = base_path
        self.log_uri = uripath.join(base_uri, taac.config.LOG_FILE)
        self.policies = None
    
    def load_policies(self, req):
        """Loads a list of files and their corresponding policy files into the
        server.
        
        We currently use a simple Notation3-based format."""
        
        # Load the policies into an RDFStore for querying.
        if self.store == None:
            self.store = llyn.RDFStore()
            myStore.setStore(self.store)
        
        try:
            context = self.store.load(uri=taac.config.POLICY_FILE,
                                      contentType=taac.config.POLICY_TYPE,
                                      remember=0,
                                      referer = '',
                                      topLevel = True)
        except:# (IOError, SyntaxError, DocumentError):
            # TODO: Actually record an error somewhere.
            apache.log_error("Unexpected error:" + traceback.format_exc(),
                             apache.APLOG_ERR)
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
        self.policies = {}
        access_policy_stmts = context.statementsMatching(
            pred = context.newSymbol(taac.namespaces.rein['access-policy']))
        for statement in access_policy_stmts:
            # Little bit kludgy.  script_int_path is an absolute file path, but
            # lacks the bit to make it an absolute URI.  We fix this.
            
            # Then, to translate the subject's URI to the corresponding HTTP
            # URI, we need to take the relative path and join it to script_uri.
            controlled_file = uripath.refTo('file://' + self.base_path,
                                            statement[SUBJ].uriref())
            controlled_file = uripath.join(self.base_uri, controlled_file)
            policy = uripath.refTo('file://' + self.base_path,
                                   statement[OBJ].uriref())
            policy = uripath.join(self.base_uri, policy)
            
            if not self.policies.has_key(controlled_file):
                self.policies[controlled_file]={'file_symbol':statement[SUBJ]}
            self.policies[controlled_file]['access_policy'] = policy
            
        # Now do the same for use policies.
        use_policy_stmts = context.statementsMatching(
            pred = context.newSymbol(taac.namespaces.rein['use-policy']))
        
        for statement in use_policy_stmts:
            controlled_file = uripath.refTo('file://' + self.base_path,
                                            statement[SUBJ].uriref())
            controlled_file = uripath.join(self.base_uri, controlled_file)
            policy = uripath.refTo('file://' + self.base_path,
                                   statement[OBJ].uriref())
            policy = uripath.join(self.base_uri, policy)
            
            if not self.policies.has_key(controlled_file):
                self.policies[controlled_file]={'file_symbol':statement[SUBJ]}
            self.policies[controlled_file]['use_policy'] = policy
                
        # Let's load the realms...
        for file in self.policies.keys():
            realm_syms = context.any(subj = self.policies[file]['file_symbol'],
                                     pred = context.newSymbol(
                                                taac.namespaces.rein.realm))
            if realm_syms == None:
                self.policies[file]['realm'] = taac.config.DEFAULT_REALM
            else:
                self.policies[file]['realm'] = str(realm_syms)
    
    def get_auth_header(self, req):
        """Gets the Authorization header from the HTTPRequest req and parses
        it."""
        
        if not req.headers_in.has_key('Authorization'):
            return None
        return taac.util.HTTPAuthHeader(req.headers_in['Authorization'])

    def log_request(self, requested_uri, identity, error):
        """Adds the record of a request to the log and returns a formula for
        processing."""
        
        # TODO: Clean up, and actually log.
        # Init the store.
        if self.store == None:
            self.store = llyn.RDFStore()
            myStore.setStore(self.store)
        
        # TODO: Find out if random id is assigned already in the log.
        req_id = uuid1()
        
        context = self.store.newFormula()
        entry = context.newSymbol(self.log_uri + '#' + req_id.hex)
        a = context.newSymbol(taac.namespaces.rdf.type)
        request = context.newSymbol(taac.namespaces.rein.Request)
        data = context.newSymbol(taac.namespaces.tami.data)
        recipient = context.newSymbol(taac.namespaces.tami.recipient)
        status = context.newSymbol(taac.namespaces.rein.status)
        if error == taac.util.REQ_NO_ID:
            status_descriptor = taac.namespaces.rein.status_no_id
        elif error == taac.util.REQ_NO_AUTH:
            status_descriptor = taac.namespaces.rein.status_no_auth
        elif error == taac.util.REQ_INCOMPLETE:
            status_descriptor = taac.namespaces.rein.status_incomplete
        elif error == taac.util.REQ_AUTH_FAILED:
            status_descriptor = taac.namespaces.rein.status_auth_failed
        elif error == taac.util.REQ_AUTH_SUCCESS:
            status_descriptor = taac.namespaces.rein.status_auth_success
        status_descriptor = context.newSymbol(status_descriptor)
        context.add(entry, a, request)
        context.add(entry, data, context.newSymbol(requested_uri))
        if identity != None:
            context.add(entry, recipient, context.newSymbol(identity))
#        context.add(context.newSymbol(identity), a, government_official)
        context.add(entry, status, status_descriptor)
        
        log = open(taac.config.LOG_FILE, 'a')
        # Initialize the log if needed.
#    if log.tell() == 0:
#        log.write("@prefix : <%> .\n" % (LOG_URI + '#'))
#        log.write("@prefix tami: <http://dig.csail.mit.edu/TAMI/2007/tami#> .\n")
#        log.write("@prefix rein: <http://dig.csail.mit.edu/2005/09/rein/network#> .\n")
#        log.write("\n")
        entry = context.n3String(flags = 'p').split("\n")
        # Strip @-directives when writing the n3String.
        for line in entry:
            line = line.strip() + "\n"
#        if len(line) > 0 and line[0] == '@':
#            continue
            log.write(line)
        log.close()
#    apache.log_error(context.n3String(), apache.APLOG_ERR)
        
        return context

    def log_completed_request(self, requested_uri, conclusions, error):
        """Adds the record of a completed request to the log."""
        
        log = open(taac.config.LOG_FILE, 'a')
        # Initialize the log if needed.
#    if log.tell() == 0:
#        log.write("@prefix : <%> .\n" % (LOG_URI + '#'))
#        log.write("@prefix tami: <http://dig.csail.mit.edu/TAMI/2007/tami#> .\n")
#        log.write("@prefix rein: <http://dig.csail.mit.edu/2005/09/rein/network#> .\n")
#        log.write("\n")
        entry = conclusions.n3String(flags = 'p').split("\n")
        # Strip @-directives when writing the n3String.
        for line in entry:
            line = line.strip() + "\n"
#        if len(line) > 0 and line[0] == '@':
#            continue
            log.write(line)
        log.close()
#    apache.log_error(context.n3String(), apache.APLOG_ERR)

    def prepare_openid(self, req, client, requested_uri):
        'Performs initialization of OpenID authentication.'

        # 1.1. Try to get the OpenID associated with the ident doc.
        
        # Get the document and parse in the RDF graph...
        if self.store == None:
            store = llyn.RDFStore()
            myStore.setStore(store)
        try:
            context = self.store.load(uri = uripath.splitFrag(client.id)[0],
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
        
        # And then query for a foaf:openid property for the
        # proffered identity fragid.
        authid = context.any(subj=context.newSymbol(client.id),
                             pred=context.newSymbol(
                                      taac.namespaces.foaf.openid))
        
        # If we don't find it, return a 401.
        if authid == None:
            policy = self.policies[requested_uri]
            auth_header = 'AIR realm="%s",policy="%s"' % \
                          (q(policy['realm']),
                           q(policy['access_policy']))
            taac.util.request_authentication(req, policies[requested_uri])
            
            # Log this request, but note no openid.
            self.log_request(requested_uri, client.id, taac.util.REQ_NO_AUTH)
            
            return apache.DONE
        
        # Save the openid server...
        authid = str(authid)
        
        # 2. Authenticate the OpenID...
        openid = Consumer({'client': client},
                          FileOpenIDStore(taac.config.OPENID_CACHE_DIRECTORY))
        auth_req = openid.begin(authid)
        
        if req.args != None:
            params = util.parse_qs(req.args)
        else:
            params = {}
        params = dict(zip(params.keys(), map(lambda x: (x[0]), params.values())))

        # If we have taac_profile=1, make sure we profile when we return.
        if params.has_key('taac_profile') and params['taac_profile'] == '1':
            requested_uri = requested_uri + '?taac_profile=1'
        redir = auth_req.redirectURL(requested_uri, requested_uri)
        
        # Log this request, but note incomplete
        self.log_request(requested_uri, client.id, taac.util.REQ_INCOMPLETE)
        
        # We actually die here, redirecting to the OpenID server.
        req.headers_out['location'] = redir
        
        return apache.HTTP_MOVED_TEMPORARILY

    def continue_openid(self, req, client, requested_uri, params):
        'Processes the continuation of an OpenID authentication.'
        
        # We have a continuation of an OpenID authentication.
        openid = Consumer({'identity': client},
                          FileOpenIDStore(taac.config.OPENID_CACHE_DIRECTORY))
        openid_resp = openid.complete(params, requested_uri)
        
        # TODO: Handle SETUP_NEEDED?
        if openid_resp.status != SUCCESS:
            # If the identity refuses to authenticate, return a 401
            policy = self.policies[requested_uri]
            auth_header = 'AIR realm="%s",policy="%s"' % \
                          (q(policy['realm']),
                           q(policy['access_policy']))
            taac.util.request_authentication(req, auth_header)
            
            self.log_request(requested_uri, client.id,
                             taac.util.REQ_AUTH_FAILED)
            
            return apache.DONE
        
        if self.policies[requested_uri].has_key('use_policy'):
            req.headers_out['x-use-policy'] = \
                str(self.policies[requested_uri]['use_policy'])

        # 3. Run the AIR Reasoner over the policy and identity.
        req_context = self.log_request(requested_uri, client.id,
                                  taac.util.REQ_AUTH_SUCCESS)
        testPolicy = policyrunner.runPolicy
        (conclusion, context) = testPolicy(
            [uripath.splitFrag(client.id)[0]],
            [uripath.splitFrag(self.policies[requested_uri]['access_policy'])[0]],
            req_context.n3String())
        
        # 4. Make the return based on what the reasoner concluded.
        
        compliance = conclusion.any(
            pred=conclusion.newSymbol(taac.namespaces.air['compliant-with']),
            obj=conclusion.newSymbol(self.policies[requested_uri]['access_policy']))
        
        # If compliance is not explicit, then it's not.
        if compliance == None:
            # Log access denied.
            self.log_completed_request(requested_uri, conclusion,
                                       taac.util.COMPLETE_ACC_DENIED)
            return apache.HTTP_FORBIDDEN
        else:
            self.log_completed_request(requested_uri, conclusion,
                                       taac.util.COMPLETE_ACC_GRANTED)
            return apache.OK
    
    def allow_access(self, req):
        'Determines whether the request should be allowed access.'
        
        # This way, we can do something about errors...
        req.content_type = 'text/plain'
        
        # Load policies
        if self.policies == None:
            self.load_policies(req)
        
        # Get the requested file.
        requested_file = uripath.refTo(self.base_path, req.filename)
        
        # requested_file is now relative within the server hierarchy.  Hope
        # that's the same as the local hierarchy!
        
        # Does the requested file exist?
        if not os.path.exists(requested_file):
            # TODO: Do we want to log this event?
            return apache.HTTP_NOT_FOUND
        
        # Let's canonicalize requested_file's URI.
        requested_uri = uripath.join(self.base_uri, requested_file)
        
        # Is it covered by a policy?
        if self.policies.has_key(requested_uri):
            # Send the 401 error if we are and no proof was sent
            
            # Parse the Authorization header.
            auth_header = self.get_auth_header(req)
            
            if self.policies[requested_uri].has_key('access_policy') and \
                   (auth_header == None \
                    or not auth_header.params.has_key('identity-document')):
                # No Authorization or identity proffered?  Then send the 401.
                policy = self.policies[requested_uri]
                auth_header = 'AIR realm="%s",policy="%s"' % \
                              (q(policy['realm']),
                               q(policy['access_policy']))
                taac.util.request_authentication(req, auth_header)
                
                # Log this request with no identity.
                self.log_request(requested_uri, None, taac.util.REQ_NO_ID)
                
                return apache.DONE
            else:
                # Otherwise, we need to check that the identity satisfies the
                # policy.  If it doesn't we return a 403.  This is a multi-part
                # process...

                if req.args != None:
                    params = util.parse_qs(req.args)
                else:
                    params = {}
                params = dict(zip(params.keys(),
                                  map(lambda x: (x[0]), params.values())))
                
                # 1. Construct the proffered identity from the ident document.
                client = taac.util.Client()
                if auth_header.params.has_key('identity-document'):
                    client.id = auth_header.params['identity-document']
                    if client.id != None:
                        client.id = client.id[0]
                if auth_header.params.has_key('credential-document'):
                    client.credentials = \
                        auth_header.params['credential-document']
                    if client.credentials != None:
                        client.credentials = client.credentials[0]
                
                # If we don't have the openid.mode header, then we need to set
                # up.  We clearly don't have the openid session ready.  When
                # the session is ready and we've got an OpenID login, we can
                # try again.
                if not params.has_key('openid.mode'):
                    return self.prepare_openid(req, client, requested_uri)
                else:
                    return self.continue_openid(req, client, requested_uri,
                                                params)
        
        # If we're proxying something not covered by a policy, we just let it
        # through.
        return apache.OK

def do_access(req):
    'This actually does the access control...'

    # Initialize paths...
    req.add_common_vars()
    
    # Constructing the URI for this script takes time.
    # dirname strips the final /
    base_uri = ''
    if req.subprocess_env.has_key('HTTPS') and \
           req.subprocess_env['HTTPS'] == 'on':
        base_uri = "https://%s" % (req.hostname)
        if req.connection.local_addr[1] == 443:
            base_uri += '/'
        else:
            base_uri += ':%d/' % (req.connection.local_addr[1])
    else:
        base_uri = "http://%s" % (req.hostname)
        if req.connection.local_addr[1] == 80:
            base_uri += '/'
        else:
            base_uri += ':%d/' % (req.connection.local_addr[1])
    
    # Now, append the relative URI from the request.
    base_uri = uripath.join(base_uri, os.path.dirname(req.uri) + '/')
    base_path = os.path.dirname(__file__) + '/'
    
    # Change the working directory.
    os.chdir(base_path)
    
    # Create the TAACServer object...
    server = TAACServer(base_uri, base_path)
    try:
        retval = server.allow_access(req)
    except apache.SERVER_RETURN, http_error:
        retval = http_error

    return retval

DEBUG = 1

def accesshandler(req):
    'This is just a wrapper so that we can optionally profile.'
    if DEBUG:
        taac.config = reload(taac.config)
        taac.namespaces = reload(taac.namespaces)
        taac.util = reload(taac.util)
    
    uuid = uuid1()

    if req.args != None:
        params = util.parse_qs(req.args)
    else:
        params = {}
    params = dict(zip(params.keys(), map(lambda x: (x[0]), params.values())))
    
    # If we have taac_profile=1, profile...  Otherwise, just run it.
    presult = None
    if params.has_key('taac_profile') and params['taac_profile'] == '1':
        pobject = hotshot.Profile("/tmp/Profiler." + uuid.hex + ".prof")
        presult = pobject.runcall(do_access, req)
        req.headers_out['x-taac-profile-id'] = uuid.hex
    else:
        presult = do_access(req)

    return presult
