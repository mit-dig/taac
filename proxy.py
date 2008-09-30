"""
TAAC - TAAC Ain't Access Control (or TAMI Accountability/Access Control) Proxy

This script acts as a filter to all requests for files within this
directory.  If a file is associated with a policy in policies.n3, it will
send a 401 error asking for AIR-based authentication.

This gateway requires mod_python with python 2.4 or greater, python-openid, and
pyCrypto 2.0.1 or greater (for ElGamal support in OpenPGP) to operate."""

# TODO: Internal caching.
# TODO: Check signature of FOAF file.

# Internal imports...
import os
import os.path
import string
import sys
from random import choice
import md5
import time
import urllib2
from binascii import a2b_hex

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
import taac.openpgp as openpgp
import taac.x509 as x509
import taac.asn1 as asn1

def pdebug(message_debug_level, message):
    level_mapping = { DEBUG_ERROR: apache.APLOG_ERR,
                      DEBUG_WARNING: apache.APLOG_WARNING,
                      DEBUG_MESSAGE: apache.APLOG_NOTICE }
    if DEBUG_LEVEL >= message_debug_level:
        apache.log_error(message, level_mapping[message_debug_level])
#        sys.stdout.write(message + "\n")

def getTimestampFromNonceTuple(a):
    return a[1]['timestamp']

def extractURISubjectAltNames(cert):
    alt_names = None

    for optfield in cert.optional_fields:
        if optfield.tag == 3:
            for ext in optfield.value():
                if ext[0].value() == (2, 5, 29, 17):
                    alt_names, rest = asn1.der_decode(ext[1].value())
                    assert rest == ''
                if alt_names != None:
                    break
            if alt_names != None:
                break

    if alt_names == None:
        return []

    alt_names_array = []
    for alt_name in alt_names:
        if alt_name.tag == 6:
            alt_names_array.append(alt_name.value())

    return alt_names_array

class TAACServer:
    def __init__(self, base_uri, base_path):
        """Initializes this TAACServer instance with base_uri containing the
        uri from which URIs should be considered relative to, and similarly
        with base_path"""
        pdebug(DEBUG_MESSAGE, 'Initializing TAACServer...')
        self.store = None
        self.base_uri = base_uri
        self.base_path = base_path
        self.log_uri = uripath.join(base_uri, taac.config.LOG_FILE)
        self.policies = None
        self.nonces = None
    
    def load_policies(self, req):
        """Loads a list of files and their corresponding policy files into the
        server.
        
        We currently use a simple Notation3-based format."""
        
        # Load the policies into an RDFStore for querying.
        pdebug(DEBUG_MESSAGE, 'Loading policies for files...')
        
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
        pdebug(DEBUG_MESSAGE, 'Extracting policy/file dictionary...')
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

        pdebug(DEBUG_MESSAGE,
               'Extracting Authorization header from HTTP request.')
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
        if conclusions != None:
            entry = conclusions.n3String(flags = 'p').split("\n")
        else:
            entry = ''
        # Strip @-directives when writing the n3String.
        for line in entry:
            line = line.strip() + "\n"
#        if len(line) > 0 and line[0] == '@':
#            continue
            log.write(line)
        log.close()
#    apache.log_error(context.n3String(), apache.APLOG_ERR)

    def load_nonces(self):
        """Loads the nonces from the cache and saves them in a Python hash.
        
        We currently use a simple text-based format."""
        
        # Load the nonces into a Python hash.
        pdebug(DEBUG_MESSAGE, 'Loading cached nonces...')
        
        self.nonces = {}
        file = open(taac.config.NONCE_CACHE_FILE, 'r')
        for line in file.readlines():
            line = line.strip()
            line = line.split(' ', 2)
            self.nonces[line[0]] = {'timestamp':line[1], 'realm':line[2]}
        file.close()
        
    def save_nonces(self):
        """Saves the nonces to the cache.
        
        We currently use a simple text-based format."""
        
        # Save the nonces from a Python hash.
        if self.nonces == None:
            self.load_nonces()
        
        self.prune_nonces()

        pdebug(DEBUG_MESSAGE, 'Saving cached nonces...')
        
        f = open(taac.config.NONCE_CACHE_FILE, 'w')
        for nonce_tuple in self.nonces.items():
            f.write("%s %s %s\n" %
                    (nonce_tuple[0], nonce_tuple[1]['timestamp'],
                     nonce_tuple[1]['realm']))
        f.close()
        
    def issue_nonce(self, realm):
        'Returns a new nonce associated with the given realm.'

        if self.nonces == None:
            self.load_nonces()

        pdebug(DEBUG_MESSAGE, 'Issuing new nonce...')
        
        nonce = md5.new("%s_%d" %
                        (taac.config.SALT, time.time())).hexdigest()
        while self.nonces.has_key(nonce):
            nonce = md5.new("%s_%d" %
                            (taac.config.SALT, time.time())).hexdigest()

        self.nonces[nonce] = {'timestamp':time.time(), 'realm':realm}

        self.save_nonces()

        return nonce
    
    def has_nonce(self, nonce, realm):
        'Returns true if a given nonce was issued with the given realm.'

        if self.nonces == None:
            self.load_nonces()

        pdebug(DEBUG_MESSAGE, 'Checking for matching nonce...')
        
        return (self.nonces.has_key(nonce) and \
                self.nonces[nonce]['realm'] == realm)

    def revoke_nonce(self, nonce):
        'Revokes a used nonce.'

        if self.nonces == None:
            self.load_nonces()

        pdebug(DEBUG_MESSAGE, 'Revoking used nonce...')

        del self.nonces[nonce]

        self.save_nonces()
    
    def prune_nonces(self):
        'Regularly cleans out old nonces so that they cannot be guessed.'

        if self.nonces == None:
            self.load_nonces()

        pdebug(DEBUG_MESSAGE, 'Pruning unused nonces...')
        
        # Go into our nonce cache and remove dated nonces and associated
        # realms.
        now = time.time()
        nonces_to_delete = map(lambda x: (x[0]),
                               filter(lambda x: (x[1]['timestamp'] < now - taac.config.NONCE_CACHE_DURATION),
                                      self.nonces.items()))
        for nonce in nonces_to_delete:
            del self.nonces[nonce]

    def check_rdfauth(self, req, client, requested_uri, realm, nonce, signature):
        """Performs RDFAuth authentication.  See:
        http://blogs.sun.com/bblfish/entry/rdfauth_sketch_of_a_buzzword"""

        pdebug(DEBUG_MESSAGE, 'Attempting to use RDFAuth...')

        # 1.1. Confirm that the nonce and realm provided are associated, and
        # remove them.

        if not self.has_nonce(nonce, realm):
            pdebug(DEBUG_WARNING,
                   "Nonce '%s' isn't associated with realm '%s'. Replay attack?" %
                   (nonce, realm))
            policy = self.policies[requested_uri]
            nonce = self.issue_nonce(q(policy['realm']))
            auth_header = 'TAAC realm="%s",policy="%s",nonce="%s"' % \
                          (q(policy['realm']),
                           q(policy['access_policy']),
                           q(nonce))
            pdebug(DEBUG_MESSAGE,
                   'Requesting authentication: %s' % (auth_header))
            taac.util.request_authentication(req, self.policies[requested_uri])
            
            # Log this request, but note no openid.
            self.log_request(requested_uri, client.id, taac.util.REQ_NO_AUTH)
            
            return apache.DONE

        # 1.2. Try to get the PGP public key associated with the ident doc.
        pdebug(DEBUG_MESSAGE, "Trying to get client's claimed PGP public key.")
        
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
        
        # And then query for wot:identity and wot:pubkeyAddress properties for
        # the proffered identity fragid.
        authids = context.each(subj=context.newSymbol(client.id),
                               pred=context.newSymbol(
                                        taac.namespaces.wot.hasKey))
        authids.extend(context.each(pred=context.newSymbol(
                                             taac.namespaces.wot.identity),
                                    obj=context.newSymbol(client.id)))
        
        # If we don't find it, return a 401.
        if authids == []:
            pdebug(DEBUG_WARNING,
                   "Couldn't find public key address in identity-document.")
            policy = self.policies[requested_uri]
            nonce = self.issue_nonce(q(policy['realm']))
            auth_header = 'TAAC realm="%s",policy="%s",nonce="%s"' % \
                          (q(policy['realm']),
                           q(policy['access_policy']),
                           q(nonce))
            pdebug(DEBUG_MESSAGE,
                   'Requesting authentication: %s' % (auth_header))
            taac.util.request_authentication(req, self.policies[requested_uri])
            
            # Log this request, but note no public key.
            self.log_request(requested_uri, client.id, taac.util.REQ_NO_AUTH)
            
            return apache.DONE

        for authid in authids:
            pubkey = context.any(subj=authid,
                                 pred=context.newSymbol(
                                          taac.namespaces.wot.pubkeyAddress))

            if pubkey == None:
                continue
            
            pubkey = str(pubkey.uriref())
            
            pdebug(DEBUG_MESSAGE, 'Public key address: %s' % (pubkey))
            pdebug(DEBUG_MESSAGE, 'Populating keyring with public key...')
            
            f = urllib2.urlopen(pubkey)
            pubkey = f.read()
            f.close()
            
            keys = openpgp.parsePGPKeys(pubkey)
            ring = openpgp.PGPKeyRing()
            for key in keys:
                ring.addKey(key)
                
            # 2. Check the provided signature against the expected message.
            pdebug(DEBUG_MESSAGE, 'Attempting to verify provided signature...')
            
            # The message is "(realm):(nonce)"
            message = realm + ':' + nonce
            
            # Build the signature ASCII-armored packet from the pure sig.
            signature = "-----BEGIN PGP SIGNATURE-----\n" + \
                        "\n" + \
                        signature + "\n" + \
                        "-----END PGP SIGNATURE-----\n"
            
            signature = openpgp.parsePGPSignature(signature)
            digest = signature.prepareDigest()
            digest.update(message)
            digest = signature.finishDigest(digest)
            
            (match, key) = signature.verifyDigest(ring, digest)
            
            if match == 1:
                # We good.
                pdebug(DEBUG_MESSAGE, "Signature matched!")
                if self.policies[requested_uri].has_key('use_policy'):
                    pdebug(DEBUG_MESSAGE, "Appending associated use policy.")
                    req.headers_out['x-use-policy'] = \
                        str(self.policies[requested_uri]['use_policy'])
                
                # 3. Run the AIR Reasoner over the policy and identity.
                req_context = self.log_request(requested_uri, client.id,
                                               taac.util.REQ_AUTH_SUCCESS)
                testPolicy = policyrunner.runPolicy
                pdebug(DEBUG_MESSAGE, "Reasoning over log and policy.")
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
                    pdebug(DEBUG_MESSAGE, "Access not compliant with policy.")
                    self.log_completed_request(requested_uri, conclusion,
                                               taac.util.COMPLETE_ACC_DENIED)
                    return apache.HTTP_FORBIDDEN
                else:
                    pdebug(DEBUG_MESSAGE, "Access compliant with policy.")
                    self.log_completed_request(requested_uri, conclusion,
                                               taac.util.COMPLETE_ACC_GRANTED)
                    return apache.OK
            else:
                # We not good.
                pdebug(DEBUG_MESSAGE, "Signature didn't match!")
                pdebug(DEBUG_WARNING, "Client failed to authenticate with RDFAuth.")
                
                policy = self.policies[requested_uri]
                nonce = self.issue_nonce(q(policy['realm']))
                auth_header = 'TAAC realm="%s",policy="%s",nonce="%s"' % \
                              (q(policy['realm']),
                               q(policy['access_policy']),
                               q(nonce))
                pdebug(DEBUG_MESSAGE,
                       'Requesting authentication: %s' % (auth_header))
                taac.util.request_authentication(req, auth_header)
                
                self.log_request(requested_uri, client.id,
                                 taac.util.REQ_AUTH_FAILED)
                
                return apache.DONE
        
        pdebug(DEBUG_WARNING,
               "Couldn't find public key address in identity-document.")
        policy = self.policies[requested_uri]
        nonce = self.issue_nonce(q(policy['realm']))
        auth_header = 'TAAC realm="%s",policy="%s",nonce="%s"' % \
                      (q(policy['realm']),
                       q(policy['access_policy']),
                       q(nonce))
        pdebug(DEBUG_MESSAGE,
               'Requesting authentication: %s' % (auth_header))
        taac.util.request_authentication(req, self.policies[requested_uri])
        
        # Log this request, but note no public key.
        self.log_request(requested_uri, client.id, taac.util.REQ_NO_AUTH)
        
        return apache.DONE
    
    def check_foaf_ssl(self, req, client, requested_uri):
        # 1.1. Extract URI subjectAltNames from client cert...
        pdebug(DEBUG_MESSAGE, 'Parsing SSL client cert...')
        cert = req.subprocess_env['SSL_CLIENT_CERT']
        cert = "-----BEGIN CERTIFICATE-----\n" + cert + \
               "\n-----END CERTIFICATE-----\n"
        cert = x509.certificate.pem_decode(cert)

        pdebug(DEBUG_MESSAGE, 'Searching for subjectAltName extension...')
        names = extractURISubjectAltNames(cert)

        for name in names:
            pdebug(DEBUG_MESSAGE, 'Checking URI: %s' % (name))

            # 1.2. Try to get the signature associated with the ident doc.
            pdebug(DEBUG_MESSAGE, "Trying to get signature from ident doc...")
            
            # Get the document and parse in the RDF graph...
            if self.store == None:
                store = llyn.RDFStore()
                myStore.setStore(store)
            try:
                context = self.store.load(uri = uripath.splitFrag(name)[0],
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
            
            # And then query for wot:identity and wot:pubkeyAddress properties for
            # the proffered identity fragid.
            authids = context.each(subj=context.newSymbol(name),
                                   pred=context.newSymbol(
                                            taac.namespaces.wot.hasKey))
            authids.extend(context.each(pred=context.newSymbol(
                                                 taac.namespaces.wot.identity),
                                        obj=context.newSymbol(name)))

            # If we find it, check it for one of the signature types.
            for authid in authids:
                if not context.contains(subj=authid,
                                        pred=context.newSymbol(taac.namespaces.rdf.type),
                                        obj=context.newSymbol(taac.namespaces.wot.x509Certificate)):
                    continue
                
                sigType = context.any(subj=authid,
                                      pred=context.newSymbol(
                                               taac.namespaces.wot.sigType))

                if sigType != None:
                    sigType = str(sigType.uriref())

                    if sigType == taac.namespaces.wot.md5WithRSAEncryption or \
                       sigType == taac.namespaces.wot.md2WithRSAEncryption or \
                       sigType == taac.namespaces.wot.sha1WithRSAEncryption or\
                       sigType == taac.namespaces.wot.sha1WithDSAEncryption:
                        # 2. Get the sig and check it against the cert.
                        sig = context.any(subj=authid,
                                          pred=context.newSymbol(
                                                 taac.namespaces.wot.sigValue))
                        sig = str(sig).replace(':', '')
                        sig = sig.replace(' ', '')

                        sig = a2b_hex(sig)
                        if sig == cert.signature.value()[0]:
                            # Alright.  Pretty sure we have a match.  It's OK.
                            pdebug(DEBUG_MESSAGE, "Signature matched!")
                            if self.policies[requested_uri].has_key('use_policy'):
                                pdebug(DEBUG_MESSAGE, "Appending associated use policy.")
                                req.headers_out['x-use-policy'] = \
                                    str(self.policies[requested_uri]['use_policy'])

                            # 3. Run the AIR Reasoner over the policy and identity.
                            req_context = self.log_request(requested_uri, name,
                                                           taac.util.REQ_AUTH_SUCCESS)
                            testPolicy = policyrunner.runPolicy
                            pdebug(DEBUG_MESSAGE, "Reasoning over log and policy.")
                            (conclusion, context) = testPolicy(
                                [uripath.splitFrag(name)[0]],
                                [uripath.splitFrag(self.policies[requested_uri]['access_policy'])[0]],
                                req_context.n3String())
                            
                            # 4. Make the return based on what the reasoner concluded.

                            pdebug(DEBUG_MESSAGE, conclusion.n3String())

                            pdebug(DEBUG_MESSAGE, taac.namespaces.air['compliant-with'])
                            pdebug(DEBUG_MESSAGE, self.policies[requested_uri]['access_policy'])
                            compliance = conclusion.any(
                                pred=conclusion.newSymbol(taac.namespaces.air['compliant-with']),
                                obj=conclusion.newSymbol(self.policies[requested_uri]['access_policy']))

                            pdebug(DEBUG_MESSAGE, str(compliance))
                            
                            # If compliance is not explicit, then it's not.
                            if compliance == None:
                                # Log access denied.
                                pdebug(DEBUG_MESSAGE, "Access not compliant with policy.")
                                self.log_completed_request(requested_uri, conclusion,
                                                           taac.util.COMPLETE_ACC_DENIED)
                                return apache.HTTP_FORBIDDEN
                            else:
                                pdebug(DEBUG_MESSAGE, "Access compliant with policy.")
                                self.log_completed_request(requested_uri, conclusion,
                                                           taac.util.COMPLETE_ACC_GRANTED)
                                return apache.OK
                        else:
                            # We don't have a match!
                            pdebug(DEBUG_MESSAGE, "Signature didn't match!")
                            pdebug(DEBUG_WARNING, "Client failed to authenticate with FOAF+SSL.")
                            self.log_completed_request(requested_uri, None,
                                                       taac.util.COMPLETE_ACC_DENIED)
                            return apache.HTTP_FORBIDDEN
                    else:
                        # Don't support it.
                        pdebug(DEBUG_WARNING, "Client offered certificate with unsupported signature type.")
                        self.log_completed_request(requested_uri, None,
                                                   taac.util.COMPLETE_ACC_DENIED)
                        return apache.HTTP_FORBIDDEN
                else:
                    pdebug(DEBUG_WARNING, "Can't find signature type in identity-document.")
                    self.log_completed_request(requested_uri, None,
                                               taac.util.COMPLETE_ACC_DENIED)
                    return apache.HTTP_FORBIDDEN
            pdebug(DEBUG_WARNING, "Can't find certificate signature in identity-document.")
            self.log_completed_request(requested_uri, None,
                                       taac.util.COMPLETE_ACC_DENIED)
            return apache.HTTP_FORBIDDEN
        pdebug(DEBUG_WARNING, "Can't find subjectAltName referencing identity-document.")
        self.log_completed_request(requested_uri, None,
                                   taac.util.COMPLETE_ACC_DENIED)
        return apache.HTTP_FORBIDDEN

    def prepare_openid(self, req, client, requested_uri):
        'Performs initialization of OpenID authentication.'

        pdebug(DEBUG_MESSAGE, 'Preparing OpenID session...')

        # 1.1. Try to get the OpenID associated with the ident doc.
        pdebug(DEBUG_MESSAGE, "Trying to get client's claimed OpenID.")
        
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
            pdebug(DEBUG_WARNING, "Couldn't find OpenID in identity-document.")
            policy = self.policies[requested_uri]
            nonce = self.issue_nonce(q(policy['realm']))
            auth_header = 'TAAC realm="%s",policy="%s",nonce="%s"' % \
                          (q(policy['realm']),
                           q(policy['access_policy']),
                           q(nonce))
            pdebug(DEBUG_MESSAGE,
                   'Requesting authentication: %s' % (auth_header))
            taac.util.request_authentication(req, self.policies[requested_uri])
            
            # Log this request, but note no openid.
            self.log_request(requested_uri, client.id, taac.util.REQ_NO_AUTH)
            
            return apache.DONE
        
        # Save the openid server...
        authid = str(authid.uriref())
        
        # 2. Authenticate the OpenID...
        pdebug(DEBUG_MESSAGE, "Authenticating the OpenID...")
        openid = Consumer({'client': client},
                          FileOpenIDStore(taac.config.OPENID_CACHE_DIRECTORY))
        auth_req = openid.begin(authid)
        
        if req.args != None:
            params = util.parse_qs(req.args)
        else:
            params = {}
        params = dict(zip(params.keys(),
                          map(lambda x: (x[0]), params.values())))

        # TODO: Move ALL parameters to the requested_uri.
        
        # If we have taac_profile=1, make sure we profile when we return.
        if params.has_key('taac_profile') and params['taac_profile'] == '1':
            requested_uri = requested_uri + '?taac_profile=1'
        redir = auth_req.redirectURL(requested_uri, requested_uri)
        
        # Log this request, but note incomplete
        self.log_request(requested_uri, client.id, taac.util.REQ_INCOMPLETE)
        
        # We actually die here, redirecting to the OpenID server.
        req.headers_out['location'] = redir

        pdebug(DEBUG_MESSAGE, "Here comes the redirect.")
        
        return apache.HTTP_MOVED_TEMPORARILY

    def continue_openid(self, req, client, requested_uri, params):
        'Processes the continuation of an OpenID authentication.'
        
        pdebug(DEBUG_MESSAGE, 'Continuing OpenID session...')

        # We have a continuation of an OpenID authentication.
        openid = Consumer({'identity': client},
                          FileOpenIDStore(taac.config.OPENID_CACHE_DIRECTORY))
        openid_resp = openid.complete(params, requested_uri)
        
        # TODO: Handle SETUP_NEEDED?
        if openid_resp.status != SUCCESS:
            # If the identity refuses to authenticate, return a 401
            pdebug(DEBUG_WARNING, "Client failed to authenticate with OpenID.")
            
            policy = self.policies[requested_uri]
            nonce = self.issue_nonce(q(policy['realm']))
            auth_header = 'TAAC realm="%s",policy="%s",nonce="%s"' % \
                          (q(policy['realm']),
                           q(policy['access_policy']),
                           q(nonce))
            pdebug(DEBUG_MESSAGE,
                   'Requesting authentication: %s' % (auth_header))
            taac.util.request_authentication(req, auth_header)
            
            self.log_request(requested_uri, client.id,
                             taac.util.REQ_AUTH_FAILED)
            
            return apache.DONE
        
        if self.policies[requested_uri].has_key('use_policy'):
            pdebug(DEBUG_MESSAGE, "Appending associated use policy.")
            req.headers_out['x-use-policy'] = \
                str(self.policies[requested_uri]['use_policy'])

        # 3. Run the AIR Reasoner over the policy and identity.
        req_context = self.log_request(requested_uri, client.id,
                                  taac.util.REQ_AUTH_SUCCESS)
        testPolicy = policyrunner.runPolicy
        pdebug(DEBUG_MESSAGE, "Reasoning over log and policy.")
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
            pdebug(DEBUG_MESSAGE, "Access not compliant with policy.")
            self.log_completed_request(requested_uri, conclusion,
                                       taac.util.COMPLETE_ACC_DENIED)
            return apache.HTTP_FORBIDDEN
        else:
            pdebug(DEBUG_MESSAGE, "Access compliant with policy.")
            self.log_completed_request(requested_uri, conclusion,
                                       taac.util.COMPLETE_ACC_GRANTED)
            return apache.OK
    
    def allow_access(self, req):
        'Determines whether the request should be allowed access.'
        
        # This way, we can do something about errors...
        req.content_type = 'text/plain'
        
        # Load the policies.
        if self.policies == None:
            self.load_policies(req)
        
        # Get the requested file.
        requested_file = uripath.refTo(self.base_path, req.filename)
        
        # requested_file is now relative within the server hierarchy.  Hope
        # that's the same as the local hierarchy!
        
        # Does the requested file exist?
        if not os.path.exists(requested_file):
            # TODO: Do we want to log this event?
            pdebug(DEBUG_WARNING,
                   "Requested file '%s' not found for access control." %
                   (requested_file))
            return apache.HTTP_NOT_FOUND
        
        # Let's canonicalize requested_file's URI.
        requested_uri = uripath.join(self.base_uri, requested_file)
        
        # Is it covered by a policy?
        if self.policies.has_key(requested_uri):
            # Send the 401 error if we are and no proof was sent
            pdebug(DEBUG_MESSAGE,
                   "Attempted access to '%s', a protected file." %
                   (requested_uri))
            
            # Parse the Authorization header.
            auth_header = self.get_auth_header(req)

            # TODO: More general protection without AC elements.

            if self.policies[requested_uri].has_key('access_policy') and \
                   (auth_header == None \
                    or not auth_header.params.has_key('identity-document')) \
                    and not req.subprocess_env.has_key('SSL_CLIENT_CERT'):
                # No Authorization or identity proffered?  Then send the 401.
                pdebug(DEBUG_MESSAGE,
                       'No Authorization/identity-document offered.')
                policy = self.policies[requested_uri]
                nonce = self.issue_nonce(q(policy['realm']))
                auth_header = 'TAAC realm="%s",policy="%s",nonce="%s"' % \
                              (q(policy['realm']),
                               q(policy['access_policy']),
                               q(nonce))
                pdebug(DEBUG_MESSAGE,
                       'Requesting authentication: %s' % (auth_header))
                taac.util.request_authentication(req, auth_header)
                
                # Log this request with no identity.
                self.log_request(requested_uri, None, taac.util.REQ_NO_ID)
                
                return apache.DONE
            else:
                # Otherwise, we need to check that the identity satisfies the
                # policy.  If it doesn't we return a 403.  This is a multi-part
                # process...
                pdebug(DEBUG_MESSAGE,
                       'Authorization/identity-document offered.')

                # Load the parameters from the query.
                if req.args != None:
                    params = util.parse_qs(req.args)
                else:
                    params = {}
                params = dict(zip(params.keys(),
                                  map(lambda x: (x[0]), params.values())))
                
                # 1. Construct the proffered identity from the ident document.
                pdebug(DEBUG_MESSAGE, 'Constructing client identity...')
                client = taac.util.Client()
                if auth_header != None and \
                       auth_header.params.has_key('identity-document'):
                    client.id = auth_header.params['identity-document']
                    if client.id != None:
                        client.id = client.id[0]
                    pdebug(DEBUG_MESSAGE, 'identity-document: ' + client.id)
                # The id parameter is a synonym for identity-document for
                # RDFAuth
                # See: http://blogs.sun.com/bblfish/entry/rdfauth_sketch_of_a_buzzword
                elif auth_header!= None and \
                         auth_header.params.has_key('id'):
                    client.id = auth_header.params['id']
                    if client.id != None:
                        client.id = client.id[0]
                    pdebug(DEBUG_MESSAGE, 'identity-document: ' + client.id)
                if auth_header != None and \
                       auth_header.params.has_key('credential-document'):
                    client.credentials = \
                        auth_header.params['credential-document']
                    if client.credentials != None:
                        client.credentials = client.credentials[0]

                # Before ANYTHING else, we should assume we aren't needing
                # to use OpenID for authentication.  Right now, check for
                # RDFAuth.
                if auth_header != None and \
                   auth_header.params.has_key('key') and \
                   auth_header.params.has_key('nonce') and \
                   auth_header.params.has_key('realm'):
                    return self.check_rdfauth(req, client, requested_uri,
                                              auth_header.params['realm'][0],
                                              auth_header.params['nonce'][0],
                                              auth_header.params['key'][0])
                # TODO: Do we have a certificate thanks to a TLS handshake?
                if req.subprocess_env.has_key('SSL_CLIENT_CERT'):
                    return self.check_foaf_ssl(req, client, requested_uri)
                # If we don't have the openid.mode header, then we need to set
                # up.  We clearly don't have the OpenID session ready.  When
                # the session is ready and we've got an OpenID login, we can
                # try again.
                elif not params.has_key('openid.mode'):
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
    pdebug(DEBUG_MESSAGE, 'Building TAAC script URI.')
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

    # And try checking for valid access.
    try:
        retval = server.allow_access(req)
    except apache.SERVER_RETURN, http_error:
        retval = http_error

    return retval

DEBUG_OFF     = 0
DEBUG_ERROR   = 0
DEBUG_ON      = 1
DEBUG_WARNING = 1
DEBUG_MESSAGE = 2
DEBUG_LEVEL = DEBUG_MESSAGE

def accesshandler(req):
    'This is just a wrapper so that we can optionally profile.'

    # Reload the custom modules to ensure that changes are represented.
    if DEBUG_LEVEL > 0:
        taac.config = reload(taac.config)
        taac.namespaces = reload(taac.namespaces)
        taac.util = reload(taac.util)

    # Generate a UUID for each profiled-run.
    uuid = uuid1()

    # Initialize the array of parameters passed with this request.
    if req.args != None:
        params = util.parse_qs(req.args)
    else:
        params = {}
    
    # Only pay attention to the first item in each parameter.
    params = dict(zip(params.keys(), map(lambda x: (x[0]), params.values())))
    
    # If we have taac_profile=1, profile...  Otherwise, just run it.
    presult = None
    if params.has_key('taac_profile') and params['taac_profile'] == '1':
        pdebug(DEBUG_MESSAGE, 'TAAC profiling requested...')
        pobject = hotshot.Profile("/tmp/Profiler." + uuid.hex + ".prof")
        presult = pobject.runcall(do_access, req)
        
        # Append the UUID so we can track the request.
        req.headers_out['x-taac-profile-id'] = uuid.hex
    else:
        presult = do_access(req)

    return presult
