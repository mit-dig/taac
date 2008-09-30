'''
pkcs1.py

An implementation of the PKCS#1 standard for RSA cryptography and public-key
encryption and signature constructions.  Based on RFC 3447.  If the asn_1 
'''

__all__ = [
  'rsa_private_key', 'rsa_public_key',
  'encryption_scheme', 'oaep_encryption_scheme', 'pkcs1_v1_5_encryption_scheme',
  'signature_scheme',   'pss_signature_scheme',  'pkcs1_v1_5_signature_scheme',
  'decryption_error', 'signature_verify_error',
  'mask_generation_function_1',

  'integer_to_octet_string', 'octet_string_to_integer',

  'i2osp', 'os2ip', 'rsaep', 'rsadp', 'rsasp1', 'rsavp1',
  'rsaes_oaep_encrypt', 'rsaes_oaep_decrypt',
  'rsaes_pkcs1_v1_5_encrypt', 'rsaes_pkcs1_v1_5_decrypt',
  'rsassa_pss_sign', 'rsassa_pss_verify',
  'rsassa_pkcs1_v1_5_sign', 'rsassa_pkcs1_v1_5_verify',

  'oid_pkcs1', 'oid_rsa_encryption', 'oid_id_mgf1',
  'oid_id_sha1',
]

import asn1
from math import log, ceil
from binascii import a2b_hex, b2a_hex
import struct


# Module internal helpers.
log2 = log( 2.0 )
def long_bits( n ):
  'Return the length of a positive long integer in bits.'
  return int( ceil( log( n ) / log2 ) )

def octets_xor( a, b ):
  'XOR together two octet strings.'
  assert len( a ) == len( b )
  out = ''
  for i in xrange( len(a) ):
    out += chr( ord(a[i]) ^ ord(b[i]) )
  return out


# PKCS#1 integer encoding primitives.
def integer_to_octet_string( long_integer, block_size ):
  '''PKCS#1's I2OSP: convert a long integer into an octet string.'''
  hex_string = '%X' % long_integer
  if len( hex_string ) > 2 * block_size:
    raise ValueError( 'integer %i too large to encode in %i octets' % ( long_integer, block_size ) )
  return a2b_hex( hex_string.zfill( 2 * block_size ) )

def octet_string_to_integer( octet_string ):
  '''PKCS#1's O2ISP: convert an octet string to a long integer.'''
  return long( b2a_hex( octet_string ), 16 )



class rsa_key( object ):
  '''Base class for RSA public and private keys.  Provides accessors for the
  public key parameters.'''

  def __init__( self, n, e ):
    self.n, self.e = n, e
    self._modulus_bits = None

  def rsa_modulus( self ):
    return self.n

  def rsa_public_exponent( self ):
    return self.e

  def modulus_bits( self ):
    'Returns the number of bits in the modulus N.'
    if self._modulus_bits is None:
      self._modulus_bits = long_bits( self.n )
    return self._modulus_bits

  def modulus_octets( self ):
    'Returns the number of octets required to encode the modulus N.'
    return ( self.modulus_bits() + 7 ) / 8

  def signature_octets( self ):
    'Returns the number of octets required to encode a signature.'
    return self.modulus_octets()

  def ciphertext_octets( self ):
    'Returns the number of octets required to encode a ciphertext.'
    return self.modulus_octets()

  def message_bits( self ):
    '''Returns the number of bits that can be recovered by a private key
    operation.  For RSA, this is one less than the number of bits in the
    modulus.'''
    return self.modulus_bits() - 1

  def message_octets( self ):
    '''Returns the number of octets required to encode a message, based on
    `message_bits`.'''
    return ( self.message_bits() + 7 ) / 8




class rsa_public_key( rsa_key ):
  '''Encapsulates an RSA keypair's public parameters N and E.'''

  def _operate( self, z ):
    'Internal method: perform a public key operation on a number.'
    return pow( z, self.e, self.n )

  def encrypt_primitive( self, m ):
    '''PKCS#1's RSAEP: produces a ciphertext representative number from a
    message representative number.'''
    if not 0 <= m < self.n:
      raise ValueError( 'message representative %i out of range [0,%i)' % ( m, self.n ) )
    return self._operate( m )

  def verify_primitive( self, s ):
    '''PKCS#1's RSAVP1: recover a message representative number from a
    signature representative number.'''
    if not 0 <= s < self.n:
      raise ValueError( 'signature representative %i out of range [0,%i)' % ( s, self.n ) )
    return self._operate( s )


  def encrypt_primitive_octets( self, message_octets ):
    '''octets -> number -> encrypt -> number -> octets'''
    m = octet_string_to_integer( message_octets )
    c = self.encrypt_primitive( m )
    return integer_to_octet_string( c, self.modulus_octets() )

  def verify_primitive_octets( self, signature_octets ):
    '''octets -> number -> verify -> number -> octets'''
    s = octet_string_to_integer( signature_octets )
    m = self.verify_primitive( s )
    return integer_to_octet_string( m, self.message_octets() )

  # Compare public keys for equality.
  def __eq__( self, other ):
    if isinstance( other, rsa_public_key ):
      return     ( other.n == self.n and other.e == self.e )
    else:
      return NotImplemented
  def __ne__( self, other ):
    if isinstance( other, rsa_public_key ):
      return not ( other.n == self.n and other.e == self.e )
    else:
      return NotImplemented

  @classmethod
  def construct( cls, n, e ):
    'Contruct a public key from the public parameters N and E.'
    return cls( long(n), long(e) )

  def der_encode( self ):
    seq = asn1.sequence(( asn1.integer( self.n ), asn1.integer( self.e ) ))
    return seq.der_encode()

  @classmethod
  def der_decode( cls, der_octets ):
    seq, rest = asn1.der_decode( der_octets )
    assert rest == ''
    n, e = seq
    return cls.construct( n, e )




class rsa_private_key( rsa_key ):
  '''Encapsulates an RSA private key.  Uses the simpler (N,D) representation
  instead of the more efficient prime-factors representation.'''

  def __init__( self, n, e, d ):
    super( rsa_private_key, self ).__init__( n, e )
    self.d = d

  def public_key( self ):
    'Return the public key for this private key.'
    pub = rsa_public_key( self.n, self.e )
    pub._modulus_bits = self._modulus_bits
    return pub


  def _operate( self, z ):
    'Internal method: perform a private key operation on a number.'
    return pow( z, self.d, self.n )

  def decrypt_primitive( self, c ):
    '''PKCS#1's RSADP: calculates a plaintext message representative number
    from the ciphertext representative number.'''
    if not 0 <= c < self.n:
      raise ValueError( 'ciphertext representative %i out of range [0,%i)' % ( c, self.n ) )
    return self._operate( c )

  def sign_primitive( self, m ):
    '''PKCS#1's RSASP1: produce a signature representative number from the
    message representative number.'''
    if not 0 <= m < self.n:
      raise ValueError( 'message representative %i out of range [0,%i)' % ( m, self.n ) )
    return self._operate( m )


  def decrypt_primitive_octets( self, ciphertext_octets ):
    '''octets -> number -> decrypt -> number -> octets'''
    c = octet_string_to_integer( ciphertext_octets )
    m = self.decrypt_primitive( c )
    return integer_to_octet_string( m, self.message_octets() )

  def sign_primitive_octets( self, message_octets ):
    '''octets -> number -> sign -> number -> octets'''
    m = octet_string_to_integer( message_octets )
    s = self.sign_primitive( m )
    return integer_to_octet_string( s, self.modulus_octets() )


  @classmethod
  def construct( cls, n, e, d,
                 p = None, q = None, d_p = None, d_q = None, q_inv = None,
                 extra_factors = () ):
    '''Construct a private key from the public paramters N and E and the
    private parameter D.'''
    if p is None:
      return cls( long(n), long(e), long(d) )
    else:
      assert q is not None 
      assert d_p is not None 
      assert d_q is not None 
      assert q_inv is not None
      return rsa_private_key_factors.construct( n, e, d, p, q, d_p, d_q, q_inv,
                                                extra_factors )

  @classmethod
  def generate( cls, bits, random_generator = None ):
    # XXX replace this all with homebrew, or continue to depend on the Crypto
    # package?
    if random_generator is None:
      if not hasattr( cls, 'random_pool' ):
        from Crypto.Util.randpool import RandomPool
        cls.random_pool = RandomPool()
      random_generator = cls.random_pool.get_bytes

    from Crypto.PublicKey import RSA
    key = RSA.generate( bits, random_generator )
    return cls.construct( key.n, key.e, key.d )

  def pem_encode( self ):
    raise NotImplementedError( 'need to compute p,q,etc from d' )

  @staticmethod
  def pem_decode( pem_text ):
    return rsa_private_key_factors.pem_decode( pem_text )


class rsa_private_key_factors( rsa_private_key ):

  def __init__( self, n, e, d, p, q, d_p, d_q, q_inv, extra_factors = () ):
    super( rsa_private_key_factors, self ).__init__( n, e, d )
    self.p, self.q, self.d_p, self.d_q, self.q_inv = p, q, d_p, d_q, q_inv
    self.extra_factors = extra_factors

    if __debug__:
      n_check = p * q
      lambda_n = (p-1) * (q-1)
      for r_i, d_i, t_i in extra_factors:
        n_check  *= r_i
        lambda_n *= r_i - 1
      assert n == n_check

      # Note that lambda_n should be the LCM of r_i-1, but is calculated here
      # as the product.  This should work in the common case, but may break.
      assert (e * d) % lambda_n == 1

      assert (e * d_p) % (p-1) == 1
      assert (e * d_q) % (q-1) == 1
      assert (q * q_inv) % p == 1

      R_i = p * q
      for r_i, d_i, t_i in extra_factors:
        assert (e * d_i) % (r_i-1) == 1
        assert (R_i * t_i) % r_i == 1
        R_i *= r_i


  def _operate( self, z ):
    'Internal method: perform a private key operation on a number.'
    m_1 = pow( z, self.d_p, self.p )
    m_2 = pow( z, self.d_q, self.q )
    h = ( ( m_1 - m_2 ) * self.q_inv ) % self.p
    m = m_2 + self.q * h

    if len( self.extra_factors ) > 0:
      R = p * q
      for r_i, d_i, t_i in self.extra_factors:
        m_i = pow( z, d_i, r_i )
        h = ( ( m_i - m ) * t_i ) % r_i
        m += R * h
        R *= r_i

    return m


  @classmethod
  def construct( cls, n, e, d, p, q, d_p, d_q, q_inv, extra_factors = ()  ):
    '''Construct a private key from the public paramters N and E and the
    private parameters D, P, Q, dP, dQ, qInv, and (r_i,d_i,t_i).'''
    ef = [( long(r_i), long(d_i), long(t_i) ) for r_i,d_i,t_i in extra_factors]
    return cls( long(n), long(e), long(d),
                long(p), long(q), long(d_p), long(d_q), long(q_inv), ef )

  @classmethod
  def generate( cls, bits, random_generator = None ):
    # XXX replace this all with homebrew
    raise NotImplementedError()

  def pem_encode( self ):
    raise NotImplementedError( 'need to compute p,q,etc from d' )

  @classmethod
  def pem_decode( cls, pem_text ):
    asn1_object, = asn1.pem_decode( pem_text, 'RSA PRIVATE KEY',
                                    der_strict = False )
    version = int( asn1_object[0] )
    assert version == 0
    ver, n, e, d, p, q, d_p, d_q, q_inv = asn1_object
    # XXX extend to handle version 1

    return cls.construct( n, e, d, p, q, d_p, d_q, q_inv )





class encryption_scheme( object ):
  '''Abstract base class for encryption schemes, which encapsulate a key type
  and an encoding method.'''

  # Virual methods --- should be overridden by subclasses (encoding methods).
  def __init__( self ):
    raise NotImplementedError()

  def encode( self, message, encoded_message_bits ):
    raise NotImplementedError()

  def decode( self, encoded_message, encoded_message_bits ):
    raise NotImplementedError()

  # Key-encapsulating constructors.
  def public_key( self, key ):
    '''Take a primitive public key and return a message-encrypting public key
    with an 'encrypt' method.'''
    return encryption_public_key( self, key )

  def private_key( self, key ):
    '''Take a primitive private key and return a message-decrypting private key
    with a 'decrypt' method.'''
    return encryption_private_key( self, key )

  # Client methods, which may also be accessed via encapsulated keys.
  def encrypt( self, key, message ):
    'Encrypt the `message` (a short string of octets).'
    encoded_message = self.encode( message, key.message_bits() )
    return key.encrypt_primitive_octets( encoded_message )

  def decrypt( self, key, ciphertext ):
    'Decrypt the `ciphertext` (a short string of octets).'
    if len( ciphertext ) != key.ciphertext_octets():
      raise ValueError( 'expected ciphertext of length %i octets, got %i octets instead' % ( key.ciphertext_octets(), len( ciphertext ) ) )
    encoded_message = key.decrypt_primitive_octets( ciphertext )
    return self.decode( encoded_message, key.message_bits() )


class encryption_public_key( object ):
  '''Encapsulates a public key which can be used to encrypt a message of octets
  to the holder of the private key.'''

  def __init__( self, scheme, key ):
    self.scheme, self.key = scheme, key

  def encrypt( self, message ):
    'Encrypt the `message` (a short string of octets).'
    return self.scheme.encrypt( self.key, message )


class encryption_private_key( object ):
  '''Encapsulates a private key which can be used to decrypt a ciphertext of
  octets encrypted using the corresponding public key.'''

  def __init__( self, scheme, key ):
    self.scheme, self.key = scheme, key

  def decrypt( self, ciphertext ):
    'Decrypt the `ciphertext` (a short string of octets).'
    return self.scheme.decrypt( self.key, ciphertext )


class decryption_error( ValueError ):
  '''Raised to signify an invalid ciphertext.  Important note: specific
  information about the kind of decryption error, such as that given by the
  text of the exception, MUST NOT be revealed to any external entity.  This is
  because an adversary who can distinguish between decryption errors can mount
  a chosen-ciphertext attack against the private key.'''
  def __init__( self, text, encoded_message = None ):
    ValueError.__init__( self, text )
    self.encoded_message = encoded_message



class oaep_encryption_scheme( encryption_scheme ):
  '''The Optimal Asymmetric Encryption Padding encryption scheme recommended by
  PKCS#1 v2.1.'''

  def __init__( self, generate_random_octets, hash, mask_generation_function = None, label = '' ):
    self.generate_random_octets = generate_random_octets
    self.hash = hash
    self.mgf = mask_generation_function
    self.label = label
    if self.mgf is None:
      self.mgf = mask_generation_function_1( hash )
    self.label_hash = hash.new( label ).digest()

  def encode( self, message, encoded_message_bits ):
    '''Apply EME-OAEP encoding.'''

    # Step 1b: check message length.
    hash_octets = len( self.label_hash )
    encoded_message_octets = encoded_message_bits/8 + 1 # parameter 'k'
    pad_octets = encoded_message_octets - len( message ) - 2 * hash_octets - 2
    if pad_octets < 0:
      raise ValueError( 'message too long: expected %i octets or less, got %i octets' % ( encoded_message_octets - 2*hash_octets - 2, len( message ) ) )

    # Steps 2b,c: pad message to form data block DB.
    data_block = self.label_hash + ( '\x00' * pad_octets ) + '\x01' + message

    # Step 2d: generate a random seed for the data block mask.
    seed = self.generate_random_octets( hash_octets )

    # Steps 2e,f: mask the data block by XORing with the seeded MGF output.
    db_mask = self.mgf( seed, len( data_block ) )
    masked_db = octets_xor( data_block, db_mask )

    # Steps 2g,h: mask the seed by XORing with newly-seeded MGF output.
    seed_mask = self.mgf( masked_db, hash_octets )
    masked_seed = octets_xor( seed, seed_mask )

    # Step 2i: construct the encoded message.
    return '\x00' + masked_seed + masked_db

  def decode( self, encoded_message, encoded_message_bits ):
    '''Remove EME-OAEP encoding.  Raises `decryption_error` on failure.  An
    adversary must not be able to distinguish between different kinds of
    `decryption_error`.'''

    # Step 1c: check message length for consistency.
    hash_octets = len( self.label_hash )
    encoded_message_octets = encoded_message_bits/8 + 1 # parameter 'k'
    if encoded_message_octets < 2 * hash_octets + 2:
      raise decryption_error( 'inconsistent encryption scheme: message length %i too short for OAEP encoding' % encoded_message_octets )

    # Fix up message if len( encoded_message ) = k - 1
    if encoded_message_bits % 8 == 0:
      encoded_message = '\x00' + encoded_message

    # Step 3b: decompose the encoded message.
    zero_octet  = encoded_message[ 0 ]
    masked_seed = encoded_message[ 1 : hash_octets+1 ]
    masked_db   = encoded_message[ hash_octets+1 : ]

    # Steps 3c,d: extract the seed.
    seed_mask = self.mgf( masked_db, hash_octets )
    seed = octets_xor( masked_seed, seed_mask )

    # Steps 3e,f: extract the data block.
    db_mask = self.mgf( seed, len( masked_db ) )
    data_block = octets_xor( masked_db, db_mask )

    # Step 3g: decompose the data block and check consistency.
    label_hash        = data_block[ : hash_octets ]
    delimited_message = data_block[ hash_octets : ].lstrip( '\x00' )
    if delimited_message[0] != '\x01':
      raise decryption_error( 'malformed ciphertext: could not find padding-delimiter 0x01 octet', encoded_message )
    if label_hash != self.label_hash:
      raise decryption_error( 'malformed ciphertext: message has wrong label', encoded_message )
    if zero_octet != '\x00':
      raise decryption_error( 'malformed ciphertext: initial octet of decryption is not zero', encoded_message )

    return delimited_message[ 1: ]



class pkcs1_v1_5_encryption_scheme( encryption_scheme ):
  '''The backward-compatible encryption scheme specified as PKCS1-v1_5 in
  PKCS#1 v2.1.  Due to certain weaknesses, generally not recommended for new
  applications.'''

  def __init__( self, generate_random_octets ):
    self.generate_random_octets = generate_random_octets

  def encode( self, message, encoded_message_bits ):
    '''Apply EME-PKCS1-v1_5 encoding.'''

    # Step 1: check message length.
    encoded_message_octets = encoded_message_bits/8 + 1 # parameter 'k'
    pad_octets = encoded_message_octets - len( message ) - 3
    if pad_octets < 8:
      raise ValueError( 'message too long: expected %i octets or less, got %i octets' % ( encoded_message_octets - 11, len( message ) ) )

    # Step 2a: generate random padding.
    padding = self.generate_random_octets( pad_octets )
    while padding.find( '\x00' ) != -1:
      padding = padding.replace( '\x00', self.generate_random_octets( 1 ), 1 )

    # Step 2b: construct and return the encoded message.
    return '\x00\x02' + padding + '\x00' + message

  def decode( self, encoded_message, encoded_message_bits ):
    '''Remove EME-PKCS1-v1_5 encoding.  Raises `decryption_error` on failure.
    An adversary must not be able to distinguish between different kinds of
    `decryption_error`.'''

    # Step 1: check ciphertext length for consistency.
    encoded_message_octets = encoded_message_bits/8 + 1 # parameter 'k'
    if encoded_message_octets < 11:
      raise decryption_error( 'inconsistent encryption scheme: message length %i too short for OAEP encoding' % encoded_message_octets )

    # Fix up message if len( encoded_message ) = k - 1
    if encoded_message_bits % 8 == 0:
      encoded_message = '\x00' + encoded_message

    # Step 3: decompose the encoded message by searching for the delimiters.
    try:
      padding, message = encoded_message[2:].split( '\x00', 1 )
    except ValueError:
      raise decryption_error( 'malformed ciphertext: could not find padding-delimiter 0x00 octet', encoded_message )
    if len( padding ) < 8:
      raise decryption_error( 'malformed ciphertext: padding is too short (expected 8 octets, got %i octets)' % len( padding ), encoded_message )
    if encoded_message[0:2] != '\x00\x02':
      raise decryption_error( 'malformed ciphertext: incorrect header octets, expected 0x00 0x02', encoded_message )

    return message






class signature_scheme( object ):
  '''Abstract base class for signature schemes with appendix.'''

  # Virtual methods, should be overridden by subclasses (encoding methods).
  def __init__( self ):
    raise NotImplementedError()

  def encode( self, message, encoded_message_bits ):
    raise NotImplementedError()

  def verify_encoded( self, message, encoded_message, encoded_message_bits ):
    raise NotImplementedError()

  # Constructors for encapsulating keys.
  def public_key( self, key ):
    '''Take a primitive public key and return a signature-verifying public key
    with a `verify` method.'''
    return signature_public_key( self, key )

  def private_key( self, key ):
    '''Take a primitive private key and return a message-signing private key
    with a `sign` method.'''
    return signature_private_key( self, key )

  # Client methods.  May also be accessed via encapsulated key objects.
  def sign( self, key, message ):
    'Generate a signature on `message` (a sequence of strings of octets).'
    if isinstance( message, basestring ): message = ( message, )
    encoded_message = self.encode( message, key.message_bits() )
    return key.sign_primitive_octets( encoded_message )

  def verify( self, key, message, signature ):
    '''Check `signature` (a string of octets) on `message` (a sequence of
    strings of octets).  Raise `signature_verify_error` if the signature isn't
    valid.'''
    if isinstance( message, basestring ): message = ( message, )
    # First check signature length.  This check isn't really necessary for
    # security, but is specified by PKCS#1.
    if len( signature ) != key.signature_octets():
      raise signature_verify_error(
        'signature is incorrect length (expected %i octets)'
        % key.signature_octets(),
        message, signature, key )
    # Perform a private-key operation to decode the signature.
    try:
      encoded_message = key.verify_primitive_octets( signature )
    except ValueError, x:
      raise signature_verify_error( 'error decoding signature: %s' % x,
                                    message, signature, key )
    # Check that the decoded signature is consistent with the message.
    self.verify_encoded( message, encoded_message, key.message_bits() )


class signature_private_key( object ):
  '''Encapsulates a private key which can be used to generate digital
  signatures on messages of octets.'''

  def __init__( self, scheme, key ):
    self.scheme, self.key = scheme, key

  def sign( self, message ):
    'Generate a signature on `message` (a sequence of strings of octets).'
    return self.scheme.sign( self.key, message )


class signature_public_key( object ):
  '''Encapsulates a public key which can be used to verify digital signatures
  on messages of octets.'''

  def __init__( self, scheme, key ):
    self.scheme, self.key = scheme, key

  def verify( self, message, signature ):
    '''Check `signature` (a string of octets) on `message` (a sequence of
    strings of octets).  Raise `signature_verify_error` if the signature isn't
    valid.'''
    self.scheme.verify( self.key, message, signature )


class signature_verify_error( ValueError ):
  'Raised to signify an invalid signature.'
  def __init__( self, text, message = None, signature = None, key = None ):
    ValueError.__init__( self, text )
    self.message = message
    self.signature = signature
    self.key = key



class pss_signature_scheme( signature_scheme ):
  '''The Probabilistic Signature Scheme recommended by PKCS#1 v2.1.'''

  def __init__( self, generate_random_octets, hash, mask_generation_function = None, salt_length = None ):
    self.generate_random_octets = generate_random_octets
    self.hash = hash
    self.mgf = mask_generation_function
    self.salt_length = salt_length
    if self.mgf is None:
      self.mgf = mask_generation_function_1( hash )

  def encode( self, message, encoded_message_bits ):
    '''PKCS#1's EMSA-PSS-ENCODE operation.'''

    # Steps 1,2: hash the message.  Iterate through chunks to make it possible
    # to pass in message incrementally --- message could be a generator.
    message_digest = self.hash.new()
    for chunk in message:
      message_digest.update( chunk )
    message_hash = message_digest.digest()

    # Define the salt length as equal to hash length by default.
    salt_length = self.salt_length
    if salt_length is None: salt_length = len( message_hash )

    # Step 3: check that key is long enough for encoded message.
    encoded_message_octets = ( encoded_message_bits + 7 ) / 8
    if encoded_message_octets < len( message_hash ) + salt_length + 2:
      raise ValueError( "encoding error: hash and salt values too long for key" )

    # Step 4: generate a random salt.
    if salt_length == 0:
      salt = ''
    else:
      salt = self.generate_random_octets( salt_length )

    # Steps 5, 6: hash together the message hash and salt with a 8-zero prefix.
    h_digest = self.hash.new()
    h_digest.update( '\x00\x00\x00\x00\x00\x00\x00\x00' )
    h_digest.update( message_hash )
    h_digest.update( salt )
    h = h_digest.digest()

    # Steps 7-10: generate a data-block-mask and XOR it with the encoded salt.
    db_octets = encoded_message_octets - len( message_hash ) - 1
    db_mask = self.mgf( h, db_octets )
    masked_db = db_mask[ :-salt_length-1 ]
    masked_db += octets_xor( db_mask[ -salt_length-1: ], '\x01' + salt )

    # Step 11: clear the top (non-message) bits of the encoded message.
    save_bits = encoded_message_bits % 8
    if save_bits > 0:
      masked_db_first = chr( ord( masked_db[0] ) & ((1 << save_bits) - 1) )
    else:
      masked_db_first = masked_db[0]

    # Steps 12,13: construct and return the encoded message.
    return masked_db_first + masked_db[ 1: ] + h + '\xBC'

  def verify_encoded( self, message, encoded_message, encoded_message_bits ):
    '''PKCS#1's EMSA-PSS-VERIFY operation.  Raises `signature_verify_error` on
    failure.'''

    # Steps 1,2: hash the message.  Iterate through chunks to make it possible
    # to pass in message incrementally --- message could be a generator.
    message_digest = self.hash.new()
    for chunk in message:
      message_digest.update( chunk )
    message_hash = message_digest.digest()
    # Define the salt length as equal to hash length by default.
    salt_length = self.salt_length
    if salt_length is None: salt_length = len( message_hash )

    # Step 3: check that key is long enough for encoded message.
    encoded_message_octets = ( encoded_message_bits + 7 ) / 8
    if encoded_message_octets < len( message_hash ) + salt_length + 2:
      raise signature_verify_error( 'encoding error: hash and salt values too long for key', message )

    # Steps 4,5,6: decompose encoded message.
    if encoded_message[-1] != '\xBC':
      raise signature_verify_error( 'encoding error: expected signature to end with octet 0xBC', message )

    db_octets = encoded_message_octets - len( message_hash ) - 1
    masked_db, h = encoded_message[:db_octets], encoded_message[db_octets:-1]

    # Steps 7-11: extract the salt by XORing with the mask generation function.
    db_mask = self.mgf( h, db_octets )
    save_bits = encoded_message_bits % 8
    if save_bits > 0:
      db_mask_first = chr( ord( db_mask[0] ) & ((1 << save_bits) - 1) )
    else:
      db_mask_first = db_mask[0]
    if db_mask_first + db_mask[1:-salt_length-1] != masked_db[:-salt_length-1]:
      raise signature_verify_error( 'encoding error: expected data block to begin with zero octets', message )
    if ord( db_mask[-salt_length-1] ) ^ ord( masked_db[-salt_length-1] ) != 1:
      raise signature_verify_error( 'encoding error: expected data block to contain octet 0x01 delimiter', message )
    salt = octets_xor( db_mask[-salt_length:], masked_db[-salt_length:] )

    # Steps 12-14: check the message hash and salt against the signed hash.
    h_prime_digest = self.hash.new()
    h_prime_digest.update( '\x00\x00\x00\x00\x00\x00\x00\x00' )
    h_prime_digest.update( message_hash )
    h_prime_digest.update( salt )
    h_prime = h_prime_digest.digest()
    if h_prime != h:
      raise signature_verify_error( 'message hash and salt do not match signed hash', message )

    # Success.
    return



class pkcs1_v1_5_signature_scheme( signature_scheme ):
  '''The backward-compatible signature scheme specified as PKCS1-v1_5 in PKCS#1
  v2.1.'''

  def __init__( self, hash, hash_asn1_oid, hash_asn1_parameters = asn1.null() ):
    self.hash = hash
    self.hash_asn1 = asn1.sequence(( hash_asn1_oid, hash_asn1_parameters ))

  def encode( self, message, encoded_message_bits ):
    '''PKCS#1's EMSA-PKCS1-v1_5-ENCODE operation.'''

    # Step 1: hash the message.
    digest = self.hash.new()
    for chunk in message:
      digest.update( chunk )
    h = digest.digest()

    # Step 2: encode an ASN.1 DigestInfo structure.
    digest_info = asn1.sequence(( self.hash_asn1, asn1.octet_string( h ) ))
    t = digest_info.der_encode()

    # Steps 3-6: construct and return the encoded message.
    encoded_message_octets = ( encoded_message_bits + 7 ) / 8
    pad_octets = encoded_message_octets - len(t) - 3
    if pad_octets < 8:
      raise ValueError( 'encoding error: digest_info structure too long for key' )
    return '\x00\x01' + ( '\xFF' * pad_octets ) + '\x00' + t

  def verify_encoded( self, message, encoded_message, encoded_message_bits ):
    '''Check that the `encoded_message` matches the `message`.  Raise
    `signature_verify_error` on failure.'''
    try:
      encoded_message_expected = self.encode( message, encoded_message_bits )
    except ValueError, x:
      raise signature_verify_error( 'error encoding message digest: %s' % x, message )
    if encoded_message != encoded_message_expected:
      raise signature_verify_error( 'signature value does not match message', message )





def mask_generation_function_1( hash ):
  '''Given a hash class, returns an instance of the PKCS#1 MGF1 function.'''
  def mgf1( seed, length ):
    'Expands a random seed into a pseudorandom string of the requested length.'
    # Pre-hash the seed in case it is long.
    seed_digest = hash.new( seed )

    # Count up, appending hash digests to T.
    t = ''
    counter = 0
    while len( t ) < length:
      try:
        c = struct.pack( '>I', counter )
      except OverflowError:
        raise ValueError( 'requested mask length too long' )

      counter_digest = seed_digest.copy()
      counter_digest.update( c )
      t += counter_digest.digest()

      counter += 1
    
    if len( t ) == length:
      return t
    else:
      return t[ :length ]

  return mgf1




# Define relevant ASN.1 object identifiers.
oid_rsadsi = asn1.oid_iso_us.child( 113549, 'rsadsi' )
oid_pkcs   = oid_rsadsi.child( 1, 'pkcs' )
oid_pkcs1  = oid_pkcs.child( 1, 'pkcs-1' )
oid_digest_algorithm = oid_rsadsi.child( 2, 'digestAlgorithm' )

oid_rsa_encryption = oid_pkcs1.child(  1, 'rsaEncryption' )
oid_id_rsaes_oaep  = oid_pkcs1.child(  7, 'id-RSAES-OAEP' )
oid_id_p_specified = oid_pkcs1.child(  9, 'id-pSpecified' )
oid_id_rsassa_pss  = oid_pkcs1.child( 10, 'id-RSASSA-PSS' )

oid_md2_with_rsa_encryption    = oid_pkcs1.child(  2,    'md2WithRSAEncryption')
oid_md5_with_rsa_encryption    = oid_pkcs1.child(  4,    'md5WithRSAEncryption')
oid_sha1_with_rsa_encryption   = oid_pkcs1.child(  5,   'sha1WithRSAEncryption')
oid_sha256_with_rsa_encryption = oid_pkcs1.child( 11, 'sha256WithRSAEncryption')
oid_sha384_with_rsa_encryption = oid_pkcs1.child( 12, 'sha384WithRSAEncryption')
oid_sha512_with_rsa_encryption = oid_pkcs1.child( 13, 'sha512WithRSAEncryption')

oid_id_mgf1        = oid_pkcs1.child( 8, 'id-mgf1' )

oid_id_md2 = oid_digest_algorithm.child( 2, 'id-md2' )
oid_id_md5 = oid_digest_algorithm.child( 5, 'id-md5' )

oid_secsig = asn1.oid_iso_identified_organization.child( 14, 'oiw', 3, 'secsig')
oid_id_sha1 = oid_secsig.child( 2, 'algorithms', 26, 'id-sha1' )

oid_nist_hashalgs = asn1.oid_country_us_gov.child( 3, 'csor', 4, 'nistalgorithm', 2, 'hashalgs' )
oid_id_sha256 = oid_nist_hashalgs.child( 1, 'id-sha256' )
oid_id_sha384 = oid_nist_hashalgs.child( 2, 'id-sha384' )
oid_id_sha512 = oid_nist_hashalgs.child( 3, 'id-sha512' )


# Define relevant ASN.1 types.
asn1_stuff = '''
      rsaPublicKey ::= SEQUENCE {
          modulus           INTEGER,  -- n
          publicExponent    INTEGER   -- e
      }
      RSAPrivateKey ::= SEQUENCE {
          version           Version,
          modulus           INTEGER,  -- n
          publicExponent    INTEGER,  -- e
          privateExponent   INTEGER,  -- d
          prime1            INTEGER,  -- p
          prime2            INTEGER,  -- q
          exponent1         INTEGER,  -- d mod (p-1)
          exponent2         INTEGER,  -- d mod (q-1)
          coefficient       INTEGER,  -- (inverse of q) mod p
          otherPrimeInfos   OtherPrimeInfos OPTIONAL
      }
            Version ::= INTEGER { two-prime(0), multi(1) }
         OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo

         OtherPrimeInfo ::= SEQUENCE {
             prime             INTEGER,  -- ri
             exponent          INTEGER,  -- di
             coefficient       INTEGER   -- ti
         }
      PKCS1Algorithms    ALGORITHM-IDENTIFIER ::= {
          { OID rsaEncryption              PARAMETERS NULL } |
          { OID md2WithRSAEncryption       PARAMETERS NULL } |
          { OID md5WithRSAEncryption       PARAMETERS NULL } |
          { OID sha1WithRSAEncryption      PARAMETERS NULL } |
          { OID sha256WithRSAEncryption    PARAMETERS NULL } |
          { OID sha384WithRSAEncryption    PARAMETERS NULL } |
          { OID sha512WithRSAEncryption    PARAMETERS NULL } |
          { OID id-RSAES-OAEP PARAMETERS RSAES-OAEP-params } |
          PKCS1PSourceAlgorithms                             |
          { OID id-RSASSA-PSS PARAMETERS RSASSA-PSS-params } ,
          ...  -- Allows for future expansion --
      }
      RSAES-OAEP-params ::= SEQUENCE {
          hashAlgorithm     [0] HashAlgorithm    DEFAULT sha1,
          maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
          pSourceAlgorithm  [2] PSourceAlgorithm DEFAULT pSpecifiedEmpty
      }
         HashAlgorithm ::= AlgorithmIdentifier {
            {OAEP-PSSDigestAlgorithms}
         }
         OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
             { OID id-sha1 PARAMETERS NULL   }|
             { OID id-sha256 PARAMETERS NULL }|
             { OID id-sha384 PARAMETERS NULL }|
             { OID id-sha512 PARAMETERS NULL },
             ...  -- Allows for future expansion --
         }
         sha1    HashAlgorithm ::= {
             algorithm   id-sha1,
             parameters  SHA1Parameters : NULL
         }
         SHA1Parameters ::= NULL
         MaskGenAlgorithm ::= AlgorithmIdentifier {
            {PKCS1MGFAlgorithms}
         }
         PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
             { OID id-mgf1 PARAMETERS HashAlgorithm },
             ...  -- Allows for future expansion --
         }
         mgf1SHA1    MaskGenAlgorithm ::= {
             algorithm   id-mgf1,
             parameters  HashAlgorithm : sha1
         }
         PSourceAlgorithm ::= AlgorithmIdentifier {
            {PKCS1PSourceAlgorithms}
         }

         PKCS1PSourceAlgorithms    ALGORITHM-IDENTIFIER ::= {
             { OID id-pSpecified PARAMETERS EncodingParameters },
             ...  -- Allows for future expansion --
         }
         EncodingParameters ::= OCTET STRING(SIZE(0..MAX))
         pSpecifiedEmpty    PSourceAlgorithm ::= {
             algorithm   id-pSpecified,
             parameters  EncodingParameters : emptyString
         }
         emptyString    EncodingParameters ::= ''H
         rSAES-OAEP-Default-Identifier  RSAES-AlgorithmIdentifier ::= {
             algorithm   id-RSAES-OAEP,
             parameters  RSAES-OAEP-params : {
                 hashAlgorithm       sha1,
                 maskGenAlgorithm    mgf1SHA1,
                 pSourceAlgorithm    pSpecifiedEmpty
             }
         }

         RSAES-AlgorithmIdentifier ::= AlgorithmIdentifier {
            {PKCS1Algorithms}
         }
      RSASSA-PSS-params ::= SEQUENCE {
          hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
          maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
          saltLength         [2] INTEGER          DEFAULT 20,
          trailerField       [3] TrailerField     DEFAULT trailerFieldBC
      }
         TrailerField ::= INTEGER { trailerFieldBC(1) }
         rSASSA-PSS-Default-Identifier  RSASSA-AlgorithmIdentifier ::= {
             algorithm   id-RSASSA-PSS,
             parameters  RSASSA-PSS-params : {
                 hashAlgorithm       sha1,
                 maskGenAlgorithm    mgf1SHA1,
                 saltLength          20,
                 trailerField        trailerFieldBC
             }
         }

         RSASSA-AlgorithmIdentifier ::=
             AlgorithmIdentifier { {PKCS1Algorithms} }
      DigestInfo ::= SEQUENCE {
          digestAlgorithm DigestAlgorithm,
          digest OCTET STRING
      }
     DigestAlgorithm ::=
          AlgorithmIdentifier { {PKCS1-v1-5DigestAlgorithms} }

      PKCS1-v1-5DigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
          { OID id-md2 PARAMETERS NULL    }|
          { OID id-md5 PARAMETERS NULL    }|
          { OID id-sha1 PARAMETERS NULL   }|
          { OID id-sha256 PARAMETERS NULL }|
          { OID id-sha384 PARAMETERS NULL }|
          { OID id-sha512 PARAMETERS NULL }
      }
'''





# Define PKCS#1's short names for primitive operations.
i2osp  = integer_to_octet_string
os2ip  = octet_string_to_integer
rsaep  = rsa_public_key.encrypt_primitive
rsadp  = rsa_private_key.decrypt_primitive
rsasp1 = rsa_private_key.sign_primitive
rsavp1 = rsa_public_key.verify_primitive

def rsaes_oaep_encrypt( k, m, random, hash, mgf = None, label = '' ):
  return oaep_encryption_scheme( random, hash, mgf, label ).encrypt(k,m)
def rsaes_oaep_decrypt( k, c,         hash, mgf = None, label = '' ):
  return oaep_encryption_scheme( None,   hash, mgf, label ).decrypt(k,c)
def rsaes_pkcs1_v1_5_encrypt( k, m, random ):
  return pkcs1_v1_5_encryption_scheme( random ).encrypt(k,m)
def rsaes_pkcs1_v1_5_decrypt( k, c ):
  return pkcs1_v1_5_encryption_scheme( None   ).decrypt(k,c)

def rsassa_pss_sign  ( k, m, random, hash, mgf = None, salt_length = None ):
  return pss_signature_scheme( random, hash, mgf, salt_length ).sign(k,m)
def rsassa_pss_verify( k, m, s,      hash, mgf = None, salt_length = None ):
  pss_signature_scheme( None, hash, mgf, salt_length ).verify(k,m,s)
def rsassa_pkcs1_v1_5_sign  ( k, m,    hash, hash_oid ):
  return pkcs1_v1_5_signature_scheme( hash, hash_oid ).sign(k,m)
def rsassa_pkcs1_v1_5_verify( k, m, s, hash, hash_oid ):
  pkcs1_v1_5_signature_scheme( hash, hash_oid ).verify(k,m,s)


class Test:

  pem_text_2048 = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA9RAulq4jGegpyn243JDiXI1Y/pYVASqxjfg1MXr59QWywnwm
H11VuX1jzxRObszhWxOwCPR5TvdqrikdF5cLzyqIXDGSY6UdVCEFm9KTGIRHBm8Q
jqNUH67sySkjpvXgiLS/UfsM3N9XUgIh9vEPZnLxRLXpYxkS54tG92FLOY3HHWKG
XPaDs4u3+OeFDhI9VDBjNiy3UVWr2x3PD3tWvX6ADY2w7bno1F1Jpd1FweIU/9eL
Lu4GeBSiUJKJ3xGIRv3+lowAC7n731GA7Aw7F/9JccOdQ5OjYu2Oeu00YdBxJL7b
nrhsngZ4WLREuDkjluBToAjIKH1XR65n7aJlBQIDAQABAoIBAQC5jVUZNiTRut3Z
ujO8nd8nIMcfjNe+mGr0CdmM64ZTJctiQspCuVLtLani44c3kd2YLmH9hc5MIj4e
PHcQo4eHhrbUx5wF4sFAL/ilMV27FH0KvBGXTselbbdP4Nxj0IwANoseMa5dlqXx
LDg3V/LHKYTQ98QNCrErrGNBb+ObYOjzLA/MUxuD35FT6qc5bDwMBr/L1AFiIPac
NaoIbtB+SOGXHpYlo5fZZrkcWSi1USFuEQXsCA8EfMJkkkP2G9Kc4aI+0xfRyLQT
OfY1XlpdqUXB9Vhj32llVxpnG2YZfQUpxcrnShgFZayrZ9qXLjODfp+iLKNfb2kU
1B1+CKBBAoGBAPtauihvBpnlZwuIsZh57aNLJCei4Zkm96i0Na4oPHN4o4sbDnJG
TgHyxBi0xBjigFJXmciGQPSXKM9O/7NWdJsLBGQCC3K4ediPiP1R17CvrHUYJL1o
6B1hN39Vy+3ybHYutaTSZr2ed2mkWJYEZ97uBJyKsod7gVXNzMixMjA9AoGBAPmX
sDQeb/svn0a3PWi8HiKSeBu9yLPL53Ri0m2zIALzK79YYEjBECWBo1TFTAmfszJP
/TC8efWYGQ3H7GqLIbc3RMuuXMv+AsRljdanyojr8R75ToF1c4/4UbfICr6lRpS5
6HYSptoZZYw6UGeltWqUcC94PnDm1VoTWFwlzMxpAoGAavGTOxjiCiCc0z95sJJQ
FaYm3+ZhbjQyM0lZfZwI/GhbzRfZ8a0QC6wq2wguVxgn2OEEwVi90lNuPaYzDS6/
tifd2l80V789uHJ5qq5jwv07tyZqm1xDRhzS7A6pEbiPhUkiZ9pNdGg0DnKqbkm5
mBRVSfWJODPIN6W0d79Mx1ECgYEAx6gQ2tBSUcPZjI7+P67kCFHUZJSfXTxKTS7U
F87HV7TAFROUCf7udKJMTn55AeXPSfr0lazffpeJyx1XQC9F7DL5BFnZf5EVE5gN
K14TxQ3AVz+lDigvJkbEz9fkyHabjFNe4jyvXh4cvlzTfuXuxnAxgbeVc2kj2CdL
coMGXakCgYEA0lzbGLbJFblQ7I1eOBpoVTaLdXFYjFROFVEhCziLEqkrEVv6DgJg
Ja/0o1Nyte3jBlIBG0TlQm9Hk4MIrLdpTvQHVKfidPB3YlpBtsuV/Bvt4qnUSXVG
DHwozzZedxh5R4m1GkRyqUwavrs+QfGAm6poMfoPdyDQFlvatrCGRm8=
-----END RSA PRIVATE KEY-----
  '''

  pem_text_2049 = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEBrrupbAEdndyLVuvRYwoqnQSxEHo/SUIvoS1P1kcKowqRDsED
F/zWy7SfHyn5sOIkiMpT43DEl3XRQlgsXJqje/BFIP7QrUVolGpv9AUuaEPAOU3t
Vstx5BKblkfrfWv+/Mng5xHaSsQdTx+5mMsRqUF/5gLSTp3jL71ONoXySVMYFH0X
YqAXRvqkEjnjhJdAIbZLaEVQWncD5zbhguW/D7w6bXXpwE0f1qAvIZXIMdpPfwui
/2adHQnVwW+zXepC+wR7cnoRkZj4N/BwGq7XNcKLvLCOuXzgEhwF7/5sPyg3B+PA
tVrpodMMiw6d14dVggEqKW3bTME+o4VNdRmkLQIDAQABAoIBAQFOb00Dm/Yn7OaP
jbfdAzbFBbCJT7G1qtsadPkpMa2zm++3GevSAzGvpsVpyAij62Jch2QNEzDBPOxG
a/m9yR+oiozSKqdR8bNakS3ttNwsfnZQyA3At2PtpvkA/UR99I1eL00dfIIWTSFI
nyRW200SMtYgfA5YlkSge4av1N6jR9x57uQGVpMxcLANOBITXXR9a1/1+tgB/vuL
uv2DovbwUC8bVbUC4PiXJXtRqSN9J80QFEjxhSlqPvSk5ijRnqdDboWXwEBHYoe+
/SiH/YIOCqPsrArfGngkhq0fkDMenozhNAfYoq8VXeictsrAsSjjsdMMdh3y+Gkt
AF7U+SlhAoGBAfliJxAlnHMWeHLK1eoqE8vbc5c0b/pYJqaV5uEJCr8VFiwJqRiZ
3CL27162zoKCNAUF3XjY4bufSJjqydeLH6nY6fL8GOjJCPruy1PJKzIP5yK5jL3J
KMQO15FL7gK9Y7dOESdLa8EF+d0ZSJIm12jCRqgFahjLg0jmBSsJ3fjZAoGBANov
p7x2TwhUnHyfdOv9OharUB1RQV2ckrHk99+ZwRuVIOKB3GaxOGMglvAGnrJjcHLV
DxF27aFvYnM1bU6iyJ8hMvu9g1B1mRWu6BFFCtTji64KVuCqMLm6ZR0BaWvcv7y1
EFbAFiuIERRN6TRjXe/+oH/nzvaBHAKkfnMt1JF1AoGBAUQCwqqegnRixqxKEOWF
PpXnR298pgIpu/X3i0NhiatCeKmZM/law4EDMipWJ4YStgk2XmyZF/gzQdcQSIHR
Z2Z8dFldeRbdtM00hdVc1z3MZlKkBXCz5Ff2cAxuUtUc2S5vdZ3sw9PH4g73o8hX
8KjwTV5xwjjNWYlGN7AFLnPZAoGAHCloghfXLaEWLbO7OLaPp9tm1NHnGPkbqiB+
qfrDhRbjjrjqRMr9FzZepQ6Fr0rMedXsQvnRxDOHRo2P1UWHlZqIZRvZ9imnn7fa
tlfuBPp1zfoBqq/s6BwZ7vt+qvBsQyQvvrK+adH/OlqwDhYBSvfXqYq3GPQjNGgc
9irlM/0CgYEA/ilEGt+dutfN3Eq9gwe3vrOZoGjPdDN5IhnF3Y+tuvnnnLkzvfmg
D5X1z6iD+FgQ/xC9amS3zNEy+y66ZW6wAtbQIqP9MrCt5/AnZ4aVJAFZ7mQNIk/G
2b2Q9IomVJezJuzEFQy59whmmuEG19hpSPaizbPi9tAsd8/1YaSvXbY=
-----END RSA PRIVATE KEY-----
  '''

  def test_pem( t ):
    key = rsa_private_key.pem_decode( t.pem_text_2048 )
    return key

  def keys( t ):
    # Test a 2049-bit key as well to try to catch fencepost errors.
    for pem in t.pem_text_2048, t.pem_text_2049:
      key = rsa_private_key.pem_decode( pem )
      yield key

  def test_oaep( t ):
    import sha
    scheme = oaep_encryption_scheme( lambda n: '\0' * n, sha )
    for key in t.keys():
      c = scheme.encrypt( key.public_key(), 'foo' )
      print len(c), repr(c)
      assert scheme.decrypt( key, c ) == 'foo'

  def test_encrypt_v1_5( t ):
    import sha
    scheme = pkcs1_v1_5_encryption_scheme( lambda n: '\1' * n )
    for key in t.keys():
      c = scheme.encrypt( key.public_key(), 'foo' )
      print len(c), repr(c)
      assert scheme.decrypt( key, c ) == 'foo'

  def test_pss( t ):
    import sha
    scheme = pss_signature_scheme( lambda n: '\0' * n, sha )
    for key in t.keys():
      sig = scheme.sign( key, 'foo' )
      print len(sig), repr( sig )
      scheme.verify( key.public_key(), 'foo', sig )

  def test_sign_v1_5( t ):
    import sha
    scheme = pkcs1_v1_5_signature_scheme( sha, oid_id_sha1 )
    for key in t.keys():
      sig = scheme.sign( key, 'foo' )
      print len(sig), repr( sig )
      scheme.verify( key.public_key(), 'foo', sig )
