'''
Based on RFC 3280.
'''

import asn1, pkcs1


class certificate:

  def __init__( self, version, serial, issuer, validity, subject,
                public_key_algorithm_id, public_key_bits, optional_fields,
                signature_algorithm_id, signature ):
    self.version = version
    self.serial = serial
    self.issuer = issuer
    self.validity = validity
    self.subject = subject
    self.public_key_algorithm_id = public_key_algorithm_id
    self.public_key_bits = public_key_bits
    self.optional_fields = optional_fields
    self.signature_algorithm_id = signature_algorithm_id
    self.signature = signature


  def extract_rsa_public_key( self ):
    '''Return the public parameters n, e of the subject's public key.'''
    pkid, pkid_params = self.public_key_algorithm_id
    assert pkid == pkcs1.oid_rsa_encryption and pkid_params == asn1.null()
    params, rest = asn1.der_decode( self.public_key_bits.as_octets() )
    assert rest == ''
    n, e = params
    return pkcs1.rsa_public_key( long(n), long(e) )

  def extract_signature( self ):
    '''Return the certificate's signature as an octet string.'''
    return self.signature.as_octets()


  def to_be_signed( self ):
    '''Construct just the to-be-signed part.'''
    tbs = []
    if self.version > 0:
      tbs.append( asn1.context_specific( 0, asn1.integer( self.version )))
    tbs += [
      asn1.integer( self.serial ),
      self.signature_algorithm_id,
      self.issuer,
      self.validity,
      self.subject,
      asn1.sequence(( self.public_key_algorithm_id, self.public_key_bits )),
    ]
    tbs.extend( self.optional_fields )
    return asn1.sequence( tbs )

  def as_asn1( self ):
    return asn1.sequence((
      self.to_be_signed(),
      self.signature_algorithm_id,
      self.signature
    ))

  def der_encode( self ):
    return self.as_asn1().der_encode()

  @classmethod
  def der_decode( cls, octets ):
    cert, rest = asn1.der_decode( octets )
    assert rest == ''
    tbs, signature_algorithm_id, signature = cert
    i = iter( tbs )
    version = 0
    if tbs[0].tag == 0: version = int( i.next().value() )
    serial = int( i.next() )
    assert signature_algorithm_id == i.next()
    issuer = i.next()
    validity = i.next()
    subject = i.next()
    public_key_algorithm_id, public_key_bits = i.next()
    optional_fields = tuple( i )

    return cls( version, serial, issuer, validity, subject,
                public_key_algorithm_id, public_key_bits, optional_fields,
                signature_algorithm_id, signature )


  def pem_encode( self ):
    return asn1.pem_encode( self.as_asn1(), 'CERTIFICATE' )

  @classmethod
  def pem_decode( cls, pem_text ):
    der, = asn1.pem_extract( pem_text, 'CERTIFICATE' )
    return cls.der_decode( der )



class Test:

  # static CA certificate (MIT client CA v1)
  ca_certificate = '''
-----BEGIN CERTIFICATE-----
MIICRzCCAbACAQAwDQYJKoZIhvcNAQEEBQAwbDELMAkGA1UEBhMCVVMxFjAUBgNV
BAgTDU1hc3NhY2h1c2V0dHMxLjAsBgNVBAoTJU1hc3NhY2h1c2V0dHMgSW5zdGl0
dXRlIG9mIFRlY2hub2xvZ3kxFTATBgNVBAsTDENsaWVudCBDQSB2MTAeFw05NzAz
MDMxOTA5MzVaFw0wMDAzMDIxOTA5MzVaMGwxCzAJBgNVBAYTAlVTMRYwFAYDVQQI
Ew1NYXNzYWNodXNldHRzMS4wLAYDVQQKEyVNYXNzYWNodXNldHRzIEluc3RpdHV0
ZSBvZiBUZWNobm9sb2d5MRUwEwYDVQQLEwxDbGllbnQgQ0EgdjEwgZ8wDQYJKoZI
hvcNAQEBBQADgY0AMIGJAoGBAMFddQmuDslk55RehR/M/DMAlGty+ScbhbKy7M+2
qxnkw0t/Vo1ssA4AmTN7zgrzqc4hhWM4nEu5+CULstOELk/ul3XNmxMe7iToaHk8
/1cqQOAyMHLL9tCOtwoK9eGjDc+VK+ClkI8p+s3IENu+n5zP3CQ98MwM19n1PZhf
9SxRAgMBAAEwDQYJKoZIhvcNAQEEBQADgYEAsj3qjB1MueHcGSSny3HZkwOAsLwt
r0UZvVcNcRq61MgJe/E+1o9iBcRi+WZ5PIw9YZlgt73Mtmd0K6k43w4cPd8/bqGg
mpD7TYhNlxvhmqwvdJWeWJhPfHeGqHdmvcldCbkDtOlKd1K6jVLkgmQmNgCnbAoF
pC8M1Cil9xR83QE=
-----END CERTIFICATE-----
  '''

  # golem@mit.edu 2005 client certificate
  client_certificate = '''
Enter Import Password:
MAC verified OK
Bag Attributes
    friendlyName: Chris T Laas's Massachusetts Institute of Technology ID
    localKeyID: 4D DE 8F A4 9E C6 89 B0 B5 7F F3 C3 01 59 DB 09 86 2F 4D 2C 
subject=/C=US/ST=Massachusetts/O=Massachusetts Institute of Technology/OU=Client CA v1/CN=Chris T Laas/emailAddress=golem@MIT.EDU
issuer=/C=US/ST=Massachusetts/O=Massachusetts Institute of Technology/OU=Client CA v1
-----BEGIN CERTIFICATE-----
MIIDdTCCAt6gAwIBAgIDGgTWMA0GCSqGSIb3DQEBBQUAMGwxCzAJBgNVBAYTAlVT
MRYwFAYDVQQIEw1NYXNzYWNodXNldHRzMS4wLAYDVQQKEyVNYXNzYWNodXNldHRz
IEluc3RpdHV0ZSBvZiBUZWNobm9sb2d5MRUwEwYDVQQLEwxDbGllbnQgQ0EgdjEw
HhcNMDUwMjEwMjE0NDIxWhcNMDUwNzMwMjE0NDIxWjCBoTELMAkGA1UEBhMCVVMx
FjAUBgNVBAgTDU1hc3NhY2h1c2V0dHMxLjAsBgNVBAoTJU1hc3NhY2h1c2V0dHMg
SW5zdGl0dXRlIG9mIFRlY2hub2xvZ3kxFTATBgNVBAsTDENsaWVudCBDQSB2MTEV
MBMGA1UEAxMMQ2hyaXMgVCBMYWFzMRwwGgYJKoZIhvcNAQkBEw1nb2xlbUBNSVQu
RURVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9RAulq4jGegpyn24
3JDiXI1Y/pYVASqxjfg1MXr59QWywnwmH11VuX1jzxRObszhWxOwCPR5Tvdqrikd
F5cLzyqIXDGSY6UdVCEFm9KTGIRHBm8QjqNUH67sySkjpvXgiLS/UfsM3N9XUgIh
9vEPZnLxRLXpYxkS54tG92FLOY3HHWKGXPaDs4u3+OeFDhI9VDBjNiy3UVWr2x3P
D3tWvX6ADY2w7bno1F1Jpd1FweIU/9eLLu4GeBSiUJKJ3xGIRv3+lowAC7n731GA
7Aw7F/9JccOdQ5OjYu2Oeu00YdBxJL7bnrhsngZ4WLREuDkjluBToAjIKH1XR65n
7aJlBQIDAQABo2swaTAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIFoDAdBgNV
HSUEFjAUBggrBgEFBQcDBAYIKwYBBQUHAwIwCwYDVR0PBAQDAgXgMB0GA1UdDgQW
BBQKCBNTN785F4yP/vv8oJvP4OW9ajANBgkqhkiG9w0BAQUFAAOBgQAspnWlJsap
qy14qy6il0pRVs+G62kBuOK3fPtTV0IYK74bxN6NdJqnjoy37sv2O/ewJv5BOWzA
BOHPGNYR5fdN/oiWXpuGVwgKwX5wC4U9CAjkqSOO2Rp8hYIc+GmdfEPJMkhtcd6d
A7DcwPNoj1dcSwaFIt1k3ezKFwJBJqjUOw==
-----END CERTIFICATE-----
  '''

  # It's expired, so worthless anyway.
  client_private_key = '''
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
  

  def test_pem(t):
    ca_cert = certificate.pem_decode( t.ca_certificate )
    client_cert = certificate.pem_decode( t.client_certificate )
    print ca_cert.extract_rsa_public_key()
    print client_cert.extract_rsa_public_key()
    assert ca_cert.pem_encode().strip() == t.ca_certificate.strip()

