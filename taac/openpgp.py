#
# Copyright (C) 2005, 2006 Red Hat, Inc.
# Author: Miloslav Trmac
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Library General Public License as published by
# the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

import array, base64, binascii, md5, sha, string, struct

try:
    import Crypto.Hash.MD2 as MD2 #, Crypto.Hash.RIPEMD as RIPEMD
    import Crypto.Hash.SHA256 as SHA256
    import Crypto.PublicKey.DSA as DSA, Crypto.PublicKey.RSA as RSA
    import Crypto.PublicKey.ElGamal as ElGamal
    import Crypto.Util.number as Util_number
    RIPEMD = None
except ImportError:
    MD2, RIPEMD, SHA256 = None, None, None
    DSA, RSA, ElGamal = None, None, None
    Util_number = None

#from logger import log

# FIXME: "VERIFY" notes
# FIXME: "BADFORMAT" notes

# Algorithm tables

_ALG_PK_RSA = 1
_ALG_PK_RSA_ENCRYPT = 2
_ALG_PK_RSA_SIGN = 3
_ALG_PK_ELGAMAL_ENCRYPT = 16
_ALG_PK_DSA = 17
_ALG_PK_ELGAMAL = 20

# alg: (name, primary, can_encrypt, can_sign)
_pubkey_alg_data = {
    _ALG_PK_RSA: ("RSA", _ALG_PK_RSA, True, True),
    _ALG_PK_RSA_ENCRYPT: ("RSA encrypt-only", _ALG_PK_RSA, True, False),
    _ALG_PK_RSA_SIGN: ("RSA sign-only", _ALG_PK_RSA, False, True),
    _ALG_PK_ELGAMAL_ENCRYPT: ("Elgamal encrypt-only", _ALG_PK_ELGAMAL, True,
                              False),
    _ALG_PK_DSA: ("DSA", _ALG_PK_DSA, True, True),
    _ALG_PK_ELGAMAL: ("Elgamal", _ALG_PK_ELGAMAL, True, True)
}

_ALG_HASH_MD5 = 1
_ALG_HASH_SHA1 = 2
_ALG_HASH_RIPE_MD160 = 3
_ALG_HASH_MD2 = 5
_ALG_HASH_SHA256 = 8
_ALG_HASH_SHA384 = 9
_ALG_HASH_SHA512 = 10


# alg: (name, module or None, ASN.1 prefix)
_hash_alg_data = {
    _ALG_HASH_MD5: ("MD5", md5, "\x30\x20\x30\x0C\x06\x08\x2A\x86"
                    "\x48\x86\xF7\x0D\x02\x05\x05\x00\x04\x10"),
    _ALG_HASH_SHA1: ("SHA1", sha, "\x30\x21\x30\x09\x06\x05\x2B\x0E"
                     "\x03\x02\x1A\x05\x00\x04\x14"),
    _ALG_HASH_RIPE_MD160: ("RIPE-MD/160", RIPEMD,
                           "\x30\x21\x30\x09\x06\x05\x2B\x24"
                           "\x03\x02\x01\x05\x00\x04\x14"),
    _ALG_HASH_MD2: ("MD2", MD2, "\x30\x20\x30\x0C\x06\x08\x2A\x86"
                    "\x48\x86\xF7\x0D\x02\x02\x05\x00\x04\x10"),
    _ALG_HASH_SHA256: ("SHA256", SHA256, "\x30\x41\x30\x0D\x06\x09\x60\x86"
                       "\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"),
    _ALG_HASH_SHA384: ("SHA384", None, "\x30\x41\x30\x0D\x06\x09\x60\x86"
                       "\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30"),
    _ALG_HASH_SHA512: ("SHA512", None, "\x30\x51\x30\x0D\x06\x09\x60\x86"
                       "\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40")
}


def _popListHead(list):
    """Return list.pop(0) if list is nonempty, None otherwise."""

    try:
        return list.pop(0)
    except IndexError:
        return None


 # Algorithm implementations
def _parseMPI(data):
    """Return a Python long parsed from MPI data and the number of bytes
    consumed.

    Raise ValueError on invalid input."""

    try:
        (length,) = struct.unpack(">H", data[:2])
    except struct.error:
        raise ValueError, "Invalid MPI format"
    end = (length + 7) / 8 + 2
    if len(data) < end:
        raise ValueError, "Invalid MPI format"
    if length == 0:
        return (0L, end)
    # The leading bit
    bit = 1 << ((length - 1) % 8)
    # (bit - 1) masks bits lower than the leading one, so ~(bit - 1) should be
    # 0...01
    if ord(data[2]) & ~(bit - 1) != bit:
        raise ValueError, "Invalid MPI format"
    return (Util_number.bytes_to_long(data[2 : end]), end)


class _PubkeyAlg:
    """Public key algorithm data handling interface."""

    def __init__(self):
        """Parse public key data from OpenPGP public key packet data area.

        Raise ValueError on invalid input, NotImplementedError if algorithm
        is not supported."""

    def verify(self, data, value):
        """Verify value with data from OpenPGP signature packet.

        Return 1 if signature is OK, raise ValueError if data is invalid."""

        raise NotImplementedError

class _RSAPubkeyAlg(_PubkeyAlg):
    """RSA public key algorithm data handling."""

    def __init__(self, data):
        _PubkeyAlg.__init__(self)
        (n, pos) = _parseMPI(data)
        (e, length) = _parseMPI(data[pos:])
        if pos + length != len(data):
            raise ValueError, "Invalid RSA public key data"
        if RSA is None:
            raise NotImplementedError, "python-Crypto not available"
        self.rsa = RSA.construct((n, e))

    def verify(self, data, value):
        (sig, length) = _parseMPI(data)
        if length != len(data):
            raise ValueError, "Invalid RSA signature data"
        return self.rsa.verify(value, (sig,))

class _DSAPubkeyAlg(_PubkeyAlg):
    """DSA public key algorithm data handling."""

    def __init__(self, data):
        _PubkeyAlg.__init__(self)
        (p, pos) = _parseMPI(data)
        (q, length) = _parseMPI(data[pos:])
        pos += length
        (g, length) = _parseMPI(data[pos:])
        pos += length
        (y, length) = _parseMPI(data[pos:])
        if pos + length != len(data):
            raise ValueError, "Invalid DSA public key data"
        if DSA is None:
            raise NotImplementedError, "python-Crypto not available"
        self.dsa = DSA.construct((y, g, p, q))

    def verify(self, data, value):
        (r, pos) = _parseMPI(data)
        (s, length) = _parseMPI(data[pos:])
        if pos + length != len(data):
            raise ValueError, "Invalid DSA signature data"
        return self.dsa.verify(value, (r, s))

class _ElGamalPubkeyAlg(_PubkeyAlg):
    """ElGamal public key algorithm data handling."""

    def __init__(self, data):
        _PubkeyAlg.__init__(self)
        (p, pos) = _parseMPI(data)
        (g, length) = _parseMPI(data[pos:])
        pos += length
        (y, length) = _parseMPI(data[pos:])
        if pos + length != len(data):
            raise ValueError, "Invalid ElGamal public key data"
        if ElGamal is None:
            raise NotImplementedError, "python-Crypto not available"
        self.elgamal = ElGamal.construct((p, g, y))

    def verify(self, data, value):
        (siga, pos) = _parseMPI(data)
        (sigb, length) = _parseMPI(data[pos:])
        if pos + length != len(data):
            raise ValueError, "Invalid ElGamal signature data"
        return self.elgamal.verify(value, (siga, sigb))

_pubkey_classes = {
    _ALG_PK_RSA: _RSAPubkeyAlg,
    _ALG_PK_RSA_ENCRYPT: _RSAPubkeyAlg,
    _ALG_PK_RSA_SIGN: _RSAPubkeyAlg,
    _ALG_PK_ELGAMAL_ENCRYPT: _ElGamalPubkeyAlg,
    _ALG_PK_DSA: _DSAPubkeyAlg,
    _ALG_PK_ELGAMAL: _ElGamalPubkeyAlg
}


 # Packet parsing
class _PGPPacket:
    """A single PGP packet."""

    def __init__(self, tag, data):
        """Parse a PGP packet.

        Raise ValueError on invalid input, NotImplementedError on unknown
        data."""

        self.tag = tag
        self.data = data

    def __str__(self):
        return "UNKNOWN TAG %s" % self.tag


class _SignaturePacket(_PGPPacket):
    """A signature (tag 2) packet."""

    # Signature types
    ST_BINARY = 0x00
    ST_TEXT = 0x01
    ST_STANDALONE = 0x02
    ST_CERT_GENERIC = 0x10
    ST_CERT_NONE = 0x11
    ST_CERT_CASUAL = 0x12
    ST_CERT_POSITIVE = 0x13
    ST_SUBKEY = 0x18
    ST_DIRECT = 0x1F
    ST_KEY_REVOCATION = 0x20
    ST_SUBKEY_REVOCATION = 0x28
    ST_CERT_REVOCATION = 0x30
    ST_TIMESTAMP = 0x40

    # Key flags ("flags")
    FL_CAN_CERTIFY = 0x01
    FL_CAN_SIGN = 0x02
    FL_CAN_ENCRYPT_COMMUNICATIONS = 0x04
    FL_CAN_ENCRYPT_STORAGE = 0x08

    sigtypes = {
        ST_BINARY: "binary", ST_TEXT: "text", ST_STANDALONE: "standalone",
        ST_CERT_GENERIC: "cert_generic", ST_CERT_NONE: "cert_none",
        ST_CERT_CASUAL: "cert_casual", ST_CERT_POSITIVE: "cert_positive",
        ST_SUBKEY: "subkey", ST_DIRECT: "direct",
        ST_KEY_REVOCATION: "key_revocation",
        ST_SUBKEY_REVOCATION: "subkey_revocation",
        ST_CERT_REVOCATION: "cert_revocation", ST_TIMESTAMP: "timestamp"
    }

    def __init__(self, tag, data):
        _PGPPacket.__init__(self, tag, data)
        if not data:
            raise ValueError, "Packet too small"
        self.ver = ord(data[0])
        if self.ver == 2 or self.ver == 3:
            self.hashed_sp = {}
            self.unhashed_sp = {}
            if len(data) < 19:
                raise ValueError, "Packet too small"
            if ord(data[1]) != 5:
                raise ValueError, "Invalid hashed material length"
            (self.sigtype, self.hashed_sp["sign_time"],
             self.hashed_sp["key_id"], self.pubkey_alg, self.hash_alg,
             self.hash_16b) \
                = struct.unpack(">BI8s2B2s", data[2:19])
            self.value_start = 19
        elif self.ver == 4:
            if len(data) < 6:
                raise ValueError, "Packet too small"
            (self.sigtype, self.pubkey_alg, self.hash_alg, count) \
                           = struct.unpack(">3BH", data[1:6])
            self.hashed_end = 6 + count
            if len(data) < self.hashed_end + 2:
                raise ValueError, "Packet too small"
            self.hashed_sp = self.__parseSubpackets(data[6 : self.hashed_end])
            if "sign_time" not in self.hashed_sp:
                raise ValueError, "Signature time not in hashed data"
            (count,) = struct.unpack(">H", data[self.hashed_end
                                                : self.hashed_end + 2])
            unhashed_end = self.hashed_end + 2 + count
            if len(data) < unhashed_end + 2:
                raise ValueError, "Packet too small"
            self.unhashed_sp = self.__parseSubpackets(data[self.hashed_end + 2
                                                           : unhashed_end])
            self.hash_16b = data[unhashed_end : unhashed_end + 2]
            self.value_start = unhashed_end + 2
        else:
            raise NotImplementedError, \
                  "Unknown signature version %s" % self.ver

    def __str__(self):
        if self.sigtype in self.sigtypes:
            sigtype = self.sigtypes[self.sigtype]
        else:
            sigtype = "type %s" % self.sigtype
        if self.pubkey_alg in _pubkey_alg_data:
            pubkey_alg = _pubkey_alg_data[self.pubkey_alg][0]
        else:
            pubkey_alg = "pubkey %s" % self.pubkey_alg
        if self.hash_alg in _hash_alg_data:
            hash_alg = _hash_alg_data[self.hash_alg][0]
        else:
            hash_alg = "hash %s" % self.hash_alg
        return ("sig(v%s, %s, %s, %s, hashed %s, unhashed %s)"
                % (self.ver, sigtype, pubkey_alg, hash_alg, self.hashed_sp,
                   self.unhashed_sp))

    def __parseSubpackets(self, data):
        """Return a hash from parsing subpacket data.

        Raise ValueError on invalid data, NotImplementedError on unknown
        data."""

        res = {}
        while data:
            len1 = ord(data[0])
            if len1 < 192:
                start = 1
                length = len1
            elif len1 < 255:
                start = 2
                if len(data) < 2:
                    raise ValueError, "Not enough data for subpacket"
                length = ((len1 - 192) << 8) + ord(data[1]) + 192
            else:
                start = 5
                if len(data) < 5:
                    raise ValueError, "Not enough data for subpacket"
                (length,) = struct.unpack(">I", data[1:5])
            if length == 0 or len(data) < start + length:
                raise ValueError, "Not enough data for subpacket"
            sptype = ord(data[start]) & 0x7F
            spdata = data[start + 1 : start + length]
            # Giant try block instead of checking spdata always has the right
            # length
            try:
                if sptype == 2:
                    (res["sign_time"],) = struct.unpack(">I", spdata)
                elif sptype == 3:
                    # Doesn't make sense on a revocation signature
                    (res["expire_time"],) = struct.unpack(">I", spdata)
                elif sptype == 4:
                    if len(spdata) != 1:
                        raise ValueError, "Invalid exportable flag"
                    v = ord(spdata[0])
                    if v > 1:
                        raise ValueError, "Invalid exportable flag"
                    res["exportable"] = v
                elif sptype == 5:
                    res["trust"] = struct.unpack(">2B", spdata)
                elif sptype == 6:
                    if not spdata or spdata[-1] != "\0":
                        raise ValueError, "Invalid regexp"
                    res["regexp"] = spdata[:-1]
                elif sptype == 7:
                    if len(spdata) != 1:
                        raise ValueError, "Invalid revocable flag"
                    v = ord(spdata[0])
                    if v > 1:
                        raise ValueError, "Invalid revocable flag"
                    res["revocable"] = v
                elif sptype == 9:
                    # VERIFY: only on a self-signature
                    (res["key_expire"],) = struct.unpack(">I", spdata)
                elif sptype == 11:
                    # VERIFY: only on a self-signature
                    res["symmetric_pref"] = array.array("B", spdata).tolist()
                elif sptype == 12:
                    # VERIFY: only on a self-signature
                    v = struct.unpack(">BB20s", spdata)
                    if (v[0] & 0x80) == 0:
                        raise ValueError, "Invalid revocation key class"
                    if "revocation_key" in res:
                        res["revocation_key"].append(v)
                    else:
                        res["revocation_key"] = [v]
                elif sptype == 16:
                    if len(spdata) != 8:
                        raise ValueError, "Invalid key ID length"
                    res["key_id"] = spdata
                elif sptype == 20:
                    (flags, nl, vl) = struct.unpack(">I2H", spdata[:8])
                    if (flags & 0x7FFFFFF) != 0:
                        raise NotImplementedError, "Unknown notation flags"
                    if len(spdata) != 8 + nl + vl:
                        raise ValueError, "Invalid notation lenghts"
                    v = (flags, spdata[8 : 8 + nl], spdata[8 + nl:])
                    if "notation" in res:
                        res["notation"].append(v)
                    else:
                        res["notation"] = [v]
                elif sptype == 21:
                    # VERIFY: only on a self-signature
                    res["hash_pref"] = array.array("B", spdata).tolist()
                elif sptype == 22:
                    # VERIFY: only on a self-signature
                    res["compress_pref"] = array.array("B", spdata).tolist()
                elif sptype == 23:
                    # VERIFY: only on a self-signature
                    v = array.array("B", spdata)
                    if len(v) >= 1 and (v[0] & 0x7F) != 0:
                        raise NotImplementedError, \
                              "Unknown key server preferences"
                    for i in xrange(1, len(v)):
                        if v[i] != 0x00:
                            raise NotImplementedError, \
                                  "Unknown key server preferences"
                    res["ks_flags"] = v
                elif sptype == 24:
                    res["ks_url"] = spdata
                elif sptype == 25:
                    # FIXME: implement on display
                    # VERIFY: only on a self-signature
                    if len(spdata) != 1:
                        raise ValueError, "Invalid primary UID flag"
                    v = ord(spdata[0])
                    if v > 1:
                        raise ValueError, "Invalid primary UID flag"
                    res["primary_uid"] = v
                elif sptype == 26:
                    res["policy_url"] = spdata
                elif sptype == 27:
                    # VERIFY: only on a self-signature or on certification
                    # signatures
                    res["flags"] = array.array("B", spdata)
                    # VERIFY: flags 0x10, 0x80 only on a self-signature
                    # FIXME: verify flags (may_certify, may_sign)
                elif sptype == 28:
                    res["user_id"] = spdata
                elif sptype == 29:
                    if not spdata:
                        raise ValueError, "Invalid revocation reason"
                    res["revocation_reason"] = (ord(spdata[0]), spdata[1:])
                elif (ord(data[start]) & 0x80) != 0:
                    raise NotImplementedError, \
                          "Unknown signature subpacket type %s" % sptype
            except struct.error:
                raise ValueError, "Invalid subpacket data"
            data = data[start + length:]
        return res

    def prepareDigest(self):
        """Return a digest prepared for hashing data to be signed.

        Raise NotImplementedError on unknown hash algorithm."""

        if self.hash_alg not in _hash_alg_data:
            raise NotImplementedError, \
                  "Unknown hash algorithm %s" % self.hash_alg
        m = _hash_alg_data[self.hash_alg][1]
        if m is None:
            raise NotImplementedError, "Can't compute hash %s" % self.hash_alg
        return m.new()

    def finishDigest(self, digest):
        """Finish digest after hashing data to be signed.

        Return digest value ("hash")."""

        if self.ver == 2 or self.ver == 3:
            digest.update(self.data[2:7])
        elif self.ver == 4:
            digest.update(self.data[:self.hashed_end]
                          + '\x04\xFF' + struct.pack(">I", self.hashed_end))
        else:
            raise AssertionError, "Unreachable"
        return digest.digest()

    def __verifyDigestWithPacket(self, packet, alg, digest):
        """Verify the signature of digest "hash" against a key packet
        and its _PubkeyAlg.

        Return 1 if the signature is OK, 0 if the key doesn't match the
        signature, -1 if the signature doesn't match.  Raise ValueError if the
        signature key contains invalid data, NotImplementedError if public key
        algorithm is not supported.

        The digest should be created using self.prepareDigest() and
        self.finishDigest().  Note that there is no way to 100% reliably detect
        whether signature verification failed or whether a wrong key was
        used."""

        if (packet.pubkey_alg not in _pubkey_alg_data
            or self.pubkey_alg not in _pubkey_alg_data):
            raise NotImplementedError, "Unknown public key algorithm"
        key_alg_data = _pubkey_alg_data[packet.pubkey_alg]
        if _pubkey_alg_data[self.pubkey_alg][1] != key_alg_data[1]:
            return 0
        if not key_alg_data[3]:
            return 0 # Key is not capable of signing
        if digest[:2] != self.hash_16b:
            return -1
        if ((self.ver == 2 or self.ver == 3)
            and _pubkey_alg_data[self.pubkey_alg][1] == _ALG_PK_RSA):
            prefix = _hash_alg_data[self.hash_alg][2]
            k = alg.rsa.size() / 8 + 1
            bs = (k - (3 + len(prefix) + len(digest)))
            if bs < 0:
                return 0 # RSA key modulus too small"
            digest = '\x00\x01' + bs * '\xFF' + '\x00' + prefix + digest
        if self.pubkey_alg == _ALG_PK_DSA and len(digest) != 20:
            raise ValueError, "Invalid digest type used with DSA"
        if alg.verify(self.data[self.value_start:], digest):
            return 1
        return -1

    def __verifyDigestWithKey(self, key, key_id, digest):
        """Verify the signature of digest of data against a key, using
        the specified key_id if it is not None.

        Return 1 if signature matches, 0 if we don't know (because we skipped a
        key or packet matching key_id, -1 if it didn't match (which doesn't
        mean it is bad).

        Raise ValueError if the signature packet is invalid."""

        if (key.primary_revocation is not None
            and (self.hashed_sp["sign_time"] >
                 key.primary_revocation.hashed_sp["sign_time"])):
            # Signature with a revoked key
            return -1
        if key_id is not None:
            packets = key.keyPacketsWithID(key_id)
        else:
            packets = key.keyPackets()
        result = -1
        for packet in packets:
            # FIXME: verify the packet was not revoked
            if (packet.pubkey_alg not in _pubkey_alg_data
                or packet.pubkey_alg not in _pubkey_classes):
                # Unsupported public key algorithm
                if packet.keyID() == key_id:
                    result = 0
                continue
            try:
                alg = (_pubkey_classes[packet.pubkey_alg]
                       (packet.data[packet.value_start:]))
            except (NotImplementedError, ValueError):
                # Unsupported or invalid key
                if packet.keyID() == key_id:
                    result = 0
                continue
            try:
                r = self.__verifyDigestWithPacket(packet, alg, digest)
            except NotImplementedError:
                r = 0;
            if r == 1:
                return 1
            elif r == 0 and packet.keyID() == key_id:
                result = 0
        return result

    def verifyDigest(self, keyring, digest): #, flags=FL_CAN_SIGN):
        """Verify the signature of digest of data against a matching key
        in a keyring, if any, with given key usage flags.

        Return (result, key); result is 1 if signature matches, 0 if we don't
        know, -1 if one valid key with maching ID was found, but its signature
        didn't match (note that this doesn't 100% imply the signature is bad).
        Key is the signing _PublicKey if result is 1, None otherwise.

        Raise ValueError if the signature packet is invalid."""

        if "key_id" in self.hashed_sp:
            key_ids = [self.hashed_sp["key_id"]]
        elif "key_id" in self.unhashed_sp:
            key_ids = [self.unhashed_sp["key_id"], None]
        else:
            key_ids = [None]
        result = 0
        for key_id in key_ids:
            if key_id is not None:
                keys = keyring.by_key_id.get(key_id, [])
                # key_ids always starts with non-None, so this is set to -1
                # only at start of the first iteration.
                if len(keys) == 1:
                    result = -1
            else:
                keys = keyring.keys.values()
            for key in keys:
                r = self.__verifyDigestWithKey(key, key_id, digest)
                if r == 1:
                    return (1, key)
                if r == 0:
                    result = 0
        return (result, None)


class _PublicKeyPacket__(_PGPPacket):
    """A public key packet (tag 6 or 14)."""

    desc = None

    def __init__(self, tag, data):
        _PGPPacket.__init__(self, tag, data)
        if not data:
            raise ValueError, "Packet too small"
        self.ver = ord(data[0])
        if self.ver == 2 or self.ver == 3:
            if len(data) < 8:
                raise ValueError, "Packet too small"
            (self.creation_time, self.validity, self.pubkey_alg) = \
                                 struct.unpack(">IHB", data[1:8])
            self.value_start = 8
            # We only know how to compute the key ID for RSA
            if (self.pubkey_alg not in _pubkey_alg_data
                or _pubkey_alg_data[self.pubkey_alg][1] != _ALG_PK_RSA):
                raise ValueError, ("Version %s %s is not an RSA key"
                                   % self.ver, self.desc)
            if len(self.data) < 10:
                raise ValueError, "Invalid RSA key"
        elif self.ver == 4:
            if len(data) < 6:
                raise ValueError, "Packet too small"
            (self.creation_time, self.pubkey_alg) \
                                 = struct.unpack(">IB", data[1:6])
            self.validity = None
            self.value_start = 6
            # We don't know how to compute key ID for larger packets
            if len(self.data) > 0xFFFF:
                raise ValueError, "Key packet too large for key ID computation"
        else:
            raise NotImplementedError, \
                  "Unknown public key version %s" % self.ver
        self.key_id = None

    def keyID(self):
        """Return key ID of this key."""

        if self.key_id is not None:
            return self.key_id
        if self.ver == 2 or self.ver == 3:
            # We only know how to compute the key ID for RSA
            if (self.pubkey_alg not in _pubkey_alg_data
                or _pubkey_alg_data[self.pubkey_alg][1] != _ALG_PK_RSA):
                raise AssertionError, "Key is not an RSA key"
            (bits,) = struct.unpack(">H", self.data[8:10])
            bytes = (bits + 7) / 8
            if bytes >= 8:
                self.key_id = self.data[10 + bytes - 8 : 10 + bytes]
            else:
                self.key_id = '\0' * (8 - bytes) + self.data[10 : 10 + bytes]
        elif self.ver == 4:
            digest = sha.new('\x99')
            if len(self.data) > 0xFFFF:
                raise AssertionError, "Key packet too large"
            digest.update(struct.pack(">H", len(self.data)) + self.data)
            self.key_id = digest.digest()[12:]
        else:
            raise AssertionError, "Unreachable"
        return self.key_id

    def __str__(self):
        if self.pubkey_alg in _pubkey_alg_data:
            pubkey_alg = _pubkey_alg_data[self.pubkey_alg][0]
        else:
            pubkey_alg = "pubkey %s" % self.pubkey_alg
        return ("%s(v%s, %s, %s, %s)"
                % (self.desc, self.ver, self.creation_time, self.validity,
                   pubkey_alg))

class _PublicKeyPacket(_PublicKeyPacket__):
    """A public key packet (tag 6)."""

    desc = "pubkey"

class _PublicSubkeyPacket(_PublicKeyPacket__):
    """A public subkey packet (tag 14)."""

    desc = "pubsubkey"


class _MarkerPacket(_PGPPacket):
    """A marker packet (tag 10)."""

    def __init__(self, tag, data):
        _PGPPacket.__init__(self, tag, data)
        if data != "PGP":
            raise NotImplementedError, "Unknown marker packet value"

    def __str__(self):
        return "marker"


class _TrustPacket(_PGPPacket):
    """A trust packet (tag 12)."""

    # Contents are unspecified
    def __str__(self):
        return "trust"


class _UserIDPacket(_PGPPacket):
    """An User ID packet (tag 13)."""

    def __str__(self):
        return "uid(%s)" % repr (self.data)

class _UserAttributePacket(_PGPPacket):
    """An User Attribute packet (tag 17)."""

    # FIXME: implement something more detailed?
    def __str__(self):
        return "uattr(...)"

_PGP_packet_types = {
    # 1: _PubKeyEncryptedSessionKeyPacket,
    2: _SignaturePacket, # 3: _SymmKeyEncryptedSessionKeyPacket,
    # 4: _OnePassSignaturePacket, 5: _SecretKeyPacket
    6: _PublicKeyPacket, # 7: SecretSubkeyPacket, 8: CompressedDataPacket,
    # 9: SymmEncryptedDataPacket,
    10: _MarkerPacket, # 11: LiteralDataPacket,
    12: _TrustPacket, 13: _UserIDPacket, 14: _PublicSubkeyPacket,
    17: _UserAttributePacket, # 18: SymmEncryptedIntegrityProtectedDataPacket,
    # 19: ModificationDetectionCodePacket
}


 # OpenPGP message parsing
def _decodeArmor(data):
    """Decode ASCII Armored data.

    Return raw data.  Raise ValueError on invalid or corrupt data.

    The data type in armor header is ignored.  Armor headers are checked, but
    their values are ignored."""

    lines = data.splitlines()
    if not lines:
        raise ValueError, "Missing armor header line"
    if (not lines[0].startswith("-----BEGIN PGP ")
        or not lines[0].endswith("-----")):
        raise ValueError, "Invalid armor header line %s" % lines[0]
    header_type = lines[0][15:-5]
    # Allows invalid multipart specifications
    if (header_type not in ["MESSAGE", "PUBLIC KEY BLOCK", "PRIVATE KEY BLOCK",
                            "SIGNATURE"]
        and not header_type.startswith("MESSAGE, PART ")):
        raise ValueError, "Unknown armor header line text"
    lines.pop(0);
    while lines and lines[0].strip() != '':
        delim = lines[0].find(": ", 1);
        if delim == -1:
            raise ValueError, "Invalid armor header %s" % lines[0]
        if lines[0][:delim] not in ["Version", "Comment", "MessageID", "Hash",
                                    "Charset"]:
            log.warning("Unknown armor header", lines[0])
        lines.pop(0)
    if not lines:
        raise ValueError, "Missing end of armor headers"
    lines.pop(0)
    for i in xrange(len(lines)):
        if lines[i] == "-----END PGP " + header_type + "-----":
            lines = lines[:i]
            break
    else:
        raise ValueError, "Missing armor tail"
    data = string.join(lines, "")
    # The checksum seems to be optional; we can detect it by looking at the
    # string, but that requires filtering out all unwanted bytes.
    data = [c for c in data
            if c in ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "abcdefghijklmnopqrstuvwxyz0123456789+/=")]
    data = string.join(data, "")
    # The '=' padding character is never at the start of a 4-character group
    # in base64; the checksum is after the last group.
    if len(data) >= 4 + 1 + 4 and len(data) % 4 == 1 and data[-5] == '=':
        csum = data[-4:]
        data = data[:-5]
    else:
        csum = None
    try:
        data = base64.decodestring(data)
    except binascii.Error:
        raise ValueError, "Invalid base64 data"
    if csum is not None:
        try:
            csum = base64.decodestring(csum)
        except binascii.Error:
            raise ValueError, "Invalid base64 checksum"
        csum = (ord(csum[0]) << 16) | (ord(csum[1]) << 8) | ord(csum[2])
        # CRC32 based on the code in RFC 2440 p6.1
        crc = 0xB704CE
        for b in data:
            crc ^= ord(b) << 16
            for i in xrange(8):
                crc <<= 1
                if (crc & 0x1000000) != 0:
                    crc ^= 0x1864CFB
        crc &= 0xFFFFFF
        if csum != crc:
            raise ValueError, "CRC mismatch: %x vs %x" % (csum, crc)
    return data


def parseRawPGPMessage(data):
    """Return a list of PGPPackets parsed from input data.

    Raise ValueError on invalid data."""

    if data.startswith("-----BEGIN"):
        data = _decodeArmor(data)
    res = []
    start = 0
    while start < len(data):
        tag = ord(data[start])
        if (tag & 0x80) == 0:
            raise ValueError, "Invalid packet tag 0x%02X" % tag
        if (tag & 0x40) == 0:
            ltype = tag & 0x03
            tag = (tag & 0x3C) >> 2
            if ltype == 0:
                offset = 2
                if len(data) < start + 1:
                    raise ValueError, "Not enough data for packet"
                length = ord(data[start + 1])
            elif ltype == 1:
                offset = 3
                if len(data) < start + 3:
                    raise ValueError, "Not enough data for packet"
                (length,) = struct.unpack(">H", data[start + 1 : start + 3])
            elif ltype == 2:
                offset = 5
                if len(data) < start + 5:
                    raise ValueError, "Not enough data for packet"
                (length,) = struct.unpack(">I", data[start + 1 : start + 5])
            elif ltype == 3:
                offset = 1
                length = len(data) - start - 1
        else:
            tag &= 0x3F
            len1 = ord(data[start + 1])
            if len1 < 192:
                offset = 2
                length = len1
            elif len1 < 224:
                offset = 3
                if len(data) < start + 3:
                    raise ValueError, "Not enough data for packet"
                length = ((len1 - 192) << 8) + ord(data[start + 2]) + 192
            elif len1 == 255:
                offset = 6
                if len(data) < start + 6:
                    raise ValueError, "Not enough data for packet"
                (length,) = struct.unpack(">I", data[start + 2 : start + 6])
            else:
                # Allowed only for literal/compressed/encrypted data packets
                raise NotImplementedError, "Unsupported partial body length"
        if len(data) < start + offset + length:
            raise ValueError, "Not enough data for packet"
        if tag == 0:
            raise ValueError, "Tag 0 is reserved"
        class_ = _PGP_packet_types.get(tag, _PGPPacket)
        res.append(class_(tag, data[start + offset : start + offset + length]))
        start += offset + length
    return res


def parsePGPMessage(data):
    """Return a list of PGPPackets parsed from input data, dropping marker and
    trust packets.

    Raise ValueError on invalid data."""

    return [packet for packet in parseRawPGPMessage(data)
            if (not isinstance(packet, _MarkerPacket)
                and not isinstance(packet, _TrustPacket))]


def parsePGPSignature(data):
    """Return a _SignaturePacket parsed from detached signature on input.

    Raise ValueError on invalid data."""

    packets = parsePGPMessage(data)
    if len(packets) != 1 or not isinstance(packets[0], _SignaturePacket):
        raise ValueError, "Input is not a detached signature"
    return packets[0]


def isolateASCIIArmor(data):
    """Assuming data contains an ASCII-armored message, possibly with some
    prefix and suffix, return only the ASCII-armored message.

    Return the isolated part, or the original data if the message is not
    ASCII-armored."""

    if data.find("-----BEGIN PGP ") == -1:
        return data
    lines = data.splitlines()
    if not lines:
        return data
    for i in xrange(len(lines)):
        if lines[i].startswith("-----BEGIN PGP "):
            lines = lines[i:]
            break
    else:
        return data
    for i in xrange(len(lines)):
        if lines[i].startswith("-----END PGP "):
            lines = lines[: i + 1]
            break
    else:
        return data
    return '\n'.join(lines) + '\n'


 # Key storage
def _mergeSigs(dest, src):
    """Merge list of signature packets src to dest."""

    s = {}
    for sig in dest:
        s[sig.data] = None
    for sig in src:
        if sig.data not in s:
            dest.append(sig)
            s[sig.data] = None


class _PublicKey:
    """A parsed public key, with optional subkeys."""

    def __init__(self, packets):
        """Parse a public key from list of packets.

        Raise ValueError on invalid input.

        The list of packets should not contain trust packets any more.
        Handled packets are removed from the list."""

        p = _popListHead(packets)
        if not isinstance(p, _PublicKeyPacket):
            raise ValueError, \
                  "Public key does not start with a public key packet"
        self.primary_key = p
        self.unique_id = p.data

        p = _popListHead(packets)
        self.primary_revocation = None
        if (isinstance(p, _SignaturePacket)
            and p.sigtype == _SignaturePacket.ST_KEY_REVOCATION):
            # FIXME: check revocations when checking signatures
            # VERIFY: verify the signature?
            self.primary_revocation = p
            p = _popListHead(packets)
        self.direct_sigs = []
        while isinstance(p, _SignaturePacket):
            if p.sigtype != _SignaturePacket.ST_DIRECT:
                raise ValueError, ("Unexpected signature type 0x%02X after "
                                   "public key packet" % p.sigtype)
            self.direct_sigs.append(p)
            p = _popListHead(packets)

        # VERIFY: primary key must be capable of signing (on selfsignature)
        # VERIFY: check primary key has not expired (on selfsignature on v4)
        #        (but what if it has?)
        h = {}
        self.user_ids = []
        have_uid = False
        while isinstance(p, (_UserIDPacket, _UserAttributePacket)):
            if isinstance(p, _UserIDPacket):
                have_uid = True
            uid = p
            if uid.data not in h:
                sigs = []
                self.user_ids.append((uid, sigs))
                h[uid.data] = sigs
            else:
                sigs = h[uid.data]
            new = []
            p = _popListHead(packets)
            while isinstance(p, _SignaturePacket):
                new.append(p)
                p = _popListHead(packets)
            _mergeSigs(sigs, new)
        if not have_uid:
            raise ValueError, "Missing User ID packet"
        del h

        self.subkeys = []
        while isinstance(p, _PublicSubkeyPacket):
            subkey = p
            sigs = []
            p = _popListHead(packets)
            while isinstance (p, _SignaturePacket):
                # BADFORMAT: 0x75BE8097, "Florian Lohoff <flo@rfc822.org>"
                # has ceritification signatures on a subkey, we just ignore
                # them
                if p.sigtype != _SignaturePacket.ST_CERT_GENERIC:
                    # Too many keys have revocation signatures after binding
                    # signatures :-(
                    if (p.sigtype != _SignaturePacket.ST_SUBKEY
                        and (p.sigtype
                             != _SignaturePacket.ST_SUBKEY_REVOCATION)):
                        raise ValueError, \
                              ("Unexpected subkey signature type 0x%02X"
                               % p.sigtype)
                    # VERIFY: subkey binding signatures are by the primary key
                    sigs.append(p)
                p = _popListHead(packets)
            self.subkeys.append((subkey, sigs))
        if p is not None:
            raise ValueError, "Unexpected trailing packet of type %s" % p.tag

    def __str__(self):
        ret = ""
        for (uid, _) in self.user_ids:
            # Ignore _UserAttributePackets
            if isinstance(uid, _UserIDPacket):
                if ret:
                    ret += "\naka "
                ret += uid.data
        return ret

    def keyPackets(self):
        """Return key packets in this key."""

        return [self.primary_key] + [subkey for (subkey, _) in self.subkeys]

    def keyIDs(self):
        """Return key IDs of keys in this key."""

        return [packet.keyID() for packet in self.keyPackets()]

    def keyPacketsWithID(self, id):
        """Return a list of key packets maching a key ID."""

        return [packet for packet in self.keyPackets() if packet.keyID() == id]

    def merge(self, other):
        """Merge data from other key with the same unique_id."""

        # One revocation is enough
        # VERIFY: ... assuming it is valid
        if (other.primary_revocation is not None
            and (self.primary_revocation is None
                 or self.primary_revocation.hashed_sp["sign_time"] >
                 other.primary_revocation.hashed_sp["sign_time"])):
            self.primary_revocation = other.primary_revocation

        _mergeSigs(self.direct_sigs, other.direct_sigs)

        h = {}
        for (uid, sigs) in self.user_ids:
            h[uid.data] = sigs
        for (uid, sigs) in other.user_ids:
            if uid.data not in h:
                sigs = sigs[:]
                self.user_ids.append((uid, sigs))
                h[uid.data] = sigs
            else:
                _mergeSigs(h[uid.data], sigs)

        h = {}
        for (subkey, sigs) in self.subkeys:
            h[subkey.data] = sigs
        for (subkey, sigs) in other.subkeys:
            if subkey.data not in h:
                sigs = sigs[:]
                self.subkeys.append((subkey, sigs))
                h[subkey.data] = sigs
            else:
                _mergeSigs(h[subkey.data], sigs)


def parsePGPKeys(data):
    """Return a list of _PublicKeys parsed from input data.

    Raise ValueError on invalid input."""

    packets = parsePGPMessage(data)
    keys = []
    start = 0;
    while start < len(packets):
        for end in xrange(start + 1, len(packets)):
            if isinstance(packets[end], _PublicKeyPacket):
                break
        else:
            end = len(packets)
        keys.append(_PublicKey(packets[start:end]))
        start = end
    return keys


class PGPKeyRing:
    """A set of keys, allowing lookup by key IDs."""

    def __init__(self):
        # unique_id => key
        self.keys = {}
        self.by_key_id = {}

    def addKey(self, key):
        """Add a _PublicKey."""

        if key.unique_id in self.keys:
            k = self.keys[key.unique_id]
            k.merge(key)
            key = k
        else:
            self.keys[key.unique_id] = key
        for key_id in key.keyIDs():
            if key_id not in self.by_key_id:
                self.by_key_id[key_id] = [key]
            else:
                l = self.by_key_id[key_id]
                if key not in l:
                    l.append(key)

# vim:ts=4:sw=4:showmatch:expandtab
