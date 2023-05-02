# -*- encoding: utf-8 -*-
"""
KERIA
gcp-ksm-shim module

"""
import hashlib

import crcmod
import six
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from google.api_core.exceptions import AlreadyExists
from google.api_core.retry import Retry
from google.cloud import kms
from keri.core import coring
from keri.core.coring import MtrDex, Cigar, IdrDex, Siger


class Module:

    def __init__(self, projectId, locationId, keyRingId):
        self.projectId = projectId
        self.locationId = locationId
        self.keyRingId = keyRingId

        # TODO:  Ensure Project and Key Ring exist and user can access them

    def shim(self, **kwargs):
        return GcpKsmShim(projectId=self.projectId, locationId=self.locationId, keyRingId=self.keyRingId, **kwargs)


class GcpKsmShim:
    STEM = 'gcp_ksm_shim'

    def __init__(self, projectId, locationId, keyRingId, pidx, kidx=0, transferable=False, stem=None, count=1, ncount=1,
                 dcode=MtrDex.Blake3_256):

        self.projectId = projectId
        self.locationId = locationId
        self.keyRingId = keyRingId

        self.icount = count
        self.ncount = ncount
        self.dcode = dcode
        self.pidx = pidx
        self.kidx = kidx
        self.transferable = transferable
        self.stem = stem if stem is not None else self.STEM

    def params(self):
        return dict(
            pidx=self.pidx,
            kidx=self.kidx,
            stem=self.stem,
            icount=self.icount,
            ncount=self.ncount,
            dcode=self.dcode,
            transferable=self.transferable
        )

    def incept(self, transferable=True):
        client = kms.KeyManagementServiceClient()

        # Build the parent key ring name.
        key_ring_name = client.key_ring_path(self.projectId, self.locationId, self.keyRingId)

        keys = self._keys(client, key_ring_name, self.icount, self.kidx, transferable)
        nkeys = self._keys(client, key_ring_name, self.ncount, self.kidx + self.icount, True)
        ndigs = [coring.Diger(ser=nkey.encode('utf-8'), code=self.dcode).qb64 for nkey in nkeys]

        return keys, ndigs

    def _keys(self, client, key_ring_name, count, kidx, transferable):
        keys = []
        for idx in range(count):
            keyId = f"{self.stem}-{self.pidx}-{kidx + idx}"

            try:
                client.create_crypto_key(
                    request={'parent': key_ring_name, 'crypto_key_id': keyId, 'crypto_key': key()})
            except AlreadyExists:
                pass
            key_version_name = client.crypto_key_version_path(self.projectId, self.locationId, self.keyRingId, keyId,
                                                              "1")
            signing_public_key = client.get_public_key(request={'name': key_version_name},
                                                       retry=Retry(timeout=60, wait_for_ready=True))

            if not signing_public_key.name == key_version_name:
                raise Exception('The request sent to the server was corrupted in-transit.')
            # See crc32c() function defined below.
            if not signing_public_key.pem_crc32c == crc32c(signing_public_key.pem):
                raise Exception('The response received from the server was corrupted in-transit.')

            pkey = load_pem_public_key(signing_public_key.pem.encode("utf-8"))
            verkey = pkey.public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)
            verfer = coring.Verfer(raw=verkey,
                                   code=coring.MtrDex.ECDSA_256k1 if transferable
                                   else coring.MtrDex.ECDSA_256k1N)
            keys.append(verfer.qb64)

        return keys

    def rotate(self, ncount, transferable):
        client = kms.KeyManagementServiceClient()
        # Build the parent key ring name.
        key_ring_name = client.key_ring_path(self.projectId, self.locationId, self.keyRingId)

        keys = self._keys(client, key_ring_name, self.ncount, self.kidx + self.icount, transferable)
        self.kidx = self.kidx + self.icount
        self.icount = self.ncount
        self.ncount = ncount
        nkeys = self._keys(client, key_ring_name, self.ncount, self.kidx + self.icount, True)
        ndigs = [coring.Diger(ser=nkey, code=self.dcode).qb64 for nkey in nkeys]

        return keys, ndigs

    def sign(self, ser, indexed=True, indices=None, ondices=None, **_):
        client = kms.KeyManagementServiceClient()

        signers = []
        for idx in range(self.icount):
            keyId = f"{self.stem}-{self.pidx}-{self.kidx + idx}"
            key = client.crypto_key_version_path(self.projectId, self.locationId, self.keyRingId, keyId,
                                                 "1")
            signing_public_key = client.get_public_key(request={'name': key},
                                                       retry=Retry(timeout=60, wait_for_ready=True))

            if not signing_public_key.name == key:
                raise Exception('The request sent to the server was corrupted in-transit.')
            # See crc32c() function defined below.
            if not signing_public_key.pem_crc32c == crc32c(signing_public_key.pem):
                raise Exception('The response received from the server was corrupted in-transit.')

            pkey = load_pem_public_key(signing_public_key.pem.encode("utf-8"))
            verkey = pkey.public_bytes(encoding=Encoding.X962, format=PublicFormat.CompressedPoint)
            verfer = coring.Verfer(raw=verkey,
                                   code=coring.MtrDex.ECDSA_256k1 if self.transferable
                                   else coring.MtrDex.ECDSA_256k1N)
            # Calculate the hash.
            hash_ = hashlib.sha256(ser).digest()

            # Build the digest.
            #
            # Note: Key algorithms will require a varying hash function. For
            # example, EC_SIGN_P384_SHA384 requires SHA-384.
            digest = {'sha256': hash_}

            # Optional, but recommended: compute digest's CRC32C.
            # See crc32c() function defined below.
            digest_crc32c = crc32c(hash_)

            # Call the API
            sign_response = client.asymmetric_sign(
                request={'name': key, 'digest': digest, 'digest_crc32c': digest_crc32c})

            # Optional, but recommended: perform integrity verification on sign_response.
            # For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
            # https://cloud.google.com/kms/docs/data-integrity-guidelines
            if not sign_response.verified_digest_crc32c:
                raise Exception('The request sent to the server was corrupted in-transit.')
            if not sign_response.name == key:
                raise Exception('The request sent to the server was corrupted in-transit.')
            if not sign_response.signature_crc32c == crc32c(sign_response.signature):
                raise Exception('The response received from the server was corrupted in-transit.')
            # End integrity verification

            (r, s) = utils.decode_dss_signature(sign_response.signature)
            sig = bytearray(r.to_bytes(32, "big"))
            sig.extend(s.to_bytes(32, "big"))
            signers.append((sig, verfer))

        return sign(signers, indexed, indices, ondices)


def key():
    # Build the key.
    purpose = kms.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN
    algorithm = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_SECP256K1_SHA256
    protection_level = kms.ProtectionLevel.HSM
    return {
        'purpose': purpose,
        'version_template': {
            'algorithm': algorithm,
            'protection_level': protection_level,
        }
    }


def crc32c(data):
    """
    Calculates the CRC32C checksum of the provided data.
    Args:
        data: the bytes over which the checksum should be calculated.
    Returns:
        An int representing the CRC32C checksum of the provided bytes.
    """
    crc32c_fun = crcmod.predefined.mkPredefinedCrcFun('crc-32c')
    return crc32c_fun(six.ensure_binary(data))


def sign(signers, indexed=False, indices=None, ondices=None):
    if indexed:
        sigers = []
        for j, (sig, verfer) in enumerate(signers):
            if indices:  # not the default get index from indices
                i = indices[j]  # must be whole number
                if not isinstance(i, int) or i < 0:
                    raise ValueError(f"Invalid signing index = {i}, not "
                                     f"whole number.")
            else:  # the default
                i = j  # same index as database

            if ondices:  # not the default get ondex from ondices
                o = ondices[j]  # int means both, None means current only
                if not (o is None or
                        isinstance(o, int) and not isinstance(o, bool) and o >= 0):
                    raise ValueError(f"Invalid other signing index = {o}, not "
                                     f"None or not whole number.")
            else:  # default
                o = i  # must both be same value int
            # .sign assigns .verfer of siger and sets code of siger
            # appropriately for single or dual indexed signatures
            sigers.append(ding(sig, verfer,
                               index=i,
                               only=True if o is None else False,
                               ondex=o))
        return [siger.qb64 for siger in sigers]

    else:
        cigars = []
        for sig, verfer in signers:
            cigars.append(ding(sig, verfer, index=None, only=False, ondex=None))  # assigns .verfer to cigar

        return [cigar.qb64 for cigar in cigars]


def ding(sig, verfer, index, only, ondex):
    if index is None:  # Must be Cigar i.e. non-indexed signature
        return Cigar(raw=sig, code=MtrDex.ECDSA_256k1_Sig, verfer=verfer)
    else:  # Must be Siger i.e. indexed signature
        # should add Indexer class method to get ms main index size for given code
        if only:  # only main index ondex not used
            ondex = None
            if index <= 63:  # (64 ** ms - 1) where ms is main index size
                code = IdrDex.ECDSA_256k1_Crt_Sig  # use small current only
            else:
                code = IdrDex.ECDSA_256k1_Big_Crt_Sig  # use big current only
        else:  # both
            if ondex is None:
                ondex = index  # enable default to be same
            if ondex == index and index <= 63:  # both same and small
                code = IdrDex.ECDSA_256k1_Sig  # use  small both same
            else:  # otherwise big or both not same so use big both
                code = IdrDex.ECDSA_256k1_Big_Sig  # use use big both

        return Siger(raw=sig,
                     code=code,
                     index=index,
                     ondex=ondex,
                     verfer=verfer)
