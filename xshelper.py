#!/usr/bin/env python3

from __future__ import annotations
from typing import (Callable, ClassVar, Dict, List, Mapping, NewType, Optional, Tuple,
        TypedDict, TypeVar, Type, cast, overload)

import abc
import base58
import base64
import json
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat

IV = NewType('IV', bytes)
MAC = NewType('MAC', bytes)
Signature = NewType('Signature', bytes)

class PrivateKey:
    _priv: ed25519.Ed25519PrivateKey

    def __init__(self, priv: ed25519.Ed25519PrivateKey):
        self._priv = priv

    def public_key(self) -> PublicKey:
        return PublicKey(self._priv.public_key())

    @classmethod
    def from_B64Str(cls, data: B64Str) -> PrivateKey:
        return PrivateKey(ed25519.Ed25519PrivateKey.from_private_bytes(data.to_bytes()))

    def sign_dict(self, data: Mapping[str, object]) -> Signature:
        clean = dict(data)
        clean.pop("signatures", None)
        clean.pop("unsigned", None)
        return Signature(self._priv.sign(canonical_json(clean)))

class PublicKey:
    _pub: ed25519.Ed25519PublicKey

    def __init__(self, pub: ed25519.Ed25519PublicKey):
        self._pub = pub

    @classmethod
    def from_B64Str(cls, data: B64Str) -> PublicKey:
        return PublicKey(ed25519.Ed25519PublicKey.from_public_bytes(data.to_bytes()))

    def to_B64Str(self) -> B64Str:
        return B64Str.from_bytes(self._pub.public_bytes(Encoding.Raw, PublicFormat.Raw))

    def verify_dict(self, data: Mapping[str, object], signature: Signature) -> None:
        clean = dict(data)
        clean.pop("signatures", None)
        clean.pop("unsigned", None)
        self._pub.verify(signature, canonical_json(clean))

    def __repr__(self) -> str:
        return 'PublicKey({})'.format(self.to_B64Str().unpad())

class KeyPair:
    private: Optional[PrivateKey]
    public: PublicKey

    @overload
    def __init__(self, private: PrivateKey, public: PublicKey):
        pass

    @overload
    def __init__(self, private: None, public: PublicKey):
        pass

    @overload
    def __init__(self, private: PrivateKey, public: None):
        pass

    def __init__(self, private: Optional[PrivateKey], public: Optional[PublicKey]):
        self.private = None

        if not private:
            if not public:
                raise ValueError("No public key!")

            self.public = public
            return

        self.private = private
        self.public = private.public_key()

        if public and self.public.to_B64Str() != public.to_B64Str():
            raise ValueError("Invalid public key!")

    def __repr__(self) -> str:
        return 'KeyPair(private: {}, public: {})'.format(self.private, self.public)

ABT = TypeVar('ABT', bound='AbstractB64Str')
class AbstractB64Str(str):
    def __new__(cls: Type[ABT], data: str) -> ABT:
        pdata = AbstractB64Str._pad(data)
        base64.b64decode(pdata.encode('utf-8'), validate = True)

        return super().__new__(cls, data) # type: ignore

    @classmethod
    def from_bytes(cls: Type[ABT], data: bytes) -> ABT:
        return cls(base64.b64encode(data).decode('utf-8'))

    def to_bytes(self) -> bytes:
        return base64.b64decode(AbstractB64Str._pad(self).encode('utf-8'))

    @staticmethod
    def _pad(data: str) -> str:
        p_needed = 4 - len(data) % 4
        if p_needed < 4:
            return data + '=' * p_needed
        return data

    @staticmethod
    def _unpad(data: str) -> str:
        return data.rstrip('=')

class B64Str(AbstractB64Str):
    def __new__(cls, data: str) -> B64Str:
        pdata = AbstractB64Str._pad(data)
        return super().__new__(cls, pdata) # type: ignore

    def unpad(self) -> B64StrU:
        return B64StrU(self)

class B64StrU(AbstractB64Str):
    def __new__(cls, data: str) -> B64StrU:
        udata = AbstractB64Str._unpad(data)
        return super().__new__(cls, udata) # type: ignore

    def pad(self) -> B64Str:
        return B64Str(self)

class B58Str(str):
    def __new__(cls, data: str) -> B58Str:
        base58.b58decode(data)
        return super().__new__(cls, data) # type: ignore

    @classmethod
    def from_bytes(cls, data: bytes) -> B58Str:
        return cls(base58.b58encode(data).decode('utf-8'))

    def to_bytes(self) -> bytes:
        return base58.b58decode(self.encode('utf-8'))

class SecretKey(bytes):
    pass

class SSSSException(Exception):
    pass

class SSSSDerivedKeys:
    aes_key: SecretKey
    hmac_key: SecretKey

    def __init__(self, aes_key: SecretKey, hmac_key: SecretKey):
        self.aes_key = aes_key
        self.hmac_key = hmac_key

class SSSSKey(SecretKey):
    def derive_keys(self, name: str) -> SSSSDerivedKeys:
        hkdf = HKDF(SHA256(), 64, None, name.encode('utf-8'), backend = default_backend())
        kmat = hkdf.derive(self)
        aes_key = SecretKey(kmat[:32])
        hmac_key = SecretKey(kmat[32:])
       
        return SSSSDerivedKeys(aes_key, hmac_key)

    @classmethod
    def from_B58Str(cls, keystr: B58Str) -> SSSSKey:
        key = keystr.to_bytes()

        parity = 0
        for b in key:
            parity = parity ^ b
        if parity != 0:
            raise ValueError("Invalid key parity!")

        if not key.startswith(b'\x8b\x01'):
            raise ValueError("Invalid key prefix!")

        if not len(key) == 32 + 2 + 1:
            raise ValueError("Invalid key length!")

        return cls(key[2:-1])

    def verify(self, keydat: KeyIntegrityData) -> None:
        if keydat.algorithm != 'm.secret_storage.v1.aes-hmac-sha2':
            raise NotImplementedError("Key verification algorithm not supported!")

        zdat = b'\x00' * 32
        zenc = SSSSData.encrypt(zdat, self, '', keydat.iv)

        if not bytes_eq(keydat.mac, zenc.mac):
            raise SSSSException("Invalid key MAC!")

class SSSSDataDict(TypedDict):
    mac: str
    iv: str
    ciphertext: str

class SSSSData:
    mac: MAC
    iv: IV
    ciphertext: bytes

    def __init__(self, mac: MAC, iv: IV, ciphertext: bytes):
        self.mac = mac
        self.iv = iv
        self.ciphertext = ciphertext

    @classmethod
    def from_dict(cls, data: SSSSDataDict) -> SSSSData:
        mac = MAC(B64Str(data['mac']).to_bytes())
        iv = IV(B64Str(data['iv']).to_bytes())
        ciphertext = B64Str(data['ciphertext']).to_bytes()
        return cls(mac, iv, ciphertext)

    def decrypt(self: SSSSData, key: SSSSKey, name: str) -> bytes:
        keys = key.derive_keys(name)

        ct = self.ciphertext

        hm = HMAC(keys.hmac_key, SHA256(), backend = default_backend())
        hm.update(ct)
        hm.verify(self.mac)

        iv = IV(self.iv)
        return aes256ctr(iv, keys.aes_key, ct)

    @classmethod
    def encrypt(cls, data: bytes, key: SSSSKey, name: str, iv: Optional[IV] = None) -> SSSSData:
        if iv:
            ivb = bytearray(iv)
        else:
            ivb = bytearray(secrets.token_bytes(16))

        ivb[8] = ivb[8] & 0x7f;
        iv = IV(bytes(ivb))

        keys = key.derive_keys(name)
        ct = aes256ctr(iv, keys.aes_key, data)

        hm = HMAC(keys.hmac_key, SHA256(), backend = default_backend())
        hm.update(ct)
        mac = MAC(hm.finalize())

        return cls(mac, iv, ct)

class KeyIntegrityDataDict(TypedDict):
    mac: str
    iv: str
    algorithm: str

class KeyIntegrityData:
    mac: MAC
    iv: IV
    algorithm: str

    def __init__(self, mac: MAC, iv: IV, algorithm: str):
        self.mac = mac
        self.iv = iv
        self.algorithm = algorithm

    @classmethod
    def from_dict(cls, data: KeyIntegrityDataDict) -> KeyIntegrityData:
        mac = MAC(B64Str(data['mac']).to_bytes())
        iv = IV(B64Str(data['iv']).to_bytes())
        algorithm = data['algorithm']
        return cls(mac, iv, algorithm)

def aes256ctr(iv: IV, key: SecretKey, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# from https://matrix.org/docs/spec/appendices#signing-json
def canonical_json(value):
    return json.dumps(
	value,
	# Encode code-points outside of ASCII as UTF-8 rather than \u escapes
	ensure_ascii=False,
	# Remove unnecessary white space.
	separators=(',',':'),
	# Sort the keys of dictionaries.
	sort_keys=True,
	# Encode the resulting unicode as UTF-8 bytes.
    ).encode("UTF-8")

class KeyDict(TypedDict):
    keys: Dict[str, str]
    signatures: Dict[str, Dict[str, str]]
    user_id: str

class XSigningKeyDict(KeyDict):
    usage: List[str]

class DeviceKeyDict(KeyDict):
    algorithms: List[str]
    device_id: str
    unsigned: dict

class XSigningKeyRingException(Exception):
    pass

class XSigningKeyRing:
    master_key: PublicKey
    user_id: str
    self_signing_key: Optional[KeyPair]
    user_signing_key: Optional[KeyPair]
    device_keys: Dict[str, PublicKey]

    def __init__(self, master_pub: PublicKey, user_id: str):
        self.master_key = master_pub
        self.user_id = user_id
        self.self_signing_key = None
        self.user_signing_key = None
        self.device_keys = dict()

    def __repr__(self) -> str:
        return ('XSigningKeyRing(master: {}, user_id: {},'
                ' self_signing: {}, user_signing: {}, device_keys: {})').format(
                self.master_key, self.user_id,
                self.self_signing_key, self.user_signing_key, self.device_keys)

    def __str__(self) -> str:
        ss_b64 = None
        if self.self_signing_key:
            ss_b64 = self.self_signing_key.public.to_B64Str().unpad()

        us_b64 = None
        if self.user_signing_key:
            us_b64 = self.user_signing_key.public.to_B64Str().unpad()

        devkeys = ''
        for dev_id, pub in self.device_keys.items():
            pub_b64 = pub.to_B64Str().unpad()
            devkeys = devkeys + (
                    "\n        {}: {}".format(dev_id, pub_b64)
            )

        return (
                "User {}:\n"
                "    Master Key: {}\n"
                "    Self-signing Key: {}\n"
                "        Signed Devices: {}\n"
                "    User-signing Key: {}"
        ).format(
                self.user_id,
                self.master_key.to_B64Str().unpad(),
                ss_b64,
                '{}',
                us_b64
        ).format(devkeys or "None")

    @classmethod
    def from_master_key_dict(cls, priv: Optional[PrivateKey], keydat: XSigningKeyDict) -> XSigningKeyRing:
        if "master" not in keydat['usage']:
            raise ValueError("Invalid key usage type!")

        user_id = keydat['user_id']
        kp = XSigningKeyRing._get_keypair(priv, keydat)

        return XSigningKeyRing(kp.public, user_id)

    def get_master_key_dict(self) -> XSigningKeyDict:
        ms_b64 = self.master_key.to_B64Str().unpad()
        return XSigningKeyDict({
            "keys": {
                'ed25519:' + ms_b64: ms_b64
            },
            "usage": [ "master" ],
            "user_id": self.user_id,
            "signatures": {}
        })

    def sign_user_key(self, to_sign: XSigningKeyDict) -> XSigningKeyDict:
        if not self.user_signing_key:
            raise XSigningKeyRingException("No private user-signing key!")
        if not self.user_signing_key.private:
            raise XSigningKeyRingException("No private user-signing key!")

        priv = self.user_signing_key.private
        pub = priv.public_key()
        pub_b64 = pub.to_B64Str().unpad()

        sig = priv.sign_dict(to_sign)
        sig_b64 = B64Str.from_bytes(sig).unpad()
        to_sign['signatures'][self.user_id] = {
            'ed25519:' + pub_b64: sig_b64
        }

        return to_sign

    def _check_signature(self, pub: PublicKey, keydat: KeyDict, kid: Optional[str] = None) -> None:
        if not kid:
            kid = pub.to_B64Str().unpad()

        if not self.user_id in keydat['signatures']:
            raise XSigningKeyRingException("Not signed by this user!")

        if not 'ed25519:' + kid in keydat['signatures'][self.user_id]:
            raise XSigningKeyRingException("Not signed by this key!")

        sig = Signature(B64Str(keydat['signatures'][self.user_id]['ed25519:' + kid]).to_bytes())
        pub.verify_dict(keydat, sig)

    @staticmethod
    def _get_keypair(priv: Optional[PrivateKey], keydat: XSigningKeyDict) -> KeyPair:
        if not keydat['keys']:
            raise ValueError("No keys!")

        if len(keydat['keys']) > 1:
            raise ValueError("No keys!")

        # assume just one key
        pub = PublicKey.from_B64Str(B64Str(next(iter(keydat['keys'].values()))))
        return KeyPair(priv, pub)

    def set_self_signing_key(self, priv: Optional[PrivateKey], keydat: XSigningKeyDict) -> None:
        if "self_signing" not in keydat['usage']:
            raise ValueError("Invalid key usage type!")

        if self.user_id != keydat['user_id']:
            raise ValueError("Invalid user ID!")

        self._check_signature(self.master_key, keydat)
        self.self_signing_key = XSigningKeyRing._get_keypair(priv, keydat)

    def set_user_signing_key(self, priv: Optional[PrivateKey], keydat: XSigningKeyDict) -> None:
        if "user_signing" not in keydat['usage']:
            raise ValueError("Invalid key usage type!")

        if self.user_id != keydat['user_id']:
            raise ValueError("Invalid user ID!")

        self._check_signature(self.master_key, keydat)
        self.user_signing_key = XSigningKeyRing._get_keypair(priv, keydat)

    def add_device_key(self, keydat: DeviceKeyDict) -> str:
        if self.user_id != keydat['user_id']:
            raise ValueError("Invalid user ID!")

        if not self.self_signing_key:
            raise ValueError("No self-signing key set!")

        self._check_signature(self.self_signing_key.public, keydat)

        dev_id = keydat['device_id']
        if not 'ed25519:' + dev_id in keydat['keys']:
            raise ValueError("No key for device!")

        pub = PublicKey.from_B64Str(B64Str(keydat['keys']['ed25519:' + dev_id]))
        self._check_signature(pub, keydat, dev_id)

        self.device_keys[dev_id] = pub

        return dev_id

    def verify_user_key(self, keydat: XSigningKeyDict) -> None:
        if "master" not in keydat['usage']:
            raise ValueError("Invalid key usage type!")

        if not self.user_signing_key:
            raise XSigningKeyRingException("No user-signing key set!")

        self._check_signature(self.user_signing_key.public, keydat)

    # TODO: function to verify device key via own device key... probably have
    # to rework verify_user_key_by_device too... perhaps make separate device
    # signing keyring, probably safer to do it explicitly though...
    def verify_user_key_by_device(self, keydat: XSigningKeyDict) -> None:
        if "master" not in keydat['usage']:
            raise ValueError("Invalid key usage type!")

        if not self.device_keys:
            raise XSigningKeyRingException("No device keys present!")

        if not self.user_id in keydat['signatures']:
            raise XSigningKeyRingException("Not signed by this user!")

        for dev_id, pub in self.device_keys.items():
            if 'ed25519:' + dev_id in keydat['signatures'][self.user_id]:
                self._check_signature(pub, keydat, dev_id)
                return

        raise XSigningKeyRingException("Not signed by any device key!")

import requests
import warnings

class MatrixClient:
    MATRIX_KEY_QUERY_EP: ClassVar[str] = '/_matrix/client/r0/keys/query'
    MATRIX_ACCT_DATA_EP: ClassVar[str] = '/_matrix/client/r0/user/{userId}/account_data/{type}'
    MATRIX_SIG_UPLOAD_EP: ClassVar[str] = '/_matrix/client/unstable/keys/signatures/upload'
    base_url: str
    headers: Dict[str, str]

    def __init__(self, base_url: str, auth_token: str):
        self.base_url = base_url
        self.headers = dict({'Authorization': 'Bearer ' + auth_token})

    def get_account_data(self, user_id: str, type: str) -> dict:
        r = requests.get(self.base_url +
                MatrixClient.MATRIX_ACCT_DATA_EP.format(userId=user_id, type=type),
                headers = self.headers)
        r.raise_for_status()
        return r.json()

    def get_user_keys(self, user_id: str) -> dict:
        r = requests.post(self.base_url + MatrixClient.MATRIX_KEY_QUERY_EP,
                json = {"device_keys":{user_id:[]}}, headers = self.headers)
        r.raise_for_status()
        return r.json()

    def post_user_signature(self, user_id: str, key_id: str, keydat: XSigningKeyDict) -> None:
        r = requests.post(self.base_url + MatrixClient.MATRIX_SIG_UPLOAD_EP,
                json = {user_id:{key_id:keydat}}, headers = self.headers)
        r.raise_for_status()

class SSSSClient:
    mc: MatrixClient
    user_id: str
    key: SSSSKey
    key_id: str

    def __init__(self, mc: MatrixClient, user_id: str, key: SSSSKey, key_id: Optional[str] = None):
        # TODO: enforce format of key id and user id somehow (regex)
        self.mc = mc
        self.user_id = user_id
        self.key = key

        if not key_id:
            r = self.mc.get_account_data(self.user_id, 'm.secret_storage.default_key')
            self.key_id = r['key']
        else:
            self.key_id = key_id

    def verify_key_integrity(self) -> None:
        r = self.mc.get_account_data(self.user_id, 'm.secret_storage.key.{}'.format(self.key_id))
        # TODO: proper checks instead of cast
        self.key.verify(KeyIntegrityData.from_dict(cast(KeyIntegrityDataDict, r)))

    def get_data(self, name: str) -> bytes:
        r = self.mc.get_account_data(self.user_id, name)
        sd = SSSSData.from_dict(r['encrypted'][self.key_id])
        return sd.decrypt(self.key, name)

class KeyQueryDict(TypedDict):
    device_keys: Dict[str, Dict[str, DeviceKeyDict]]
    master_keys: Dict[str, XSigningKeyDict]
    self_signing_keys: Dict[str, XSigningKeyDict]
    user_signing_keys: Dict[str, XSigningKeyDict]

def build_keyring(keys: KeyQueryDict, user_id: str,
        master_key: Optional[PrivateKey] = None,
        self_signing_key: Optional[PrivateKey] = None,
        user_signing_key: Optional[PrivateKey] = None) -> XSigningKeyRing:
    if user_id not in keys['master_keys']:
        raise ValueError("No master key!")
    if user_id not in keys['self_signing_keys']:
        raise ValueError("No self-signing key!")

    # init keyring
    kr = XSigningKeyRing.from_master_key_dict(master_key, keys['master_keys'][user_id])
    if kr.user_id != user_id:
        raise ValueError("Invalid user ID!")

    kr.set_self_signing_key(self_signing_key, keys['self_signing_keys'][user_id])

    if user_id in keys['user_signing_keys']:
        kr.set_user_signing_key(user_signing_key, keys['user_signing_keys'][user_id])

    if user_id not in keys['device_keys']:
        warnings.warn("No devices for user {}!".format(user_id))
        return kr

    for dev_id, dat in keys['device_keys'][user_id].items():
        try:
            if dev_id != kr.add_device_key(dat):
                raise ValueError("Invalid device ID!")
        except (ValueError, XSigningKeyRingException) as e:
            warnings.warn("No signature for {}'s device {}: {}".format(user_id, dev_id, e))

    return kr

def build_own_keyring(keys: KeyQueryDict, user_id: str,
        master_key: PrivateKey, self_signing_key: PrivateKey,
        user_signing_key: PrivateKey) -> XSigningKeyRing:
    kr = build_keyring(keys, user_id, master_key, self_signing_key, user_signing_key)

    # add user-signing key
    if not kr.user_signing_key:
        raise ValueError("No user-signing key!")

    return kr

def fetch_own_keyring(client: MatrixClient, user_id: str, rkey: B58Str,
        rkey_id: Optional[str] = None) -> XSigningKeyRing:
    # init secret storage client
    ssssc = SSSSClient(client, user_id, SSSSKey.from_B58Str(rkey), rkey_id)
    ssssc.verify_key_integrity()

    # obtain cross-signing private keys
    ms_b64 = B64Str(ssssc.get_data("m.cross_signing.master").decode('utf-8'))
    ms = PrivateKey.from_B64Str(ms_b64)
    ss_b64 = B64Str(ssssc.get_data("m.cross_signing.self_signing").decode('utf-8'))
    ss = PrivateKey.from_B64Str(ss_b64)
    us_b64 = B64Str(ssssc.get_data("m.cross_signing.user_signing").decode('utf-8'))
    us = PrivateKey.from_B64Str(us_b64)

    # query keys
    # TODO: proper checks instead of cast
    keys = cast(KeyQueryDict, client.get_user_keys(user_id))

    return build_own_keyring(keys, user_id, ms, ss, us)

def fetch_keyring(client: MatrixClient, user_id: str,
        verifier: Callable[[XSigningKeyDict], None]) -> XSigningKeyRing:
    # query keys
    # TODO: proper checks instead of cast
    keys = cast(KeyQueryDict, client.get_user_keys(user_id))

    # verify master key against given keyring
    verifier(keys['master_keys'][user_id])

    return build_keyring(keys, user_id)

class PublicKeyVerifier:
    pub: PublicKey

    def __init__(self, pub: PublicKey):
        self.pub = pub

    def __call__(self, keydat: XSigningKeyDict) -> None:
        if not keydat['keys']:
            raise ValueError("No keys!")

        if len(keydat['keys']) > 1:
            raise ValueError("No keys!")

        # compare key with given public key
        key_b64 = B64Str(next(iter(keydat['keys'].values())))
        if key_b64 != self.pub.to_B64Str():
            raise ValueError("Invalid public key!")

def InsecureVerifier(keydat: XSigningKeyDict) -> None:
    pass

def post_keyring_signature(client: MatrixClient, signer: XSigningKeyRing, signee: XSigningKeyRing) -> None:
    keydat = signee.get_master_key_dict()
    signed = signer.sign_user_key(keydat)
    signer.verify_user_key(signed)
    client.post_user_signature(signee.user_id, signee.master_key.to_B64Str().unpad(), signed)

# TODO: check if foreign master key is signed by foreign device key which is signed with own device key which is signed by self-signing key (to bootstrap cross-trust from device-trust)
# TODO: validate inputs from server (jsonschema?)

# TODO: potential use cases:
#       listing a user's public keys (optional trust anchor)
#       signing an individual user's master key (trust anchor?)
#       exporting own signatures for later use as trust anchor?
#       signing a list of user's master keys
#       potential turst anchors:
#           - own master key (give pubkey or recovery key to make sure
#           - other list with signatures from other user, anchor with pubkey or by transitivity from own key
#           - other user's master key (give pubkey or insure signed by own key... transitivity?)
#           - just a list of mxid, pubkey tuples
#       difference between own key and other ppl's key user-signing key is accessible

import argparse
import os
import sys

def cmd_list_pubkeys(client: MatrixClient, args: argparse.Namespace) -> None:
    print(fetch_keyring(client, args.target, args.trust_anchor))

class AbstractSelfCached:
    namespace: argparse.Namespace
    client: MatrixClient
    self: Optional[XSigningKeyRing]

    def __init__(self, namespace: argparse.Namespace):
        self.namespace = namespace
        self.self = None

    def set_client(self, client: MatrixClient):
        self.client = client

    @abc.abstractmethod
    def _get_self(self) -> XSigningKeyRing:
        pass

    def __call__(self) -> XSigningKeyRing:
        if not self.self:
            self.self = self._get_self()

        return self.self

class SelfPubkey(AbstractSelfCached):
    def _get_self(self) -> XSigningKeyRing:
        ver = PublicKeyVerifier(self.namespace.pubkey)
        return fetch_keyring(self.client, self.namespace.login, ver)

class SelfRecovery(AbstractSelfCached):
    def _get_self(self) -> XSigningKeyRing:
        return fetch_own_keyring(self.client, self.namespace.login, self.namespace.recovery_key())

class SelfAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None) -> None:
        if values == 'pubkey':
            if not namespace.pubkey:
                parser.error('--pubkey/-p required for --self=pubkey')

            namespace.self = SelfPubkey(namespace)

        else:
            namespace.self = SelfRecovery(namespace)

class TrustAnchorAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None) -> None:
        if values == 'self':
            if not namespace.self:
                parser.error('--self/-s required for --trust-anchor=self')

            def self_verifier(keydat: XSigningKeyDict) -> None:
                namespace.self().verify_user_key(keydat)
            namespace.trust_anchor = self_verifier

        elif values == 'pubkey':
            if not namespace.pubkey:
                parser.error('--pubkey/-p required for --trust-anchor=pubkey')

            def pubkey_verifier(keydat: XSigningKeyDict) -> None:
                PublicKeyVerifier(namespace.pubkey)(keydat)
            namespace.trust_anchor = pubkey_verifier

        else:
            namespace.trust_anchor = InsecureVerifier

def access_token(arg: str) -> Callable[[], str]:
    def access_token_value() -> str:
        return arg
    def access_token_input() -> str:
        return input("Access Token: ")

    if not arg:
        return access_token_input

    return access_token_value

def public_key(arg: str) -> PublicKey:
    return PublicKey.from_B64Str(B64Str(arg))

def recovery_key(arg: str) -> Callable[[], B58Str]:
    def recovery_key_value() -> B58Str:
        return B58Str(arg.replace(' ', ''))
    def recovery_key_input() -> B58Str:
        return B58Str(input("Recovery Key: ").replace(' ', ''))

    if not arg:
        return recovery_key_input

    return recovery_key_value

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "Do some cross-signing things.")

    parser.add_argument('--url', '-u', required=True,
            help="Homeserver URL.")
    parser.add_argument('--login', '-l', required=True,
            help="Your own user's MXID.")
    parser.add_argument('--access-token', '-a',
            default=os.environ.get('MATRIX_ACCESS_TOKEN', ''),
            type=access_token,
            help=(
                "The user's access token. Read from the MATRIX_ACCESS_TOKEN environment "
                "variable or stdin if not specified."))

    parser.add_argument('--pubkey', '-p', type=public_key)

    parser.add_argument('--recovery-key', '-r',
            default=os.environ.get('MATRIX_RECOVERY_KEY', ''),
            type=recovery_key,
            help=(
                "The user's recovery key. Read from the MATRIX_RECOVERY_KEY environment "
                "variable or stdin if not specified and --self=recovery."))
    parser.add_argument('--self', '-s', choices=['pubkey', 'recovery'],
            action=SelfAction,
            help=("How to get your own keys. "
                  "Options are 'recovery', which will fetch the private keys from the "
                  "secret storage, and 'pubkey' (see --pubkey), which will download your "
                  "public keys and check the master key against the specified public key."))

    ta_act = parser.add_argument('--trust-anchor', '-t', default='self',
            choices=['self', 'pubkey', 'none'],
            action=TrustAnchorAction,
            help=(
                "All keys need to be signed directly or indirectly by the trust anchor. "
                "Options are 'self' for your own master key (see --self), "
                "'pubkey' for a Base 64 encoded public key (see --pubkey) "
                "and 'none' for no verification."))

    subparsers = parser.add_subparsers(dest='command', title='commands', required=True,
            help="Available commands.")

    list_p = subparsers.add_parser('list',
            help="List the target user's public keys.")
    list_p.add_argument('target', metavar='MXID',
            help="MXID of the target user.")
    list_p.set_defaults(func=cmd_list_pubkeys)

    parsed_args = parser.parse_args()

    if parsed_args.trust_anchor == ta_act.default:
        ta_act(parser, parsed_args, ta_act.default)

    client = MatrixClient(parsed_args.url, parsed_args.access_token())

    if parsed_args.self:
        parsed_args.self.set_client(client)

    parsed_args.func(client, parsed_args)
