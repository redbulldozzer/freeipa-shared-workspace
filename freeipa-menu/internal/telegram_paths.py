"""Conservative, in-memory repair of Telegram Desktop's global last dialog path.

Only the global tdata/settings{s,0,1} envelope is supported, NOT account files.
The caller must stop Telegram, back up the original, and write atomically with
original ownership. This module never reads files, persists plaintext or logs.

Format references: telegramdesktop/tdesktop, storage/details/
storage_file_utilities.cpp, storage_settings_scheme.h and Local::writeSettings()
in storage/localstorage.cpp. Version 7002005 was verified on the deployed client.
Unknown versions/blocks fail closed: callers should warn and leave files intact.
"""
import ctypes
import ctypes.util
import hashlib
import hmac
import os
import posixpath
import struct

SUPPORTED_VERSIONS = frozenset({7002005})
MAX_SETTINGS_SIZE = 16 * 1024 * 1024


class TelegramPathError(ValueError):
    """Safe-to-display reason for leaving an unsupported settings file intact."""


class _AESKey(ctypes.Structure):
    # OpenSSL's public AES_KEY layout; AES_LONG builds are not supported.
    _fields_ = [('rd_key', ctypes.c_uint * 60), ('rounds', ctypes.c_int)]


def _ige(data, key, iv, encrypt=False):
    if len(key) != 32 or len(iv) != 32 or not data or len(data) % 16:
        raise TelegramPathError('Invalid Telegram AES parameters')
    try:
        name = ctypes.util.find_library('crypto')
        if not name:
            raise OSError()
        lib = ctypes.CDLL(name)
        setter = lib.AES_set_encrypt_key if encrypt else lib.AES_set_decrypt_key
        setter.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(_AESKey)]
        setter.restype = ctypes.c_int
        lib.AES_ige_encrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(_AESKey), ctypes.c_void_p, ctypes.c_int]
        lib.AES_ige_encrypt.restype = None
    except (OSError, AttributeError):
        raise TelegramPathError('OpenSSL libcrypto with AES-IGE is unavailable') from None
    schedule = _AESKey()
    if setter(key, 256, ctypes.byref(schedule)) != 0:
        raise TelegramPathError('OpenSSL AES initialization failed')
    output = ctypes.create_string_buffer(len(data))
    ivbuf = ctypes.create_string_buffer(iv)
    lib.AES_ige_encrypt(data, output, len(data), ctypes.byref(schedule), ivbuf, int(encrypt))
    return output.raw


def _aes_material(auth, msg):
    sha = lambda value: hashlib.sha1(value).digest()
    a = sha(msg + auth[8:40])
    b = sha(auth[40:56] + msg + auth[56:72])
    c = sha(auth[72:104] + msg)
    d = sha(msg + auth[104:136])
    return a[:8] + b[8:20] + c[4:16], a[8:20] + b[:8] + c[16:20] + d[:8]


class _Reader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, length):
        if length < 0 or length > len(self.data) - self.offset:
            raise TelegramPathError('Truncated Telegram settings block')
        result = self.data[self.offset:self.offset + length]
        self.offset += length
        return result

    def uint(self):
        return struct.unpack('>I', self.take(4))[0]

    def array(self, nullable=False):
        length = self.uint()
        if nullable and length == 0xffffffff:
            return b''
        return self.take(length)


def _decode(raw):
    if not isinstance(raw, bytes) or not 64 <= len(raw) <= MAX_SETTINGS_SIZE:
        raise TelegramPathError('Invalid Telegram settings file size')
    if raw[:4] != b'TDF$':
        raise TelegramPathError('Unsupported Telegram settings envelope')
    if struct.unpack('<I', raw[4:8])[0] not in SUPPORTED_VERSIONS:
        raise TelegramPathError('Unsupported Telegram settings version')
    data = raw[8:-16]
    digest = hashlib.md5(data + struct.pack('<I', len(data)) + raw[4:8] + raw[:4]).digest()
    if not hmac.compare_digest(digest, raw[-16:]):
        raise TelegramPathError('Telegram settings checksum mismatch')
    reader = _Reader(data)
    salt, encrypted = reader.array(), reader.array()
    if reader.offset != len(data) or len(salt) != 32:
        raise TelegramPathError('Unsupported Telegram settings salt or envelope layout')
    if len(encrypted) < 32 or len(encrypted) % 16:
        raise TelegramPathError('Invalid Telegram encrypted settings length')
    auth = hashlib.pbkdf2_hmac('sha1', b'', salt, 4, 256)
    key, iv = _aes_material(auth, encrypted[:16])
    plain = _ige(encrypted[16:], key, iv)
    if not hmac.compare_digest(hashlib.sha1(plain).digest()[:16], encrypted[:16]):
        raise TelegramPathError('Telegram settings decryption integrity failure')
    length = struct.unpack('<I', plain[:4])[0]
    if not max(3, len(plain) - 16) < length <= len(plain):
        raise TelegramPathError('Invalid Telegram decrypted settings length')
    return raw[:8], salt, auth, plain[4:length]


def _dialog_field(content):
    """Walk complete top-level blocks; never interpret bytes inside opaque blobs."""
    fixed = {0x06: 4, 0x07: 4, 0x1d: 4, 0x0a: 4, 0x0c: 4,
             0x0d: 4, 0x58: 4, 0x57: 4, 0x54: 20, 0x61: 16,
             0x55: 8, 0x4e: 8, 0x5a: 8}
    reader, seen, field = _Reader(content), set(), None
    while reader.offset < len(content):
        tag = reader.uint()
        if tag in seen:
            raise TelegramPathError('Ambiguous duplicate Telegram settings block')
        seen.add(tag)
        if tag in fixed:
            reader.take(fixed[tag])
        elif tag in (0x60, 0x5e):
            reader.array(nullable=True)
        elif tag == 0x23:
            start = reader.offset
            encoded = reader.array(nullable=True)
            try:
                value = encoded.decode('utf-16-be')
            except UnicodeError:
                raise TelegramPathError('Invalid Telegram dialog path encoding') from None
            if '\0' in value:
                raise TelegramPathError('Invalid Telegram dialog path')
            field = (start, reader.offset, value)
        else:
            raise TelegramPathError('Unsupported Telegram settings block schema')
    return field


def _home(value):
    if (not isinstance(value, str) or not value.startswith('/') or value == '/'
            or '\0' in value or posixpath.normpath(value) != value or value.startswith('//')):
        raise TelegramPathError('Home path must be a normalized absolute directory')
    return value


def _encode(header, salt, auth, content):
    plain = struct.pack('<I', len(content) + 4) + content
    plain += os.urandom((-len(plain)) % 16)
    msg = hashlib.sha1(plain).digest()[:16]
    key, iv = _aes_material(auth, msg)
    encrypted = msg + _ige(plain, key, iv, encrypt=True)
    data = struct.pack('>I', len(salt)) + salt + struct.pack('>I', len(encrypted)) + encrypted
    return header + data + hashlib.md5(data + struct.pack('<I', len(data)) + header[4:8] + header[:4]).digest()


def repair_settings_bytes(raw, source_home, dest_home):
    """Return repaired encrypted bytes, or original bytes when no change is needed.

    Only dbiDialogLastPath is rewritten, at a home-directory boundary. All other
    decrypted fields, including opaque application settings, remain byte-exact.
    Unsupported/corrupt inputs raise TelegramPathError and must be left intact.
    """
    source_home, dest_home = _home(source_home), _home(dest_home)
    header, salt, auth, content = _decode(raw)
    field = _dialog_field(content)
    if field is None or source_home == dest_home:
        return raw
    start, end, path = field
    if path != source_home and not path.startswith(source_home + '/'):
        return raw
    if posixpath.normpath(path) != path:
        raise TelegramPathError('Non-normalized Telegram dialog path; manual review required')
    replacement = (dest_home + path[len(source_home):]).encode('utf-16-be')
    changed = content[:start] + struct.pack('>I', len(replacement)) + replacement + content[end:]
    result = _encode(header, salt, auth, changed)
    verified_header, verified_salt, _, verified_content = _decode(result)
    if (verified_header != header or verified_salt != salt or verified_content != changed):
        raise TelegramPathError('Telegram settings repair verification failed')
    _dialog_field(verified_content)
    return result
