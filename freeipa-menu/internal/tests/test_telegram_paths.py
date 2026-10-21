import base64
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('telegram_paths', Path(__file__).parents[1] / 'telegram_paths.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


def block(tag, data):
    return struct.pack('>I', tag) + data


def array(data):
    return struct.pack('>I', len(data)) + data


def path_block(path):
    return block(0x23, array(path.encode('utf-16-be')))


HEADER = b'TDF$' + struct.pack('<I', 7002005)
SALT = bytes(range(32))
AUTH = hashlib.pbkdf2_hmac('sha1', b'', SALT, 4, 256)
# Opaque settings deliberately contain a misleading serialized path field.
OPAQUE = b'opaque-prefix' + path_block('/home/user') + b'opaque-suffix'
PREFIX = b''.join(block(tag, struct.pack('>I', value)) for tag, value in
                 [(6, 1), (7, 0), (0x1d, 0), (0x0a, 1), (0x0c, 1), (0x0d, 123), (0x58, 100)])
PREFIX += block(0x60, array(b'fallback-config')) + block(0x5e, array(OPAQUE))
SUFFIX = block(0x57, struct.pack('>I', 0)) + block(0x54, bytes(20)) + block(0x4e, bytes(8))


def fixture(path='/home/user', content=None):
    return t._encode(HEADER, SALT, AUTH, PREFIX + path_block(path) + SUFFIX if content is None else content)


def envelope(header, data):
    return header + data + hashlib.md5(data + struct.pack('<I', len(data)) + header[4:8] + header[:4]).digest()


class TelegramPaths(unittest.TestCase):
    def test_independent_ecb_ige_fixture(self):
        # Generated independently using cryptography AES-ECB + explicit IGE chaining;
        # fixed public synthetic data, no Telegram account data or runtime dependency.
        raw = base64.b64decode('VERGJJXXagAAAAAgAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8AAADwypsH1ck4ltxbcWpaGNdAp6Y30aWAjqTzBDuzoUiiGVd1IxglsaRdzMHNDf/A9kLRr+9GzZvmBR+3MEJrCf47wyCtHtqaxDnIODAywixjzZZ9E/plvMocvmVPhomSpPku9xSwQz00VAhoyMYROdUzNWy81qqS+px8FPrxhOg0bAfLUww1bw/C2/IsCf4eXL4JqOEZ9MtuyUPQhPhZAmRfcJVL3rPrYDFsHtNH0zpL5ZX3Mz3gcIugRcgYkPSDNMOEkhoz+VYp8PpoYVOfMNdjMwGmwgr2Xghqepo9FVVp82gC2HA1fKhM5J8drfaGqVmB2/pMraQhqXT3o03yQzYIOQ==')
        self.assertEqual(t._decode(raw)[3], PREFIX + path_block('/home/user') + SUFFIX)
        repaired = t.repair_settings_bytes(raw, '/home/user', '/home/new')
        self.assertEqual(t._decode(repaired)[3], PREFIX + path_block('/home/new') + SUFFIX)

    def test_realistic_roundtrip_preserves_opaque_payload_and_all_other_fields(self):
        raw = fixture('/home/user/Downloads')
        repaired = t.repair_settings_bytes(raw, '/home/user', '/home/office-workspace')
        header, salt, auth, plain = t._decode(repaired)
        self.assertEqual((header, salt, auth), (HEADER, SALT, AUTH))
        self.assertEqual(plain, PREFIX + path_block('/home/office-workspace/Downloads') + SUFFIX)
        self.assertIn(OPAQUE, plain)
        self.assertEqual(t.repair_settings_bytes(repaired, '/home/user', '/home/office-workspace'), repaired)

    def test_exact_home_is_relocated(self):
        out = t.repair_settings_bytes(fixture(), '/home/user', '/home/office-workspace')
        self.assertEqual(t._dialog_field(t._decode(out)[3])[2], '/home/office-workspace')

    def test_noop_is_byte_exact_for_absent_field_and_other_paths(self):
        for raw in [fixture(content=PREFIX + SUFFIX), fixture('/home/user2'), fixture('/other/home'), fixture('')]:
            self.assertEqual(t.repair_settings_bytes(raw, '/home/user', '/home/new'), raw)

    def test_duplicate_fields_fail_closed(self):
        with self.assertRaisesRegex(t.TelegramPathError, 'duplicate'):
            t.repair_settings_bytes(fixture(content=PREFIX + path_block('/home/user') * 2 + SUFFIX), '/home/user', '/home/new')

    def test_unknown_schema_and_truncated_blocks_fail_closed(self):
        for content in [PREFIX + block(0x999, bytes(4)), PREFIX + block(0x23, struct.pack('>I', 1000)), PREFIX + b'\x00', PREFIX + path_block('/home/user') + block(0x4b, array(b'auth'))]:
            with self.assertRaises(t.TelegramPathError):
                t.repair_settings_bytes(fixture(content=content), '/home/user', '/home/new')

    def test_checksum_and_ciphertext_corruption_fail_closed(self):
        raw = fixture()
        bad_checksum = raw[:-1] + bytes([raw[-1] ^ 1])
        data = bytearray(raw[8:-16]); data[-1] ^= 1
        for broken in [bad_checksum, envelope(HEADER, bytes(data)), b'other' + raw[5:], raw[:20]]:
            with self.assertRaises(t.TelegramPathError):
                t.repair_settings_bytes(broken, '/home/user', '/home/new')

    def test_unknown_version_and_salt_layout_fail_closed(self):
        raw = fixture()
        unknown = envelope(b'TDF$' + struct.pack('<I', 9000000), raw[8:-16])
        short_salt = envelope(HEADER, array(SALT[:-1]) + raw[8 + 4 + 32:-16])
        trailing = envelope(HEADER, raw[8:-16] + b'extra')
        for broken in [unknown, short_salt, trailing]:
            with self.assertRaises(t.TelegramPathError):
                t.repair_settings_bytes(broken, '/home/user', '/home/new')

    def test_unsafe_home_and_path_traversal_are_rejected(self):
        for home in ['/', 'relative', '/home/user/', '/home/../user', '//home/user']:
            with self.assertRaises(t.TelegramPathError):
                t.repair_settings_bytes(fixture(), home, '/home/new')
        for path in ['/home/user/../user2', '/home/user//Downloads', '/home/user/./Downloads']:
            with self.assertRaises(t.TelegramPathError):
                t.repair_settings_bytes(fixture(path), '/home/user', '/home/new')

    def test_missing_crypto_is_safe_and_explicit(self):
        raw = fixture()
        with mock.patch.object(t.ctypes.util, 'find_library', return_value=None):
            with self.assertRaisesRegex(t.TelegramPathError, 'unavailable'):
                t.repair_settings_bytes(raw, '/home/user', '/home/new')

    def test_bad_utf16_fails_closed(self):
        raw = fixture(content=PREFIX + block(0x23, array(b'\xd8\x00')) + SUFFIX)
        with self.assertRaisesRegex(t.TelegramPathError, 'encoding'):
            t.repair_settings_bytes(raw, '/home/user', '/home/new')


if __name__ == '__main__':
    unittest.main()
