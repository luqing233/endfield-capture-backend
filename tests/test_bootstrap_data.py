"""版本绑定与原生入口未适配时的失败保护，不读取真实客户端或密钥。"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from endfield_capture import decoder


class BootstrapDataTest(unittest.TestCase):
    def test_both_client_hashes_must_match(self):
        bootstrap = object.__new__(decoder.Bootstrap)
        payload = {
            "client_dll_sha256": decoder.CLIENT_DLL_SHA256,
            "client_metadata_sha256": decoder.CLIENT_METADATA_SHA256,
            "modulus_hex": f"{(1 << 2047) + 1:x}",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "modulus.json"
            with patch.object(decoder, "MODULUS_DATA_PATH", path):
                path.write_text(json.dumps(payload), encoding="utf-8")
                self.assertEqual(bootstrap._load_stored_modulus(), (1 << 2047) + 1)
                for field in ("client_dll_sha256", "client_metadata_sha256"):
                    path.write_text(json.dumps({**payload, field: "other-version"}), encoding="utf-8")
                    self.assertIsNone(bootstrap._load_stored_modulus())

    def test_missing_data_does_not_execute_old_native_entry(self):
        bootstrap = object.__new__(decoder.Bootstrap)
        bootstrap._modulus = None
        with (
            patch.object(decoder, "_EMULATION_VERIFIED", False),
            self.assertRaisesRegex(ValueError, "旧版原生模拟入口尚未适配"),
        ):
            bootstrap.unwrap(bytes(272))


if __name__ == "__main__":
    unittest.main()
