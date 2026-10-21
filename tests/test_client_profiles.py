"""Client and modulus identities must stay paired across channels."""

import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from endfield_capture.client_profiles import (
    CN_PROFILE,
    INTERNATIONAL_PROFILE,
    modulus_data_path,
    profile_for_digest,
)
from endfield_capture.decoder import Bootstrap


class ClientProfileTest(unittest.TestCase):
    def test_only_verified_builds_are_selected(self):
        for profile in (CN_PROFILE, INTERNATIONAL_PROFILE):
            self.assertIs(profile_for_digest(profile.dll_sha256), profile)
        with self.assertRaisesRegex(ValueError, "GameAssembly.dll sha256="):
            profile_for_digest("0" * 64)

    def test_each_channel_has_a_separate_modulus_file(self):
        self.assertNotEqual(modulus_data_path(CN_PROFILE), modulus_data_path(INTERNATIONAL_PROFILE))

    def test_shipped_moduli_match_their_exact_profiles(self):
        for profile in (CN_PROFILE, INTERNATIONAL_PROFILE):
            with self.subTest(channel=profile.channel):
                bootstrap = object.__new__(Bootstrap)
                bootstrap.profile = profile
                bootstrap.modulus_data_path = modulus_data_path(profile)
                modulus = bootstrap._load_stored_modulus()
                self.assertIsNotNone(modulus)
                self.assertEqual(modulus.bit_length(), 2048)

    def test_mismatched_or_missing_profile_material_is_not_used(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "modulus.json"
            bootstrap = object.__new__(Bootstrap)
            bootstrap.profile = INTERNATIONAL_PROFILE
            bootstrap.modulus_data_path = path
            self.assertIsNone(bootstrap._load_stored_modulus())
            for dll, metadata, accepted in (
                (CN_PROFILE.dll_sha256, INTERNATIONAL_PROFILE.metadata_sha256, False),
                (INTERNATIONAL_PROFILE.dll_sha256, "0" * 64, False),
                (INTERNATIONAL_PROFILE.dll_sha256, INTERNATIONAL_PROFILE.metadata_sha256, True),
            ):
                with self.subTest(dll=dll, metadata=metadata):
                    modulus = (1 << 2047) + 1
                    path.write_text(
                        json.dumps(
                            {
                                "client_dll_sha256": dll,
                                "client_metadata_sha256": metadata,
                                "modulus_hex": f"{modulus:x}",
                            }
                        ),
                        encoding="utf-8",
                    )
                    self.assertEqual(bootstrap._load_stored_modulus(), modulus if accepted else None)

    def test_wrong_metadata_is_rejected_before_key_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "Endfield_Data/il2cpp_data/Metadata/global-metadata.dat"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"unexpected metadata")
            bootstrap = object.__new__(Bootstrap)
            bootstrap.game_directory = root
            bootstrap.profile = INTERNATIONAL_PROFILE
            with self.assertRaisesRegex(ValueError, "global-metadata.dat sha256="):
                bootstrap._load_client_private_key(None)


class SrsaEntryTest(unittest.TestCase):
    def test_emulator_uses_the_verified_receive_entry_and_pointer_abi(self):
        from unicorn.x86_const import UC_X86_REG_RCX

        from endfield_capture import srsa

        class Image:
            image_base = 0x180000000

        # A native stub checks the decoded input pointer, then returns an encoded
        # result. This exercises Unicorn startup, memory mapping and the real ABI.
        def bind_stub(emulator):
            emulator.uc.mem_map(Image.image_base + 0x109000, 0x1000)
            body = b"\x48\xb8" + struct.pack("<Q", srsa._ARG_POINTER_XOR) + b"\x48\x31\xc1\x48\x8b\x01\xc3"
            emulator.uc.mem_write(Image.image_base + 0x109EE0, body)

        result_pointer = srsa._HEAP_BASE + 0x2000
        encoded_result = result_pointer ^ srsa._RESULT_POINTER_XOR
        with patch.object(srsa._Emulator, "_bind_imports", bind_stub):
            emulator = srsa._Emulator(Image(), struct.pack("<Q", encoded_result) + b"\0" * 264)
            emulator.uc.mem_write(result_pointer, struct.pack("<I", 3) + b"abc")
            output, state = emulator.run()
        self.assertEqual(output, b"abc")
        self.assertEqual(state["stop"]["reason"], "returned")
        self.assertEqual(emulator.uc.reg_read(UC_X86_REG_RCX), srsa._HEAP_BASE)

    def test_native_recovery_matches_real_handshake_without_cached_modulus(self):
        """Optional local regression: no packet captures or game files in Git."""
        pcap = os.environ.get("EF_NATIVE_REFERENCE_PCAP")
        game = os.environ.get("EF_GAME_DIR")
        if not pcap or not game:
            self.skipTest("Set EF_NATIVE_REFERENCE_PCAP and EF_GAME_DIR for native handshake regression")
        from endfield_capture import srsa
        from endfield_capture.decoder import Engine, State
        from endfield_capture.pe_image import PeImage
        from endfield_capture.selftest import _read_packets

        class NativeBootstrap(Bootstrap):
            envelope = None

            def _load_stored_modulus(self):
                return None

            def unwrap(self, envelope):
                self.envelope = envelope
                return super().unwrap(envelope)

        bootstrap = NativeBootstrap(Path(game))
        engine = Engine(State(), bootstrap)
        for packet in _read_packets(Path(pcap)):
            engine.receive(packet)
        self.assertIsNotNone(bootstrap.envelope)
        self.assertEqual(bootstrap.modulus_source, "emulated")
        self.assertTrue(any(flow.ciphers for flow in engine.flows.values()))
        self.assertFalse(any(flow.failed for flow in engine.flows.values()))
        result = srsa.emulate_receive_entry(PeImage(Path(game) / "GameAssembly.dll"), bootstrap.envelope)
        self.assertTrue(result.ok, result.state.get("stop"))
        self.assertEqual(result.modulus, bootstrap.modulus)
        self.assertEqual(result.modulus.bit_length(), 2048)
        self.assertEqual(result.transformed, bootstrap.unwrap(bootstrap.envelope))
        checks = result.state["modularExponentiationChecks"]
        self.assertTrue(checks)
        for check in checks:
            self.assertTrue(check["matchesPythonPow"])
            self.assertTrue(check["standardPublicExponent65537"])
            self.assertTrue(check["operandMatchesCiphertextBigEndian"])
        self.assertEqual(result.state["rawRsaFormulaMatchesOutput"], [True])


if __name__ == "__main__":
    unittest.main()
