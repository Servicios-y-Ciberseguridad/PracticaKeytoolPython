import contextlib
import io
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import mykeytool


class GenKeyPairTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "test.myks"
        self.password = "test-password-123"

    def generate(self, alias="miClave", password=None, dn=None):
        password = self.password if password is None else password
        passwords = [password, password] if not self.path.exists() else [password]
        fields = dn if dn is not None else ["Ana", "TI", "Empresa", "Madrid", "Madrid", "es"]
        output = io.StringIO()
        errors = io.StringIO()
        with (
            patch("mykeytool.getpass.getpass", side_effect=passwords) as getpass_mock,
            patch("builtins.input", side_effect=[alias, *fields, "yes"]),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main(["--genkeypair", "--keystore", str(self.path)])
        self.assertNotIn(password, output.getvalue() + errors.getvalue())
        self.assertTrue(getpass_mock.called)
        return result, output.getvalue(), errors.getvalue()

    def test_generates_encrypted_rsa_2048_entry_and_dn(self):
        result, output, errors = self.generate()
        self.assertEqual(result, 0, errors)
        self.assertIn("Exito", output)
        entry = mykeytool.load_keystore(self.path, self.password)["miClave"]
        private = serialization.load_pem_private_key(
            entry["private_key"].encode("ascii"), password=None
        )
        public = serialization.load_pem_public_key(entry["public_key"].encode("ascii"))
        self.assertIsInstance(private, rsa.RSAPrivateKey)
        self.assertIsInstance(public, rsa.RSAPublicKey)
        self.assertEqual(private.key_size, 2048)
        self.assertEqual(public.key_size, 2048)
        self.assertEqual(private.public_key().public_numbers(), public.public_numbers())
        self.assertEqual(public.public_numbers().e, 65537)
        self.assertEqual(entry["dn"], dict(zip(mykeytool.DN_FIELDS, [
            "Ana", "TI", "Empresa", "Madrid", "Madrid", "ES"
        ])))
        encrypted = self.path.read_bytes()
        for secret in (b"miClave", b"PRIVATE KEY", b"Empresa", self.password.encode()):
            self.assertNotIn(secret, encrypted)
        with self.assertRaisesRegex(ValueError, "incorrecta"):
            mykeytool.load_keystore(self.path, "wrong-password")

    def test_supports_keytool_style_arguments(self):
        output = io.StringIO()
        errors = io.StringIO()
        argv = [
            "-genkeypair",
            "-keystore",
            str(self.path),
            "-alias",
            "mykey",
            "-storepass",
            self.password,
            "-keyalg",
            "RSA",
            "-keysize",
            "3072",
            "-dname",
            "CN=Ana, OU=TI, O=Empresa, L=Madrid, ST=Madrid, C=es",
        ]
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main(argv)
        self.assertEqual(result, 0, errors.getvalue())
        self.assertIn("3072 bits", output.getvalue())
        entry = mykeytool.load_keystore(self.path, self.password)["mykey"]
        private = serialization.load_pem_private_key(
            entry["private_key"].encode("ascii"), password=None
        )
        self.assertEqual(private.key_size, 3072)
        self.assertEqual(entry["dn"]["C"], "ES")

    def test_reprompts_until_distinguished_name_is_confirmed(self):
        output = io.StringIO()
        errors = io.StringIO()
        answers = [
            "miClave",
            "Ana",
            "TI",
            "Empresa",
            "Madrid",
            "Madrid",
            "es",
            "no",
            "Ana Dos",
            "TI",
            "Empresa",
            "Madrid",
            "Madrid",
            "es",
            "yes",
        ]
        with (
            patch("mykeytool.getpass.getpass", side_effect=[self.password, self.password]),
            patch("builtins.input", side_effect=answers),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main(["-genkeypair", "-keystore", str(self.path)])
        self.assertEqual(result, 0, errors.getvalue())
        entry = mykeytool.load_keystore(self.path, self.password)["miClave"]
        self.assertEqual(entry["dn"]["CN"], "Ana Dos")

    def test_rejects_unsupported_key_algorithm(self):
        output = io.StringIO()
        errors = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = mykeytool.main([
                "-genkeypair",
                "-keystore",
                str(self.path),
                "-alias",
                "mykey",
                "-storepass",
                self.password,
                "-keyalg",
                "EC",
                "-dname",
                "CN=Ana, OU=TI, O=Empresa, L=Madrid, ST=Madrid, C=ES",
            ])
        self.assertEqual(result, 1)
        self.assertIn("Solo se admite -keyalg RSA", errors.getvalue())
        self.assertFalse(self.path.exists())

    def test_preserves_existing_entries(self):
        self.assertEqual(self.generate()[0], 0)
        original = mykeytool.load_keystore(self.path, self.password)["miClave"]
        self.assertEqual(self.generate(alias="segunda")[0], 0)
        entries = mykeytool.load_keystore(self.path, self.password)
        self.assertEqual(set(entries), {"miClave", "segunda"})
        self.assertEqual(entries["miClave"], original)

    def test_duplicate_alias_and_wrong_password_preserve_file(self):
        self.assertEqual(self.generate()[0], 0)
        before = self.path.read_bytes()
        for kwargs, message in [({}, "ya existe"), ({"password": "wrong-password"}, "incorrecta")]:
            result, output, errors = self.generate(**kwargs)
            self.assertEqual(result, 1)
            self.assertNotIn("Exito", output)
            self.assertIn(message, errors)
            self.assertEqual(self.path.read_bytes(), before)

    def test_tampered_or_invalid_store_is_not_overwritten(self):
        self.assertEqual(self.generate()[0], 0)
        data = self.path.read_bytes()
        tampered = data[:-1] + bytes([data[-1] ^ 1])
        for invalid in (tampered, b"", b"not-a-keystore"):
            self.path.write_bytes(invalid)
            self.assertEqual(self.generate()[0], 1)
            self.assertEqual(self.path.read_bytes(), invalid)

    def test_empty_fields_and_invalid_country_fail(self):
        for alias, fields in [
            (" ", None),
            ("valid", ["", "TI", "Empresa", "Madrid", "Madrid", "ES"]),
            ("valid", ["Ana", "TI", "Empresa", "Madrid", "Madrid", "ESP"]),
        ]:
            with self.subTest(alias=alias, fields=fields):
                self.assertEqual(self.generate(alias=alias, dn=fields)[0], 1)
                self.assertFalse(self.path.exists())

    def test_short_or_mismatched_password_fails(self):
        self.assertEqual(self.generate(password="short")[0], 1)
        with (
            patch("mykeytool.getpass.getpass", side_effect=[self.password, "different"]),
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(mykeytool.handle_genkeypair(self.path), 1)
        self.assertIn("no coinciden", errors.getvalue())
        self.assertFalse(self.path.exists())

    def test_insecure_password_fallback_is_rejected(self):
        def insecure_getpass(prompt):
            warnings.warn("No secure terminal", getpass_warning)
            self.fail("getpass continued with an insecure fallback")

        getpass_warning = mykeytool.getpass.GetPassWarning
        with (
            patch("mykeytool.getpass.getpass", side_effect=insecure_getpass),
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(mykeytool.handle_genkeypair(self.path), 1)
        self.assertIn("ocultar", errors.getvalue())
        self.assertFalse(self.path.exists())

    def test_cancelled_input_fails_without_writing(self):
        with (
            patch("mykeytool.getpass.getpass", side_effect=KeyboardInterrupt),
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(mykeytool.handle_genkeypair(self.path), 1)
        self.assertIn("cancelada", errors.getvalue())
        self.assertFalse(self.path.exists())

    def test_failed_replace_preserves_store_and_cleans_temporary(self):
        self.assertEqual(self.generate()[0], 0)
        before = self.path.read_bytes()
        with patch("mykeytool.os.replace", side_effect=PermissionError("Acceso denegado")):
            result, output, errors = self.generate(alias="segunda")
        self.assertEqual(result, 1)
        self.assertIn("Acceso denegado", errors)
        self.assertNotIn("Exito", output)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_certreq_behavior_is_preserved(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(mykeytool.main(["--certreq"]), 0)
        self.assertIn("--certreq seleccionado", output.getvalue())

    def test_prompts_for_command_when_no_arguments_are_given(self):
        with (
            patch("builtins.input", side_effect=["", "--certreq"]) as prompt,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(mykeytool.main([]), 0)
        self.assertEqual(prompt.call_count, 2)
        self.assertIn("--certreq seleccionado", output.getvalue())


if __name__ == "__main__":
    unittest.main()
