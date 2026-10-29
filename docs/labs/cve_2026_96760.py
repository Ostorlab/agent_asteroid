"""Run local Authlib 1.8.0/1.9.0 controls; no HTTP server or target input.

Install the selected Authlib version in a disposable environment, then execute
this file directly. It is intentionally separate from normal pytest collection
so Asteroid does not acquire a runtime dependency on Authlib.
"""

from __future__ import annotations

import base64
import copy
import json
import unittest
from importlib import metadata

from authlib import jose
from authlib.jose import errors


class AuthlibLocalControls(unittest.TestCase):
    """Exercise real release artifacts with a harmless marker and local test key."""

    def testJws_whenEmptySignatures_matchesReleaseBehavior(self) -> None:
        release = metadata.version("authlib")
        self.assertIn(release, ("1.8.0", "1.9.0"))
        payload = b"asteroid-local-control"
        forged = {
            "payload": base64.urlsafe_b64encode(payload).rstrip(b"=").decode(),
            "signatures": [],
        }
        jws = jose.JsonWebSignature(algorithms=["HS256"])
        for key in (None, "local-test-key"):
            for entrypoint, token in (
                (jws.deserialize_json, forged),
                (jws.deserialize, forged),
                (jws.deserialize, json.dumps(forged)),
            ):
                with self.subTest(release=release, key=key, entrypoint=entrypoint):
                    if release == "1.8.0":
                        self.assertEqual(entrypoint(token, key)["payload"], payload)
                    else:
                        with self.assertRaises(errors.BadSignatureError):
                            entrypoint(token, key)

    def testJws_whenSignedOrTampered_checksSignatures(self) -> None:
        jws = jose.JsonWebSignature(algorithms=["HS256"])
        payload = b"asteroid-local-control"
        key = "local-test-key"
        headers = [{"protected": {"alg": "HS256"}}] * 2
        signed = jws.serialize_json(headers, payload, key)
        self.assertEqual(jws.deserialize_json(signed, key)["payload"], payload)
        with self.assertRaises(errors.BadSignatureError):
            jws.deserialize_json(signed, "wrong-local-key")
        tampered = copy.deepcopy(signed)
        tampered["signatures"][0]["signature"] = "AA"
        with self.assertRaises(errors.BadSignatureError):
            jws.deserialize_json(tampered, key)
        flattened = jws.serialize_json(headers[0], payload, key)
        self.assertEqual(jws.deserialize_json(flattened, key)["payload"], payload)
        flattened["signature"] = ""
        with self.assertRaises(errors.DecodeError):
            jws.deserialize_json(flattened, key)
        compact = jws.serialize_compact({"alg": "HS256"}, payload, key)
        self.assertEqual(jws.deserialize_compact(compact, key)["payload"], payload)
        with self.assertRaises(errors.BadSignatureError):
            jws.deserialize_compact(compact.rsplit(b".", 1)[0] + b".", key)
        with self.assertRaises(errors.DecodeError):
            jws.deserialize_json({"payload": signed["payload"]}, key)
        with self.assertRaises(TypeError):
            jws.deserialize_json(
                {"payload": signed["payload"], "signatures": None}, key
            )


if __name__ == "__main__":
    unittest.main()
