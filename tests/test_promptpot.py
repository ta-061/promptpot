from __future__ import annotations

import http.client
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import promptpot


class HelperTests(unittest.TestCase):
    def test_parse_port_spec(self) -> None:
        self.assertEqual(
            promptpot.parse_port_spec("11434:ollama, 8000:vllm,9000"),
            [(11434, "ollama"), (8000, "vllm"), (9000, "openai")],
        )

    def test_parse_port_spec_rejects_invalid_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported profile"):
            promptpot.parse_port_spec("8080:unknown")
        with self.assertRaisesRegex(ValueError, "no listeners"):
            promptpot.parse_port_spec(" , ")

    def test_merge_profile_config_changes_known_profiles_only(self) -> None:
        merged = promptpot.merge_profile_config(
            {
                "profiles": {
                    "ollama": {"version": "test-version"},
                    "unknown": {"server": "ignored"},
                }
            }
        )
        self.assertEqual(merged["ollama"]["version"], "test-version")
        self.assertNotIn("unknown", merged)

    def test_extract_prompt_handles_chat_messages(self) -> None:
        model, extracted_prompt, messages = promptpot.extract_prompt(
            {
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
            }
        )
        self.assertEqual(model, "test-model")
        self.assertEqual(extracted_prompt, "")
        self.assertEqual(messages, '[{"role":"user","content":"hello"}]')

    def test_append_log_writes_one_json_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "events.jsonl"
            with patch.object(promptpot, "LOG_PATH", path), redirect_stdout(io.StringIO()):
                promptpot.append_log({"sensor": "promptpot", "value": "test"})

            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["value"], "test")


class HTTPIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "promptpot.jsonl"
        self.log_patch = patch.object(promptpot, "LOG_PATH", self.log_path)
        self.host_patch = patch.object(promptpot, "HOST_IP", "192.0.2.10")
        self.log_patch.start()
        self.host_patch.start()

        self.server = promptpot.ProfiledHTTPServer(
            ("127.0.0.1", 0), promptpot.PromptPotHandler, "ollama"
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.host_patch.stop()
        self.log_patch.stop()
        self.temp_dir.cleanup()

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_address[1], timeout=2
        )
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def events(self) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]

    def test_ollama_model_list_response_and_log(self) -> None:
        with redirect_stdout(io.StringIO()):
            status, headers, body = self.request("GET", "/api/tags")

        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertGreater(len(json.loads(body)["models"]), 0)

        event = self.events()[0]
        self.assertEqual(event["type"], "OllamaPot")
        self.assertEqual(event["dest_port"], self.server.server_address[1])
        self.assertEqual(event["dest_ip"], "192.0.2.10")
        self.assertEqual(event["http"]["status"], 200)

    def test_chat_completion_extracts_messages(self) -> None:
        request_body = json.dumps(
            {
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
            }
        ).encode()
        with redirect_stdout(io.StringIO()):
            status, _, body = self.request(
                "POST",
                "/v1/chat/completions",
                request_body,
                {"Content-Type": "application/json"},
            )

        response = json.loads(body)
        event = self.events()[0]
        self.assertEqual(status, 200)
        self.assertEqual(response["model"], "test-model")
        self.assertTrue(event["promptpot"]["json_valid"])
        self.assertEqual(event["promptpot"]["model"], "test-model")
        self.assertIn("hello", event["promptpot"]["messages"])

    def test_malformed_json_is_recorded_without_crashing(self) -> None:
        with redirect_stdout(io.StringIO()):
            status, _, _ = self.request(
                "POST",
                "/api/generate",
                b'{"prompt":',
                {"Content-Type": "application/json"},
            )

        event = self.events()[0]
        self.assertEqual(status, 200)
        self.assertFalse(event["promptpot"]["json_valid"])
        self.assertEqual(event["promptpot"]["body"], '{"prompt":')

    def test_request_body_is_capped_and_marked_truncated(self) -> None:
        body = b"x" * 64
        with patch.object(promptpot, "MAX_BODY_BYTES", 16), redirect_stdout(io.StringIO()):
            status, _, _ = self.request("POST", "/api/generate", body)

        event = self.events()[0]
        self.assertEqual(status, 200)
        self.assertTrue(event["promptpot"]["body_truncated"])
        self.assertEqual(len(event["promptpot"]["body"]), 16)
        self.assertEqual(event["http"]["length"], 64)

    def test_unknown_post_returns_and_logs_not_found(self) -> None:
        with redirect_stdout(io.StringIO()):
            status, _, body = self.request("POST", "/unknown", b"{}")

        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not found"})
        self.assertEqual(self.events()[0]["http"]["status"], 404)

    def test_profile_discovery_routes(self) -> None:
        cases = [
            ("lmstudio", "/", "application/json"),
            ("vllm", "/docs", "text/html; charset=utf-8"),
            ("gradio", "/config", "application/json"),
            ("comfyui", "/system_stats", "application/json"),
        ]
        for profile, path, content_type in cases:
            with self.subTest(profile=profile), redirect_stdout(io.StringIO()):
                self.server.profile = profile
                status, headers, _ = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertEqual(headers["Content-Type"], content_type)


if __name__ == "__main__":
    unittest.main()
