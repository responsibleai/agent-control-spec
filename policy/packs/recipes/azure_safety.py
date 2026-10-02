"""Reference ACS dispatcher for Azure Content Safety's 2024-09-01 REST API."""

import http.client
import json
from typing import ClassVar
from urllib.parse import urlsplit


class AzureSafety:
    """Use a host-configured endpoint and credential, never fields from agent input."""

    categories: ClassVar[dict[str, str]] = {
        "Hate": "hate",
        "SelfHarm": "self_harm",
        "Sexual": "sexual",
        "Violence": "violence",
    }

    def __init__(
        self,
        endpoint,
        api_key,
        *,
        timeout=5,
        max_chars=10000,
        allow_loopback_for_tests=False,
    ):
        url = urlsplit(endpoint)
        local_test = (
            allow_loopback_for_tests
            and url.scheme == "http"
            and url.hostname in {"127.0.0.1", "::1"}
        )
        if not url.hostname or (url.scheme != "https" and not local_test):
            raise ValueError("Content Safety requires HTTPS")
        if (
            url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
            or url.path not in {"", "/"}
        ):
            raise ValueError(
                "Use a Content Safety service origin without credentials, path or query"
            )
        if (
            not isinstance(api_key, str)
            or not api_key
            or any(c in api_key for c in "\r\n")
        ):
            raise ValueError("A valid host-provided Content Safety API key is required")
        if timeout <= 0 or type(max_chars) is not int or max_chars < 1:
            raise ValueError("Timeout and text limit must be positive")
        self.url = url
        self.api_key = api_key
        self.timeout = timeout
        self.max_chars = max_chars

    def _text(self, value):
        def check_media(node):
            if isinstance(node, dict):
                kind = node.get("type")
                if isinstance(kind, str) and kind in {
                    "image",
                    "image_url",
                    "input_image",
                    "image_file",
                    "input_audio",
                    "audio",
                    "file",
                }:
                    raise ValueError("This dispatcher only analyzes text")
                for child in node.values():
                    check_media(child)
            elif isinstance(node, list):
                for child in node:
                    check_media(child)

        check_media(value)
        text = (
            value
            if isinstance(value, str)
            else json.dumps(value, ensure_ascii=False, allow_nan=False)
        )
        if len(text) > self.max_chars:
            raise ValueError(
                "Target exceeds the configured text limit; it was not truncated"
            )
        return text

    def _post(self, operation, body):
        connection_type = (
            http.client.HTTPSConnection
            if self.url.scheme == "https"
            else http.client.HTTPConnection
        )
        connection = connection_type(
            self.url.hostname, self.url.port, timeout=self.timeout
        )
        try:
            connection.request(
                "POST",
                f"/contentsafety/text:{operation}?api-version=2024-09-01",
                body=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Ocp-Apim-Subscription-Key": self.api_key,
                },
            )
            response = connection.getresponse()
            # http.client does not follow redirects or copy credentials to another origin.
            if response.status != 200:
                raise RuntimeError(f"Content Safety returned HTTP {response.status}")
            payload = response.read(65537)
            if len(payload) > 65536:
                raise RuntimeError("Content Safety response exceeded 64 KiB")
            result = json.loads(payload)
            if not isinstance(result, dict):
                raise TypeError("Content Safety response must be an object")
            return result
        finally:
            connection.close()

    def dispatch(self, name, declaration, preliminary):
        text = self._text(preliminary["policy_target"]["value"])
        if name == "content_safety":
            result = self._post(
                "analyze",
                {
                    "text": text,
                    "categories": list(self.categories),
                    "outputType": "EightSeverityLevels",
                },
            )
            items = result.get("categoriesAnalysis")
            if not isinstance(items, list):
                raise ValueError("Content Safety response omitted category analysis")
            scores = {}
            for item in items:
                if not isinstance(item, dict):
                    raise TypeError("Malformed Content Safety category")
                category, severity = item.get("category"), item.get("severity")
                if (
                    category not in self.categories
                    or self.categories[category] in scores
                ):
                    raise ValueError("Unexpected or duplicate Content Safety category")
                if type(severity) is not int or not 0 <= severity <= 7:
                    raise ValueError("Invalid Content Safety severity")
                scores[self.categories[category]] = severity
            if set(scores) != set(self.categories.values()):
                raise ValueError("Content Safety did not analyze every category")
            return {"scores": scores}
        if name == "prompt_injection":
            point = preliminary["intervention_point"]
            if point == "input":
                prompt, documents = text, []
            elif point == "post_tool_call":
                prompt = preliminary["snapshot"]["extensions"]["policy_packs"][
                    "user_prompt"
                ]
                if not isinstance(prompt, str) or not prompt:
                    raise ValueError(
                        "Retrieved-document screening requires the original user prompt"
                    )
                prompt, documents = self._text(prompt), [text]
            else:
                raise ValueError("Unsupported Prompt Shields interception point")
            result = self._post(
                "shieldPrompt", {"userPrompt": prompt, "documents": documents}
            )
            prompt_result = result.get("userPromptAnalysis")
            document_results = result.get("documentsAnalysis")
            if (
                not isinstance(prompt_result, dict)
                or type(prompt_result.get("attackDetected")) is not bool
            ):
                raise ValueError("Missing or malformed user prompt analysis")
            # No document analysis is required when this request submitted no documents.
            if not documents and document_results is None:
                document_results = []
            if not isinstance(document_results, list) or len(document_results) != len(
                documents
            ):
                raise ValueError("Prompt Shields did not analyze every document")
            flags = [prompt_result["attackDetected"]]
            for document in document_results:
                if (
                    not isinstance(document, dict)
                    or type(document.get("attackDetected")) is not bool
                ):
                    raise ValueError("Missing or malformed document analysis")
                flags.append(document["attackDetected"])
            # Prompt Shields reports a boolean, not a calibrated probability.
            return {"score": 1.0 if any(flags) else 0.0}
        raise ValueError(f"Unsupported annotator {name}")
