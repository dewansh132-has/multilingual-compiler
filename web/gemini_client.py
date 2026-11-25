# -*- coding: utf-8 -*-
"""
web/gemini_client.py — Drop-In Google Gemini API Client for VITAL IDE

Drop-in replacement for ollama_client.py:
  - Communicates directly with Google Gemini REST API via standard library urllib.
  - Zero external dependencies (no google-genai or requests package required).
  - Preserves exact method signatures, return dictionary shapes, HealthResult
    subclass semantics, and routing logic for full compatibility with all
    downstream subsystems (ai_remediation_engine, security_analyzer, ir_optimizer,
    fix_orchestrator, server, and pipeline_tracker).
  - Strict security: API key is transmitted solely via the x-goog-api-key header,
    never embedded in URLs, and scrubbed from all logs and error messages.
  - Configured solely via environment variables:
      GEMINI_API_KEY (or GOOGLE_API_KEY)
      GEMINI_MODEL_FAST (default: gemini-2.5-flash)
      GEMINI_MODEL_ADVANCED (default: gemini-2.5-flash)
      VITAL_AI_TIMEOUT (default: 45.0 seconds)
      VITAL_AI_DISABLED
      VITAL_AI_MOCK
"""

import os
import sys
import re
import json
import time
import socket
import urllib.request
import urllib.error
import threading
from typing import Dict, Any, List, Optional, Tuple, Set

# At module import time: load .env into os.environ if not already present
try:
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _env_file = os.path.join(_repo_root, ".env")
    if os.path.isfile(_env_file):
        with open(_env_file, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    _k = _k.strip()
                    _v = _v.strip().strip("'\"")
                    if _k and _k not in os.environ:
                        os.environ[_k] = _v
except Exception:
    pass

# Configuration constants and environment variable bindings
DEFAULT_GEMINI_BASE_URL = os.environ.get("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta").rstrip("/")
DEFAULT_GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest")
DEFAULT_GEMINI_MODEL_FALLBACKS_ADVANCED = "gemini-flash-lite-latest,gemini-3.1-flash-lite,gemini-3-flash-preview,gemini-flash-latest"
DEFAULT_GEMINI_MODEL_FALLBACKS_FAST = "gemini-flash-lite-latest,gemini-3.1-flash-lite,gemini-flash-latest,gemini-3-flash-preview"
DEFAULT_GEMINI_MODEL_FALLBACKS = os.environ.get("GEMINI_MODEL_FALLBACKS", DEFAULT_GEMINI_MODEL_FALLBACKS_ADVANCED)

GEMINI_MODEL_FALLBACKS_ADVANCED = [
    m.strip()
    for m in os.environ.get("GEMINI_MODEL_FALLBACKS_ADVANCED", DEFAULT_GEMINI_MODEL_FALLBACKS_ADVANCED).split(",")
    if m.strip()
]
GEMINI_MODEL_FALLBACKS_FAST = [
    m.strip()
    for m in os.environ.get("GEMINI_MODEL_FALLBACKS_FAST", DEFAULT_GEMINI_MODEL_FALLBACKS_FAST).split(",")
    if m.strip()
]
GEMINI_MODEL_FALLBACKS = [
    m.strip()
    for m in os.environ.get("GEMINI_MODEL_FALLBACKS", DEFAULT_GEMINI_MODEL_FALLBACKS).split(",")
    if m.strip()
]
MODEL_FAST = os.environ.get(
    "GEMINI_MODEL_FAST",
    os.environ.get("GEMINI_MODEL", os.environ.get("VITAL_AI_MODEL", DEFAULT_GEMINI_MODEL))
)
MODEL_ADVANCED = os.environ.get("GEMINI_MODEL_ADVANCED", os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL))
DEFAULT_TIMEOUT = float(os.environ.get("VITAL_AI_TIMEOUT", "20.0"))
DEFAULT_TIMEOUT_FAST = DEFAULT_TIMEOUT
DEFAULT_TIMEOUT_ADVANCED = DEFAULT_TIMEOUT
MAX_PAYLOAD_BYTES = 65536  # 64 KB limit
DEFAULT_NUM_CTX = int(os.environ.get("VITAL_NUM_CTX", 2048))
DEFAULT_NUM_PREDICT = int(os.environ.get("VITAL_NUM_PREDICT", 400))


class HealthResult(tuple):
    """Tuple subclass supporting both tuple unpacking and dict/attribute access."""

    def __new__(cls, is_healthy: bool, message: str, details: Dict[str, Any]):
        return super().__new__(cls, (is_healthy, message, details))

    @property
    def healthy(self) -> bool:
        return self[0]

    @property
    def message(self) -> str:
        return self[1]

    @property
    def details(self) -> Dict[str, Any]:
        return self[2]

    @property
    def status(self) -> str:
        return "online" if self[0] else "offline"

    @property
    def ai_online(self) -> bool:
        return self[0]

    @property
    def ollama_online(self) -> bool:
        return self[0]

    @property
    def model_available(self) -> bool:
        return self[2].get("model_found", False)

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"'HealthResult' object has no attribute '{name}'")

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, IndexError):
            return default

    def __getitem__(self, item):
        if isinstance(item, str):
            if item in ("healthy", "is_healthy", "ollama_online", "ai_online"):
                return self[0]
            if item in ("message", "msg"):
                return self[1]
            if item == "details":
                return self[2]
            if item == "status":
                return "online" if self[0] else "offline"
            if item in ("model_available", "model_found"):
                return self[2].get("model_found", False)
            if item == "model":
                return self[2].get("target_model", self[2].get("model", ""))
            if item == "error":
                return self[2].get("error", "")
            if item in self[2]:
                return self[2][item]
            raise KeyError(item)
        return super().__getitem__(item)

    def __contains__(self, key):
        return key in (
            "healthy",
            "is_healthy",
            "ollama_online",
            "ai_online",
            "message",
            "msg",
            "details",
            "status",
            "model_available",
            "error",
        ) or (len(self) > 2 and key in self[2])


class GeminiClient:
    """
    Cloud-hosted Google Gemini API client for VITAL IDE.
    Provides a drop-in replacement for local OllamaClient with identical
    public interfaces, caching, in-flight guards, and result dictionary shapes.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout: Optional[float] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        model_fast: Optional[str] = None,
        model_advanced: Optional[str] = None,
    ):
        chosen_base_url = (base_url or DEFAULT_GEMINI_BASE_URL).rstrip("/")
        pinned_fast = model_fast or os.environ.get(
            "GEMINI_MODEL_FAST",
            os.environ.get("GEMINI_MODEL", os.environ.get("VITAL_AI_MODEL", MODEL_FAST))
        )
        pinned_advanced = model_advanced or os.environ.get("GEMINI_MODEL_ADVANCED", MODEL_ADVANCED)
        chosen_model = model or model_name or pinned_fast

        self.base_url = chosen_base_url
        self.model_fast = pinned_fast
        self.model_advanced = pinned_advanced
        self.model_name = chosen_model
        self.timeout = float(timeout if timeout is not None else DEFAULT_TIMEOUT)
        self.api_key = api_key

        # Concurrency & deduplication guards
        self._lock = threading.Lock()
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._in_flight: Set[str] = set()

        # Health check cache (60s TTL)
        self._cached_health: Optional[HealthResult] = None
        self._last_health_check_time: float = 0.0
        self._health_cache_ttl: float = 60.0
        self._active_loaded_model: Optional[str] = None

        # Dynamic model discovery & resolution cache
        self._resolved_model_cache: Dict[str, str] = {}
        self._available_models: Optional[List[str]] = None
        self._resolved_model: Optional[str] = None

    @property
    def model(self) -> str:
        return self.model_name

    def _get_api_key(self) -> str:
        """Retrieves active Gemini API key from instance or environment."""
        if self.api_key is not None:
            return self.api_key
        return (
            os.environ.get("GEMINI_API_KEY") or
            os.environ.get("GOOGLE_API_KEY") or
            ""
        ).strip()

    def _sanitize_error(self, err_text: str, api_key: Optional[str] = None) -> str:
        """Strips API keys from error messages to prevent credential leakage."""
        if not err_text:
            return ""
        key = api_key or self._get_api_key()
        if key and key in err_text:
            err_text = err_text.replace(key, "[REDACTED]")
        # Redact potential key header or query patterns
        err_text = re.sub(r'(?:key|x-goog-api-key)[=:]\s*[\w\-]+', r'key=[REDACTED]', err_text, flags=re.IGNORECASE)
        return err_text

    def _url_for_model(self, model: str, action: Optional[str] = None) -> str:
        """Constructs target Gemini REST URL honoring v1beta prefixing."""
        base = self.base_url.rstrip("/")
        if not base.endswith("/v1beta"):
            base = f"{base}/v1beta"
        clean_model = model.replace("models/", "", 1) if model.startswith("models/") else model
        if action:
            return f"{base}/models/{clean_model}:{action}"
        return f"{base}/models/{clean_model}"

    @property
    def resolved_model_advanced(self) -> str:
        """Returns the active resolved advanced model name."""
        return self.resolve_model(self.model_advanced, tier="advanced")

    @property
    def resolved_model_fast(self) -> str:
        """Returns the active resolved fast model name."""
        return self.resolve_model(self.model_fast, tier="fast")

    @property
    def resolved_model(self) -> str:
        """Returns the active resolved model name (defaults to advanced tier for quality)."""
        if not self._resolved_model:
            self._resolved_model = self.resolved_model_advanced
        return self._resolved_model or self.model_name

    def get_available_models(self, force_refresh: bool = False) -> List[str]:
        """Queries GET /v1beta/models to list available models supporting generateContent."""
        if self._available_models is not None and not force_refresh:
            return self._available_models
        api_key = self._get_api_key()
        if not api_key:
            return []
        base = self.base_url.rstrip("/")
        if not base.endswith("/v1beta"):
            base = f"{base}/v1beta"
        url = f"{base}/models"
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "x-goog-api-key": api_key},
                method="GET"
            )
            with urllib.request.urlopen(req, timeout=min(self.timeout, 10.0)) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    models = []
                    for m in data.get("models", []):
                        if "generateContent" in m.get("supportedGenerationMethods", []):
                            clean_name = m.get("name", "").replace("models/", "")
                            if clean_name:
                                models.append(clean_name)
                    self._available_models = models
                    return models
        except Exception:
            pass
        return []

    def resolve_model(self, requested_model: Optional[str] = None, tier: Optional[str] = None) -> str:
        """
        Resolves the target model against the Models API and tier preference list.
        Caches the resolved model so subsequent calls avoid 404 round trips.
        """
        target = requested_model or self.model_name
        effective_tier = tier
        if not effective_tier:
            if target == self.model_fast and target != self.model_advanced:
                effective_tier = "fast"
            elif any(k in target.lower() for k in ("lite", "fast")) and not any(k in target.lower() for k in ("3-flash", "advanced", "pro")):
                effective_tier = "fast"
            else:
                effective_tier = "advanced"

        cache_key = f"{target}_{effective_tier}"
        if cache_key in self._resolved_model_cache:
            return self._resolved_model_cache[cache_key]
        if target in self._resolved_model_cache and not tier:
            return self._resolved_model_cache[target]

        preference_list = GEMINI_MODEL_FALLBACKS_FAST if effective_tier == "fast" else GEMINI_MODEL_FALLBACKS_ADVANCED

        candidates: List[str] = []
        if target:
            candidates.append(target)
        for fb in preference_list:
            if fb not in candidates:
                candidates.append(fb)

        available = self.get_available_models()
        resolved = target
        retired_models = ("gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.5-pro")
        if available:
            # If target is in available, keep target unless it is retired
            if target in available and target not in retired_models:
                resolved = target
            else:
                for c in candidates:
                    if c in retired_models:
                        continue
                    if c in available:
                        resolved = c
                        break
        else:
            resolved = next((c for c in candidates if c not in retired_models), candidates[0] if candidates else target)

        self._resolved_model_cache[cache_key] = resolved
        self._resolved_model_cache[target] = resolved
        if effective_tier == "advanced" or not self._resolved_model:
            self._resolved_model = resolved
        return resolved

    def get_hardware_status(self) -> Dict[str, Any]:
        """Returns hardware/hosted status dictionary indicating hosted Gemini API."""
        return {
            "provider": "Google Gemini API",
            "hosted": True,
            "status": "hosted API, no local hardware constraints",
            "message": "hosted API, no local hardware constraints",
            "model_fast": self.model_fast,
            "model_advanced": self.model_advanced,
            "max_models_in_memory": None,
            "active_model_in_ram": None,
            "all_loaded_models": [],
            "total_ram_mb": 16384,
            "free_ram_mb": 16384,
            "ram_used_percent": 0.0,
            "cpu": "hosted API, no local hardware constraints",
            "gpu": "hosted API, no local hardware constraints",
            "context_window_tokens": 1048576,
        }

    def get_loaded_models(self) -> List[str]:
        """Harmless no-op for hosted API: memory management is handled by Google Gemini."""
        return []

    def unload_model(self, model_name: str) -> bool:
        """Harmless no-op for hosted API: memory management is handled by Google Gemini."""
        return True

    def ensure_single_model_loaded(self, target_model: str) -> float:
        """Harmless no-op for hosted API: multi-model residency handled cloud-side."""
        self._active_loaded_model = target_model
        return 0.0

    def warm_model(self, target_model: Optional[str] = None) -> None:
        """Harmless no-op for hosted API: background model warming is not needed."""
        pass

    def route_model(
        self,
        stage_id: str,
        rule_id: str = "",
        title: str = "",
        is_escalation: bool = False,
        error_count: int = 1,
        source_code: str = ""
    ) -> Tuple[str, str]:
        """
        Intelligent multi-tier model routing keeping exact routing logic and signature:
          - Fast model: Simple syntax, delimiter balancing, bracket matching, single small errors.
          - Advanced model: Complex parser errors, semantic analysis, security vulnerabilities,
            SQL injection, multi-error Fix All, or escalated attempts.
        Returns: (selected_model_name, routing_reason)
        """
        # 1. Escalated corrections always route to Advanced model
        if is_escalation:
            return self.model_advanced, "Escalated to 7B Advanced model after preliminary proposal failed validation."

        # 2. Security vulnerabilities and SQL Injection strictly require Advanced model
        rule_upper = str(rule_id).upper()
        title_lower = title.lower()
        title_upper = title.upper()
        if (
            "SEC-INJ-" in rule_upper or
            "SQL" in title_upper or
            "SEC-IDOR-" in rule_upper or
            "IDOR" in title_lower or
            "SEC-STATE-" in rule_upper or
            "SEC-IR-" in rule_upper or
            stage_id in ("security_analysis", "ai_security_analysis", "deterministic_security")
        ):
            return self.model_advanced, "Routed to 7B Advanced model for deep security vulnerability and dataflow analysis."

        # 3. Complex multi-error Fix All requests route to Advanced model
        if error_count > 2:
            return self.model_advanced, f"Routed to 7B Advanced model for multi-error Fix All synthesis ({error_count} errors)."

        # 4. Semantic errors (scope, identifier, type analysis) route to Advanced model
        if stage_id in ("semantic_analysis", "symbol_table") or "SEC-SEM-" in rule_upper or "SEM-" in rule_upper:
            return self.model_advanced, "Routed to 7B Advanced model for symbol-table and scope resolution."

        # 5. Simple syntax errors and delimiter balancing route to Fast model
        if (
            stage_id in ("syntax_analysis", "parser", "lexical_analysis", "source_input") or
            "SEC-PAR-" in rule_upper or
            "SYN-" in rule_upper or
            "delimiter" in title_lower or
            "brace" in title_lower or
            "parenthes" in title_lower
        ):
            return self.model_fast, "Routed to 3B Lightweight model for fast syntax and delimiter balancing."

        # Default fallback: Fast for small files (<= 60 lines), Advanced for larger
        line_count = len(source_code.splitlines()) if source_code else 1
        if line_count <= 60:
            return self.model_fast, "Routed to 3B Lightweight model for rapid code correction."
        return self.model_advanced, "Routed to 7B Advanced model for comprehensive source analysis."

    def check_health(self, force_refresh: bool = False) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verifies Gemini API availability with a cheap authenticated GET on /v1beta/models/{model_fast}.
        Caches result for 60 seconds.
        Returns: (is_healthy: bool, status_message: str, details: dict)
        """
        if os.environ.get("VITAL_AI_DISABLED") in ("1", "true", "True"):
            return HealthResult(
                False,
                "Gemini AI offline: AI Disabled via VITAL_AI_DISABLED environment variable.",
                {
                    "service_reachable": False,
                    "model_fast_found": False,
                    "model_advanced_found": False,
                    "available_models": [],
                    "target_model": self.model_name,
                    "model_fast": self.model_fast,
                    "model_advanced": self.model_advanced,
                    "latency_ms": 0.0,
                    "hardware": self.get_hardware_status(),
                    "disabled": True
                }
            )

        details: Dict[str, Any] = {
            "service_reachable": False,
            "model_fast_found": False,
            "model_advanced_found": False,
            "available_models": [],
            "target_model": self.model_name,
            "model_fast": self.model_fast,
            "model_advanced": self.model_advanced,
            "latency_ms": 0.0,
            "hardware": self.get_hardware_status()
        }

        if os.environ.get("VITAL_AI_MOCK") in ("1", "true", "TRUE"):
            details["service_reachable"] = True
            details["model_fast_found"] = True
            details["model_advanced_found"] = True
            details["model_found"] = True
            details["available_models"] = [self.model_fast, self.model_advanced]
            return HealthResult(True, f"Gemini mock client online (model: {self.model_fast})", details)

        now = time.time()
        if not force_refresh and self._cached_health and (now - self._last_health_check_time < self._health_cache_ttl):
            return self._cached_health

        api_key = self._get_api_key()
        if not api_key:
            msg = "No API key found (set GEMINI_API_KEY in .env)"
            details["error"] = msg
            result = HealthResult(
                False,
                msg,
                details
            )
            self._cached_health = result
            self._last_health_check_time = now
            return result

        start_time = time.time()
        target_health_model = self.resolve_model(self.model_fast)
        health_url = self._url_for_model(target_health_model)
        try:
            req = urllib.request.Request(
                health_url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "VITAL-AI-Manager/2.0",
                    "x-goog-api-key": api_key
                },
                method="GET"
            )
            with urllib.request.urlopen(req, timeout=min(self.timeout, 15.0)) as resp:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                details["latency_ms"] = elapsed_ms
                details["service_reachable"] = True

                if resp.status == 200:
                    details["model_fast_found"] = True
                    details["model_advanced_found"] = True
                    details["model_found"] = True
                    details["target_model"] = self.model_name
                    details["resolved_model"] = self.resolved_model
                    details["available_models"] = self._available_models or [target_health_model]
                    if self.model_advanced != target_health_model and self.model_advanced not in details["available_models"]:
                        details["available_models"].append(self.model_advanced)

                    msg = f"Gemini API online with model '{self.resolved_model}' ({elapsed_ms}ms)"
                    result = HealthResult(True, msg, details)
                else:
                    details["error"] = f"Gemini API returned HTTP status {resp.status}"
                    result = HealthResult(False, details["error"], details)

        except urllib.error.HTTPError as e:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            details["latency_ms"] = elapsed_ms
            details["service_reachable"] = True
            if e.code in (401, 403):
                msg = f"Gemini rejected the key ({e.code})"
                details["error"] = msg
            elif e.code == 404:
                msg = f"Model '{target_health_model}' not found (404)"
                details["error"] = msg
            elif e.code == 429:
                msg = "Quota exceeded (429), retry later"
                details["error"] = msg
            elif e.code >= 500:
                msg = f"Gemini server error (HTTP {e.code})"
                details["error"] = msg
            else:
                msg = f"Gemini API health check failed with HTTP {e.code}: {e.reason}"
                details["error"] = msg
            result = HealthResult(False, msg, details)

        except (socket.timeout, TimeoutError):
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            details["latency_ms"] = elapsed_ms
            details["service_reachable"] = False
            msg = f"Timed out after {int(self.timeout)}s"
            details["error"] = msg
            result = HealthResult(False, msg, details)

        except urllib.error.URLError as e:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            details["latency_ms"] = elapsed_ms
            details["service_reachable"] = False
            if isinstance(getattr(e, "reason", None), (socket.timeout, TimeoutError)) or "timed out" in str(e).lower():
                msg = f"Timed out after {int(self.timeout)}s"
            else:
                msg = "Network unreachable"
            details["error"] = msg
            result = HealthResult(False, msg, details)

        except Exception as e:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            details["latency_ms"] = elapsed_ms
            details["error"] = self._sanitize_error(str(e), api_key)
            result = HealthResult(False, f"Gemini connection check failed: {details['error']}", details)

        self._cached_health = result
        self._last_health_check_time = now
        return result

    @staticmethod
    def _convert_messages_to_gemini(
        messages: List[Dict[str, Any]]
    ) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Converts Ollama-style messages:
          - 'system' -> systemInstruction: {"parts": [{"text": ...}]}
          - 'assistant' -> contents role: 'model'
          - 'user' -> contents role: 'user'
        """
        system_parts: List[Dict[str, str]] = []
        contents: List[Dict[str, Any]] = []

        for msg in messages:
            role = (msg.get("role") or "user").strip().lower()
            raw_content = msg.get("content", "")
            text_val = str(raw_content) if raw_content is not None else ""

            if role == "system":
                system_parts.append({"text": text_val})
            elif role == "assistant":
                contents.append({
                    "role": "model",
                    "parts": [{"text": text_val}]
                })
            else:  # 'user' or any other fallback
                contents.append({
                    "role": "user",
                    "parts": [{"text": text_val}]
                })

        if not contents:
            contents = [{"role": "user", "parts": [{"text": ""}]}]

        system_instruction = {"parts": system_parts} if system_parts else None
        return system_instruction, contents

    def _failure_result(
        self,
        model: str,
        error_msg: str,
        elapsed_ms: float = 0.0,
        status: str = "error",
        offline: bool = False
    ) -> Dict[str, Any]:
        """Constructs standardized failure payload matching ollama_client contract."""
        return {
            "success": False,
            "content": "",
            "error": error_msg,
            "model": model,
            "latency_ms": elapsed_ms,
            "model_load_time_ms": 0.0,
            "inference_time_ms": 0.0,
            "total_duration_ms": elapsed_ms,
            "model_switch_time_ms": 0.0,
            "tokens_generated": 0,
            "prompt_tokens": 0,
            "tokens_per_second": 0.0,
            "cached": False,
            "status": status,
            "offline": offline
        }

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        tier: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = 2048,
        response_format: Optional[str] = "json",
        timeout: Optional[float] = None,
        cache_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sends a thread-safe chat completion request to the Google Gemini API.
        Maintains exact return dictionary shape, request deduplication, and caching.
        """
        raw_target_model = model or self.model_name
        effective_tier = tier
        if not effective_tier:
            if raw_target_model == self.model_fast and raw_target_model != self.model_advanced:
                effective_tier = "fast"
            elif any(k in raw_target_model.lower() for k in ("lite", "fast")) and not any(k in raw_target_model.lower() for k in ("3-flash", "advanced", "pro")):
                effective_tier = "fast"
            else:
                effective_tier = "advanced"

        target_model = self.resolve_model(raw_target_model, tier=effective_tier)
        active_fallbacks = GEMINI_MODEL_FALLBACKS_FAST if effective_tier == "fast" else GEMINI_MODEL_FALLBACKS_ADVANCED
        rotation_history: List[Tuple[str, str, str]] = []
        effective_timeout = timeout if timeout is not None else self.timeout

        # 1. Check cache
        if cache_key and cache_key in self._cache:
            cached_resp = dict(self._cache[cache_key])
            cached_resp["cached"] = True
            return cached_resp

        # 2. Check disabled status
        if os.environ.get("VITAL_AI_DISABLED") in ("1", "true", "True"):
            return self._failure_result(
                target_model,
                "Gemini AI offline or unreachable: AI Disabled via VITAL_AI_DISABLED.",
                status="error",
                offline=True
            )

        # 3. Check mock mode for deterministic tests
        if os.environ.get("VITAL_AI_MOCK") in ("1", "true", "TRUE"):
            mock_content = json.dumps({
                "status": "ok",
                "identified_root_cause": "Mock diagnostic root cause.",
                "explanation": "Deterministic mock explanation.",
                "target_line": 1,
                "original_code": "",
                "corrected_code": "",
                "proposed_source": "",
                "safety_assessment": "Verified safe."
            }) if response_format == "json" else "Mock Gemini completion."
            return {
                "success": True,
                "content": mock_content,
                "error": None,
                "model": target_model,
                "latency_ms": 1.0,
                "model_load_time_ms": 0.0,
                "inference_time_ms": 1.0,
                "total_duration_ms": 1.0,
                "model_switch_time_ms": 0.0,
                "tokens_generated": 20,
                "prompt_tokens": 10,
                "tokens_per_second": 20000.0,
                "cached": False,
                "status": "ok",
                "offline": False
            }

        # 4. Check API key presence
        api_key = self._get_api_key()
        if not api_key:
            return self._failure_result(
                target_model,
                "Gemini API key not configured (set GEMINI_API_KEY or GOOGLE_API_KEY).",
                status="error",
                offline=True
            )

        # 5. Guard against duplicate in-flight requests
        if cache_key and cache_key in self._in_flight:
            return self._failure_result(
                target_model,
                "Duplicate inference request is already in progress for this diagnostic.",
                status="error",
                offline=False
            )

        if cache_key:
            self._in_flight.add(cache_key)

        start_time = time.time()

        # Thread lock for sequential safety
        with self._lock:
            try:
                # Build Gemini request payload
                system_instruction, contents = self._convert_messages_to_gemini(messages)
                payload: Dict[str, Any] = {"contents": contents}
                if system_instruction:
                    payload["systemInstruction"] = system_instruction

                generation_config: Dict[str, Any] = {}
                if response_format in ("json", "application/json") or (
                    isinstance(response_format, dict) and response_format.get("type") == "json_object"
                ):
                    generation_config["responseMimeType"] = "application/json"

                if temperature is not None:
                    try:
                        generation_config["temperature"] = float(temperature)
                    except (ValueError, TypeError):
                        pass

                if max_tokens is not None:
                    try:
                        generation_config["maxOutputTokens"] = int(max_tokens)
                    except (ValueError, TypeError):
                        pass

                # Disable or minimize thinking budget for non-lite models to prevent JSON output truncation
                if "lite" not in target_model.lower():
                    generation_config["thinkingConfig"] = {"thinkingBudget": 0}

                if generation_config:
                    payload["generationConfig"] = generation_config

                payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                if len(payload_bytes) > MAX_PAYLOAD_BYTES:
                    return self._failure_result(
                        target_model,
                        f"Payload size ({len(payload_bytes)} bytes) exceeds safety limit ({MAX_PAYLOAD_BYTES} bytes)",
                        elapsed_ms=0.0,
                        status="error"
                    )

                generate_url = self._url_for_model(target_model, "generateContent")
                headers = {
                    "Content-Type": "application/json; charset=utf-8",
                    "Accept": "application/json",
                    "User-Agent": "VITAL-AI-Manager/2.0",
                    "x-goog-api-key": api_key
                }

                # Retry loop handling HTTP 429 rate limits (up to 2 retries)
                max_retries = 2
                attempt = 0
                while attempt <= max_retries:
                    try:
                        req = urllib.request.Request(
                            generate_url,
                            data=payload_bytes,
                            headers=headers,
                            method="POST"
                        )
                        with urllib.request.urlopen(req, timeout=effective_timeout) as resp:
                            elapsed_ms = round((time.time() - start_time) * 1000, 2)
                            if resp.status == 200:
                                raw_body = resp.read().decode("utf-8", errors="replace")
                                try:
                                    resp_json = json.loads(raw_body)
                                except Exception as json_err:
                                    return self._failure_result(
                                        target_model,
                                        f"Malformed JSON received from Gemini API: {json_err}",
                                        elapsed_ms=elapsed_ms,
                                        status="error"
                                    )

                                # Check promptFeedback for safety blocks
                                prompt_feedback = resp_json.get("promptFeedback", {})
                                block_reason = prompt_feedback.get("blockReason")
                                if block_reason:
                                    return self._failure_result(
                                        target_model,
                                        f"Gemini prompt blocked by safety filters: {block_reason}",
                                        elapsed_ms=elapsed_ms,
                                        status="error"
                                    )

                                candidates = resp_json.get("candidates", [])
                                if not candidates:
                                    return self._failure_result(
                                        target_model,
                                        "Gemini API returned no candidates (empty response).",
                                        elapsed_ms=elapsed_ms,
                                        status="error"
                                    )

                                candidate = candidates[0]
                                finish_reason = candidate.get("finishReason", "")
                                if finish_reason in ("SAFETY", "RECITATION", "BLOCKLIST"):
                                    return self._failure_result(
                                        target_model,
                                        f"Gemini response blocked due to {finish_reason}.",
                                        elapsed_ms=elapsed_ms,
                                        status="error"
                                    )

                                # Read content text parts
                                parts = candidate.get("content", {}).get("parts", [])
                                text_parts = []
                                for p in parts:
                                    if isinstance(p, dict) and "text" in p:
                                        if not p.get("thought", False):
                                            text_parts.append(p["text"])
                                msg_content = "".join(text_parts)

                                if response_format in ("json", "application/json") or (
                                    isinstance(response_format, dict) and response_format.get("type") == "json_object"
                                ):
                                    cleaned = msg_content.strip()
                                    if cleaned.startswith("```"):
                                        cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned)
                                        cleaned = re.sub(r"\n?```$", "", cleaned)
                                    msg_content = cleaned.strip()

                                if not msg_content and finish_reason and finish_reason != "STOP":
                                    return self._failure_result(
                                        target_model,
                                        f"Gemini returned empty content with finishReason: {finish_reason}",
                                        elapsed_ms=elapsed_ms,
                                        status="error"
                                    )

                                # Read token counts from usageMetadata
                                usage = resp_json.get("usageMetadata", {})
                                prompt_tokens = usage.get("promptTokenCount", 0)
                                tokens_generated = usage.get("candidatesTokenCount", 0)

                                tok_sec = elapsed_ms / 1000.0
                                tok_rate = round(tokens_generated / tok_sec, 1) if tok_sec > 0 and tokens_generated > 0 else 0.0

                                result_payload = {
                                    "success": True,
                                    "content": msg_content,
                                    "error": None,
                                    "model": target_model,
                                    "tier": effective_tier,
                                    "rotations": rotation_history,
                                    "latency_ms": elapsed_ms,
                                    "model_load_time_ms": 0.0,
                                    "inference_time_ms": elapsed_ms,
                                    "total_duration_ms": elapsed_ms,
                                    "model_switch_time_ms": 0.0,
                                    "tokens_generated": tokens_generated,
                                    "prompt_tokens": prompt_tokens,
                                    "tokens_per_second": tok_rate,
                                    "cached": False,
                                    "status": "ok",
                                    "offline": False
                                }

                                if cache_key:
                                    self._cache[cache_key] = result_payload

                                return result_payload
                            else:
                                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                                return self._failure_result(
                                    target_model,
                                    f"Gemini API returned HTTP {resp.status}",
                                    elapsed_ms=elapsed_ms,
                                    status="error"
                                )

                    except urllib.error.HTTPError as e:
                        elapsed_ms = round((time.time() - start_time) * 1000, 2)
                        err_body = ""
                        try:
                            err_body = e.read().decode("utf-8", errors="replace")
                        except Exception:
                            pass
                        clean_err = self._sanitize_error(err_body, api_key)

                        # Handle 429 Rate Limit with exponential backoff and Retry-After header
                        if e.code == 429:
                            if "quota" in clean_err.lower() or "resource_exhausted" in clean_err.lower():
                                available = self.get_available_models()
                                next_model = None
                                for fb in active_fallbacks:
                                    if fb != target_model and (not available or fb in available):
                                        next_model = fb
                                        break
                                if not next_model:
                                    for fb in GEMINI_MODEL_FALLBACKS_FAST + GEMINI_MODEL_FALLBACKS_ADVANCED:
                                        if fb != target_model and (not available or fb in available):
                                            next_model = fb
                                            break
                                if next_model and attempt <= max_retries:
                                    rotation_history.append((target_model, next_model, "HTTP 429 quota exhaustion"))
                                    print(f"[Gemini Client] Model rotated from '{target_model}' to '{next_model}' (attempt {attempt + 1}) due to HTTP 429 quota exhaustion.")
                                    target_model = next_model
                                    self._resolved_model_cache[raw_target_model] = target_model
                                    self._resolved_model_cache[f"{raw_target_model}_{effective_tier}"] = target_model
                                    if effective_tier == "advanced":
                                        self._resolved_model = target_model
                                    generate_url = self._url_for_model(target_model, "generateContent")
                                    attempt += 1
                                    continue

                            attempt += 1
                            if attempt <= max_retries:
                                retry_after = e.headers.get("Retry-After") if hasattr(e, "headers") and e.headers else None
                                sleep_time = 0.0
                                if retry_after:
                                    try:
                                        sleep_time = float(retry_after)
                                    except (ValueError, TypeError):
                                        pass
                                if sleep_time <= 0.0:
                                    sleep_time = 2.0 ** attempt  # 2.0s, 4.0s
                                time.sleep(min(sleep_time, 10.0))
                                continue

                            return self._failure_result(
                                target_model,
                                f"Gemini API rate limit exceeded (HTTP 429) after {max_retries} retries: {clean_err}",
                                elapsed_ms=elapsed_ms,
                                status="error"
                            )

                        # Handle 401/403 Authentication Error
                        if e.code in (401, 403):
                            return self._failure_result(
                                target_model,
                                f"Gemini API authentication failed (HTTP {e.code}): invalid or unauthorized API key.",
                                elapsed_ms=elapsed_ms,
                                status="error"
                            )

                        # Handle 400 Bad Request
                        if e.code == 400:
                            if "thinkingConfig" in payload.get("generationConfig", {}) and attempt <= max_retries:
                                payload["generationConfig"].pop("thinkingConfig", None)
                                payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                                attempt += 1
                                continue
                            return self._failure_result(
                                target_model,
                                f"Gemini API Bad Request (HTTP 400): {clean_err}",
                                elapsed_ms=elapsed_ms,
                                status="error"
                            )

                        # Handle 404 Model Retired / Not Found (fallback to next candidate in active_fallbacks)
                        if e.code == 404:
                            available = self.get_available_models(force_refresh=True)
                            next_model = None
                            for fb in active_fallbacks:
                                if fb != target_model and (not available or fb in available):
                                    next_model = fb
                                    break
                            if not next_model:
                                for fb in GEMINI_MODEL_FALLBACKS_FAST + GEMINI_MODEL_FALLBACKS_ADVANCED:
                                    if fb != target_model and (not available or fb in available):
                                        next_model = fb
                                        break
                            if next_model and attempt <= max_retries:
                                rotation_history.append((target_model, next_model, "HTTP 404 model retirement"))
                                print(f"[Gemini Client] Model rotated from '{target_model}' to '{next_model}' (attempt {attempt + 1}) due to HTTP 404 model retirement.")
                                target_model = next_model
                                self._resolved_model_cache[raw_target_model] = target_model
                                self._resolved_model_cache[f"{raw_target_model}_{effective_tier}"] = target_model
                                if effective_tier == "advanced":
                                    self._resolved_model = target_model
                                generate_url = self._url_for_model(target_model, "generateContent")
                                attempt += 1
                                continue

                        # Handle 5xx Server Error (retry up to 2 times with exponential backoff)
                        if e.code >= 500:
                            attempt += 1
                            if attempt <= max_retries:
                                sleep_time = min(2.0 ** attempt, 10.0)
                                time.sleep(sleep_time)
                                continue
                            return self._failure_result(
                                target_model,
                                f"Gemini API server error (HTTP {e.code}): {e.reason}",
                                elapsed_ms=elapsed_ms,
                                status="error"
                            )

                        return self._failure_result(
                            target_model,
                            f"Gemini HTTP Error {e.code}: {e.reason}. {clean_err}".strip(),
                            elapsed_ms=elapsed_ms,
                            status="error"
                        )

            except (socket.timeout, TimeoutError) as e:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                return self._failure_result(
                    target_model,
                    f"Gemini model '{target_model}' timed out after {effective_timeout}s: {e}",
                    elapsed_ms=elapsed_ms,
                    status="unresolved"
                )

            except urllib.error.URLError as e:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                if isinstance(getattr(e, "reason", None), (socket.timeout, TimeoutError)) or "timed out" in str(e).lower():
                    return self._failure_result(
                        target_model,
                        f"Gemini model '{target_model}' timed out after {effective_timeout}s: {e}",
                        elapsed_ms=elapsed_ms,
                        status="unresolved"
                    )
                clean_err = self._sanitize_error(str(e.reason if hasattr(e, "reason") else e), api_key)
                return self._failure_result(
                    target_model,
                    f"Gemini service unreachable at {self.base_url} ({clean_err})",
                    elapsed_ms=elapsed_ms,
                    status="error",
                    offline=True
                )

            except Exception as e:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                clean_err = self._sanitize_error(str(e), api_key)
                is_timeout = "timeout" in clean_err.lower()
                return self._failure_result(
                    target_model,
                    f"Gemini invocation error with '{target_model}': {clean_err}",
                    elapsed_ms=elapsed_ms,
                    status="unresolved" if is_timeout else "error"
                )

            finally:
                if cache_key and cache_key in self._in_flight:
                    self._in_flight.remove(cache_key)

    def generate_text(self, prompt: str, tier: str = "advanced") -> str:
        """Sends a text completion prompt and returns the raw text content."""
        messages = [{"role": "user", "content": prompt}]
        res = self.chat(messages=messages, tier=tier)
        if res.get("success"):
            return res.get("content", "")
        return ""

    def get_config(self) -> Dict[str, Any]:
        """Returns client configuration and API status."""
        return {
            "provider": "gemini",
            "base_url": self.base_url,
            "model_name": self.model_name,
            "resolved_model": self.resolved_model,
            "resolved_model_advanced": self.resolved_model_advanced,
            "resolved_model_fast": self.resolved_model_fast,
            "model_fast": self.model_fast,
            "model_advanced": self.model_advanced,
            "fallbacks_advanced": GEMINI_MODEL_FALLBACKS_ADVANCED,
            "fallbacks_fast": GEMINI_MODEL_FALLBACKS_FAST,
            "fallbacks": GEMINI_MODEL_FALLBACKS,
            "timeout": self.timeout,
            "timeout_fast": self.timeout,
            "timeout_advanced": self.timeout,
            "hardware": self.get_hardware_status()
        }


# Singleton instance
ai_client = GeminiClient()
gemini_client = ai_client
ollama_client = ai_client
