# -*- coding: utf-8 -*-
"""
web/ollama_client.py — Hardware-Aware Multi-Model Ollama AI Client for VITAL IDE

Hardware Profile & Resource Management:
  - RAM Constraint: 16 GB Total RAM.
  - Processor: Intel Core i5-11300H (11th Gen) with Intel Iris Xe Graphics (No CUDA).
  - Multi-Model Architecture:
      1. Primary Lightweight Model: qwen2.5-coder:3b (Fast, ~1.9 GB)
         - Simple syntax errors, delimiter balancing, diagnostic classification, small fixes.
      2. Advanced Coding Model: qwen2.5-coder:7b-instruct (Advanced, ~4.7 GB)
         - Complex parser errors, semantic errors, security vulnerabilities, SQL injection,
           multi-error Fix All, and automatic escalation when 3B proposals fail validation.
  - Strict Memory Rules:
      - Maximum ONE model loaded into memory at any time.
      - Controlled sequential execution (concurrency lock).
      - Explicit model eviction (keep_alive: 0) before switching models.
      - Context window capped at 4096 tokens (num_ctx: 4096).
      - Granular performance metrics (model loading, inference, eval count, token rate, memory).
      - Request deduplication & caching to eliminate redundant inferences.
"""

import os
import sys
import json
import time
import socket
import urllib.request
import urllib.error
import threading
from typing import Dict, Any, List, Optional, Tuple, Set

# Optional psutil for memory monitoring
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Configuration with defaults
DEFAULT_OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
MODEL_FAST = os.environ.get("OLLAMA_MODEL_FAST", "qwen2.5-coder:3b")
MODEL_ADVANCED = os.environ.get("OLLAMA_MODEL_ADVANCED", "qwen2.5-coder:7b-instruct")
DEFAULT_TIMEOUT_FAST = float(os.environ.get("OLLAMA_TIMEOUT_FAST", "35.0"))
DEFAULT_TIMEOUT_ADVANCED = float(os.environ.get("OLLAMA_TIMEOUT_ADVANCED", "65.0"))
MAX_PAYLOAD_BYTES = 65536  # 64 KB limit
DEFAULT_NUM_CTX = 4096     # Context window capped at 4096 tokens for 16GB RAM


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
    def model_available(self) -> bool:
        return self[2].get("model_found", False)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (KeyError, IndexError):
            return default

    def __getitem__(self, item):
        if isinstance(item, str):
            if item in ("healthy", "is_healthy", "ollama_online"):
                return self[0]
            if item in ("message", "msg"):
                return self[1]
            if item == "details":
                return self[2]
            if item == "status":
                return "online" if self[0] else "offline"
            if item in ("model_available", "model_found"):
                return self[2].get("model_found", False)
            if item == "error":
                return self[2].get("error", "")
            if item in self[2]:
                return self[2][item]
            raise KeyError(item)
        return super().__getitem__(item)

    def __contains__(self, key):
        return key in ("healthy", "is_healthy", "ollama_online", "message", "msg", "details", "status", "model_available", "error") or (len(self) > 2 and key in self[2])


class OllamaClient:
    """
    Hardware-aware, multi-model client for local Ollama service.
    Intelligently routes between qwen2.5-coder:3b and qwen2.5-coder:7b-instruct
    with single-model memory guarantees on a 16 GB RAM PC.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_BASE_URL,
        model_name: str = MODEL_ADVANCED,
        timeout: float = DEFAULT_TIMEOUT_ADVANCED,
        model: Optional[str] = None
    ):
        if model:
            model_name = model
        self.base_url = base_url.rstrip("/")
        self.model_fast = MODEL_FAST
        self.model_advanced = MODEL_ADVANCED
        self.model_name = model_name
        self.timeout = timeout

        # Memory & concurrency management
        self._lock = threading.Lock()
        self._active_loaded_model: Optional[str] = None
        self._last_loaded_models_cache: List[str] = []

        # Request caching & deduplication
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._in_flight: Set[str] = set()

        # Health check cache
        self._cached_health: Optional[HealthResult] = None
        self._last_health_check_time: float = 0.0
        self._health_cache_ttl: float = 3.0  # seconds

    @property
    def model(self) -> str:
        return self.model_name

    @property
    def chat_url(self) -> str:
        return f"{self.base_url}/api/chat"

    @property
    def generate_url(self) -> str:
        return f"{self.base_url}/api/generate"

    @property
    def tags_url(self) -> str:
        return f"{self.base_url}/api/tags"

    @property
    def ps_url(self) -> str:
        return f"{self.base_url}/api/ps"

    def get_hardware_status(self) -> Dict[str, Any]:
        """Inspects physical memory and active model allocation."""
        total_ram_mb = 16384
        free_ram_mb = 8192
        percent_used = 50.0

        if HAS_PSUTIL:
            try:
                vm = psutil.virtual_memory()
                total_ram_mb = round(vm.total / (1024 * 1024), 1)
                free_ram_mb = round(vm.available / (1024 * 1024), 1)
                percent_used = vm.percent
            except Exception:
                pass

        # Query loaded models in Ollama memory
        loaded_in_ollama = self.get_loaded_models()
        active_model = loaded_in_ollama[0] if loaded_in_ollama else self._active_loaded_model

        return {
            "total_ram_mb": total_ram_mb,
            "free_ram_mb": free_ram_mb,
            "ram_used_percent": percent_used,
            "cpu": "Intel Core i5-11300H (11th Gen)",
            "gpu": "Intel Iris Xe Graphics (CPU/ggml execution runner)",
            "max_models_in_memory": 1,
            "active_model_in_ram": active_model,
            "all_loaded_models": loaded_in_ollama,
            "model_fast": self.model_fast,
            "model_advanced": self.model_advanced,
            "context_window_tokens": DEFAULT_NUM_CTX
        }

    def get_loaded_models(self) -> List[str]:
        """Queries Ollama /api/ps to see which models are currently resident in RAM."""
        try:
            req = urllib.request.Request(
                self.ps_url,
                headers={"Accept": "application/json", "User-Agent": "VITAL-AI-Manager/2.0"}
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="replace"))
                    models = [m.get("name") or m.get("model") for m in data.get("models", [])]
                    self._last_loaded_models_cache = [m for m in models if m]
                    return self._last_loaded_models_cache
        except Exception:
            pass
        return self._last_loaded_models_cache

    def unload_model(self, model_name: str) -> bool:
        """
        Explicitly unloads a model from RAM by posting keep_alive: 0 to Ollama.
        Guarantees that memory is returned to the system before switching models.
        """
        if not model_name:
            return True
        try:
            payload = json.dumps({
                "model": model_name,
                "keep_alive": 0
            }).encode("utf-8")
            req = urllib.request.Request(
                self.generate_url,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "VITAL-AI-Manager/2.0"}
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                if resp.status == 200:
                    if self._active_loaded_model == model_name:
                        self._active_loaded_model = None
                    return True
        except Exception:
            pass
        return False

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
        Hardware-aware intelligent model routing.
        Selects between qwen2.5-coder:3b (Fast) and qwen2.5-coder:7b-instruct (Advanced):
          - 3B: Simple syntax, delimiter balancing, bracket matching, single small errors.
          - 7B: Complex parser errors, semantic analysis, security vulnerabilities,
                SQL injection, multi-error Fix All, or escalated attempts.
        Returns: (selected_model_name, routing_reason)
        """
        # 1. Escalated corrections always route to Advanced 7B model
        if is_escalation:
            return self.model_advanced, "Escalated to 7B Advanced model after preliminary proposal failed validation."

        # 2. Security vulnerabilities and SQL Injection strictly require Advanced 7B model
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

        # 3. Complex multi-error Fix All requests route to Advanced 7B model
        if error_count > 2:
            return self.model_advanced, f"Routed to 7B Advanced model for multi-error Fix All synthesis ({error_count} errors)."

        # 4. Semantic errors (scope, identifier, type analysis) route to Advanced 7B model
        if stage_id in ("semantic_analysis", "symbol_table") or "SEC-SEM-" in rule_upper or "SEM-" in rule_upper:
            return self.model_advanced, "Routed to 7B Advanced model for symbol-table and scope resolution."

        # 5. Simple syntax errors and delimiter balancing route to Lightweight 3B model
        if (
            stage_id in ("syntax_analysis", "parser", "lexical_analysis", "source_input") or
            "SEC-PAR-" in rule_upper or
            "SYN-" in rule_upper or
            "delimiter" in title_lower or
            "brace" in title_lower or
            "parenthes" in title_lower
        ):
            return self.model_fast, "Routed to 3B Lightweight model for fast syntax and delimiter balancing."

        # Default fallback: 3B for small files (< 60 lines), 7B for larger
        line_count = len(source_code.splitlines()) if source_code else 1
        if line_count <= 60:
            return self.model_fast, "Routed to 3B Lightweight model for rapid code correction."
        return self.model_advanced, "Routed to 7B Advanced model for comprehensive source analysis."

    def ensure_single_model_loaded(self, target_model: str) -> float:
        """
        Enforces that only target_model is loaded in memory.
        If another model is currently in memory, unloads it first.
        Returns: model_switch_time_ms
        """
        switch_start = time.time()
        switch_occurred = False

        currently_loaded = self.get_loaded_models()
        for loaded in currently_loaded:
            # Check if a different model tag is resident
            if loaded != target_model:
                self.unload_model(loaded)
                switch_occurred = True

        self._active_loaded_model = target_model
        return round((time.time() - switch_start) * 1000, 2) if switch_occurred else 0.0

    def check_health(self, force_refresh: bool = False) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verifies local Ollama service and checks availability of both 3B and 7B models.
        Returns: (is_healthy: bool, status_message: str, details: dict)
        """
        if os.environ.get("VITAL_AI_DISABLED") in ("1", "true", "True"):
            return HealthResult(
                False,
                "Ollama offline: AI Disabled via VITAL_AI_DISABLED environment variable.",
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

        now = time.time()
        if not force_refresh and self._cached_health and (now - self._last_health_check_time < self._health_cache_ttl):
            return self._cached_health

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

        start_time = time.time()
        try:
            req = urllib.request.Request(
                self.tags_url,
                headers={"Accept": "application/json", "User-Agent": "VITAL-AI-Manager/2.0"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                details["latency_ms"] = elapsed_ms
                details["service_reachable"] = True

                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="replace"))
                    models = [m.get("name", "") for m in data.get("models", [])]
                    details["available_models"] = models

                    # Check fast model
                    fast_base = self.model_fast.split(":")[0]
                    found_fast = any(m == self.model_fast or m.split(":")[0] == fast_base for m in models)
                    details["model_fast_found"] = found_fast

                    # Check advanced model
                    adv_base = self.model_advanced.split(":")[0]
                    found_adv = any(m == self.model_advanced or m.split(":")[0] == adv_base for m in models)
                    details["model_advanced_found"] = found_adv

                    details["model_found"] = (found_fast or found_adv)

                    if found_fast and found_adv:
                        msg = f"Ollama online with dual models ('{self.model_fast}' and '{self.model_advanced}') ({elapsed_ms}ms)"
                        result = HealthResult(True, msg, details)
                    elif found_adv:
                        msg = f"Ollama online with advanced model '{self.model_advanced}' ({elapsed_ms}ms)"
                        result = HealthResult(True, msg, details)
                    elif found_fast:
                        msg = f"Ollama online with fast model '{self.model_fast}' ({elapsed_ms}ms)"
                        result = HealthResult(True, msg, details)
                    else:
                        msg = f"Ollama online, but neither '{self.model_fast}' nor '{self.model_advanced}' was found in {models}"
                        result = HealthResult(False, msg, details)
                else:
                    result = HealthResult(False, f"Ollama returned HTTP status {resp.status}", details)

        except urllib.error.URLError as e:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            details["latency_ms"] = elapsed_ms
            details["service_reachable"] = False
            details["error"] = str(e.reason if hasattr(e, 'reason') else e)
            result = HealthResult(False, f"Ollama service offline at {self.base_url} ({details['error']})", details)
        except Exception as e:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            details["latency_ms"] = elapsed_ms
            details["error"] = str(e)
            result = HealthResult(False, f"Ollama connection check failed: {e}", details)

        self._cached_health = result
        self._last_health_check_time = now
        return result

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = 2048,
        response_format: Optional[str] = "json",
        timeout: Optional[float] = None,
        cache_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sends a thread-safe, sequential chat request to local Ollama.
        Guarantees single-model memory residence and extracts granular timing metrics.
        """
        target_model = model or self.model_name
        effective_timeout = timeout or (DEFAULT_TIMEOUT_FAST if target_model == self.model_fast else DEFAULT_TIMEOUT_ADVANCED)

        # Check Cache
        if cache_key and cache_key in self._cache:
            cached_resp = dict(self._cache[cache_key])
            cached_resp["cached"] = True
            return cached_resp

        if os.environ.get("VITAL_AI_DISABLED") in ("1", "true", "True"):
            return {
                "success": False,
                "content": "",
                "error": "Ollama offline or unreachable: AI Disabled via VITAL_AI_DISABLED.",
                "offline": True,
                "model": target_model
            }

        # Check in-flight duplicate requests
        if cache_key and cache_key in self._in_flight:
            return {
                "success": False,
                "content": "",
                "error": "Duplicate inference request is already in progress for this diagnostic.",
                "model": target_model,
                "cached": False
            }

        if cache_key:
            self._in_flight.add(cache_key)

        # Acquire lock for sequential execution (never run multiple models concurrently)
        with self._lock:
            try:
                # 1. Enforce single loaded model in memory
                switch_ms = self.ensure_single_model_loaded(target_model)

                # 2. Build payload with num_ctx=4096 and keep_alive="5m"
                payload: Dict[str, Any] = {
                    "model": target_model,
                    "messages": messages,
                    "stream": False,
                    "keep_alive": "5m",
                    "options": {
                        "temperature": temperature,
                        "num_ctx": DEFAULT_NUM_CTX
                    }
                }
                if response_format:
                    payload["format"] = response_format
                if max_tokens:
                    payload["options"]["num_predict"] = max_tokens

                payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                if len(payload_bytes) > MAX_PAYLOAD_BYTES:
                    return {
                        "success": False,
                        "content": "",
                        "error": f"Payload size ({len(payload_bytes)} bytes) exceeds safety limit ({MAX_PAYLOAD_BYTES} bytes)",
                        "model": target_model
                    }

                start_time = time.time()
                req = urllib.request.Request(
                    self.chat_url,
                    data=payload_bytes,
                    headers={
                        "Content-Type": "application/json; charset=utf-8",
                        "Accept": "application/json",
                        "User-Agent": "VITAL-AI-Manager/2.0"
                    },
                    method="POST"
                )

                with urllib.request.urlopen(req, timeout=effective_timeout) as resp:
                    elapsed_ms = round((time.time() - start_time) * 1000, 2)
                    if resp.status == 200:
                        raw_data = resp.read().decode("utf-8", errors="replace")
                        resp_json = json.loads(raw_data)
                        msg_content = resp_json.get("message", {}).get("content", "")

                        # Extract granular timing metrics from Ollama response
                        load_dur = resp_json.get("load_duration", 0)
                        eval_dur = resp_json.get("eval_duration", 0)
                        total_dur = resp_json.get("total_duration", 0)
                        eval_count = resp_json.get("eval_count", 0)
                        prompt_eval_count = resp_json.get("prompt_eval_count", 0)

                        load_dur_ms = round(load_dur / 1e6, 2) if load_dur else 0.0
                        eval_dur_ms = round(eval_dur / 1e6, 2) if eval_dur else elapsed_ms
                        total_dur_ms = round(total_dur / 1e6, 2) if total_dur else elapsed_ms

                        # Calculate token speed
                        tok_rate = round(eval_count / (eval_dur / 1e9), 1) if eval_dur > 0 else 0.0

                        result_payload = {
                            "success": True,
                            "content": msg_content,
                            "error": None,
                            "model": resp_json.get("model", target_model),
                            "latency_ms": elapsed_ms,
                            "model_load_time_ms": load_dur_ms,
                            "inference_time_ms": eval_dur_ms,
                            "total_duration_ms": total_dur_ms,
                            "model_switch_time_ms": switch_ms,
                            "tokens_generated": eval_count,
                            "prompt_tokens": prompt_eval_count,
                            "tokens_per_second": tok_rate,
                            "cached": False
                        }

                        if cache_key:
                            self._cache[cache_key] = result_payload

                        return result_payload
                    else:
                        return {
                            "success": False,
                            "content": "",
                            "error": f"Ollama HTTP {resp.status}",
                            "model": target_model,
                            "latency_ms": elapsed_ms
                        }

            except urllib.error.HTTPError as e:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                err_body = ""
                try:
                    err_body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                return {
                    "success": False,
                    "content": "",
                    "error": f"Ollama HTTP Error {e.code}: {e.reason}. {err_body}".strip(),
                    "model": target_model,
                    "latency_ms": elapsed_ms
                }
            except (socket.timeout, TimeoutError) as e:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                return {
                    "success": False,
                    "content": "",
                    "error": f"Ollama model '{target_model}' timed out after {effective_timeout}s: {e}",
                    "model": target_model,
                    "latency_ms": elapsed_ms
                }
            except Exception as e:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                return {
                    "success": False,
                    "content": "",
                    "error": f"Ollama invocation error with '{target_model}': {e}",
                    "model": target_model,
                    "latency_ms": elapsed_ms
                }
            finally:
                if cache_key and cache_key in self._in_flight:
                    self._in_flight.remove(cache_key)

    def get_config(self) -> Dict[str, Any]:
        """Returns client configuration and hardware status."""
        return {
            "base_url": self.base_url,
            "model_fast": self.model_fast,
            "model_advanced": self.model_advanced,
            "timeout_fast": DEFAULT_TIMEOUT_FAST,
            "timeout_advanced": DEFAULT_TIMEOUT_ADVANCED,
            "hardware": self.get_hardware_status()
        }


# Singleton instance
ollama_client = OllamaClient()
