#!/usr/bin/env python3
"""Synthetic fixtures only: no network, no credentials, no real secret resolution."""
import ast
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys


def load_module():
    path = Path(__file__).parent / "asm-exec-compat"
    loader = importlib.machinery.SourceFileLoader("compat_offline_fixture", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    module._check_sma = lambda: False
    module.time.sleep = lambda seconds: None
    return module


def fixture(value="fixture-only-not-a-secret", **updates):
    payload = {"status": "success", "stdout": "", "stderr": None,
               "return_value": {"SecretString": value},
               "api_calls": [{"service": "secretsmanager", "operation": "GetSecretValue", "status": "success"}]}
    payload.update(updates)
    return {"result": {"structuredContent": payload, "isError": False}}


def main():
    module = load_module()
    calls = []
    def mocked_post(payload, session_id=None):
        calls.append(payload)
        if payload["method"] == "initialize":
            return {"result": {"protocolVersion": "2025-06-18"}}, "fixture-session"
        if payload["method"] == "notifications/initialized":
            return {}, None
        return fixture(json.dumps({"password": "fixture-password", "username": "fixture-username"})), None
    module._mcp_post = mocked_post
    prefix = "{{resolve:secretsmanager:fixture-not-a-real-resource:SecretString:"
    assert module.resolve_string(prefix + "password:AWSCURRENT}}") == "fixture-password"
    assert module.resolve_string(prefix + "username:AWSCURRENT}}") == "fixture-username"
    assert len([call for call in calls if call["method"] == "tools/call"]) == 1
    module._resolve_via_mcp("fixture-not-a-real-resource", "AWSPENDING", "us-east-1")
    module._resolve_via_mcp("fixture-not-a-real-resource", "AWSPENDING", "us-west-2")
    assert len([call for call in calls if call["method"] == "tools/call"]) == 3
    assert module._mcp_verified_secret(fixture(stdout="fixture-console-output")) is None
    assert module._mcp_verified_secret(fixture(stderr="fixture-error")) is None
    assert module._mcp_verified_secret(fixture(api_calls=[])) is None
    wrong = [{"service": "sts", "operation": "GetCallerIdentity", "status": "success"}]
    assert module._mcp_verified_secret(fixture(api_calls=wrong)) is None
    wrong_operation = [{"service": "secretsmanager", "operation": "DescribeSecret", "status": "success"}]
    assert module._mcp_verified_secret(fixture(api_calls=wrong_operation)) is None
    assert module._mcp_verified_secret(fixture(api_calls=[{"service": "secretsmanager", "operation": "GetSecretValue", "status": "error"}])) is None
    assert module._mcp_verified_secret(fixture(return_value={"username": "fixture"})) is None
    text_result = {"result": {"isError": False, "content": [{"type": "text", "text": json.dumps(fixture()["result"]["structuredContent"])}]}}
    assert module._mcp_verified_secret(text_result) == "fixture-only-not-a-secret"
    module._mcp_secret_cache.clear()
    polled = []
    def asynchronous_post(payload, session_id=None):
        if payload["method"] in ("initialize", "notifications/initialized"):
            return {"result": {}}, "fixture-session"
        name = payload["params"]["name"]
        polled.append(name)
        if name == "aws___run_script":
            return {"result": {"structuredContent": {"status": "working", "task_id": "fixture-task", "recommended_wait_seconds": 1}}}, None
        assert payload["params"]["arguments"] == {"task_ids": ["fixture-task"], "poll_iteration": 1}
        return fixture(), None
    module._mcp_post = asynchronous_post
    assert module._resolve_via_mcp("fixture", "AWSCURRENT", "us-east-1") == "fixture-only-not-a-secret"
    assert polled == ["aws___run_script", "aws___get_tasks"]
    module._mcp_secret_cache.clear()
    def substituted_post(payload, session_id=None):
        if payload["method"] in ("initialize", "notifications/initialized"):
            return {"result": {}}, "fixture-session"
        return fixture(json.dumps({"password": "{{resolve:secretsmanager:must-not-be-rescanned}}"})), None
    module._mcp_post = substituted_post
    assert module.resolve_string(prefix + "password:AWSCURRENT}}") == "{{resolve:secretsmanager:must-not-be-rescanned}}"
    module._mcp_secret_cache.clear()
    module._mcp_post = lambda *args, **kwargs: (None, None)
    assert module._resolve_via_mcp("fixture", "AWSCURRENT", "us-east-1") is None
    assert module.MCP_LAST_ERROR == {"class": "protocol", "code": "initialize_failed"}
    module._mcp_post = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("fixture-only error must never be echoed"))
    assert module._resolve_via_mcp("fixture", "AWSCURRENT", "us-east-1") is None
    assert module.MCP_LAST_ERROR["code"] == "resolution_failed"
    root = Path(__file__).parent.parent
    original = ast.parse((Path(__file__).parent / "asm-exec.original").read_text(encoding="utf-8"))
    compat = ast.parse((Path(__file__).parent / "asm-exec-compat").read_text(encoding="utf-8"))
    originals = {node.name: ast.dump(node) for node in original.body if isinstance(node, ast.FunctionDef)}
    edited = {node.name: ast.dump(node) for node in compat.body if isinstance(node, ast.FunctionDef)}
    preserved = ["_get_aws_credentials", "_signing_service_region", "_sign_v4", "_check_sma", "resolve_one", "resolve_string", "main"]
    assert all(originals[name] == edited[name] for name in preserved)
    print(json.dumps({"success": True, "real_secret_resolution_performed": False,
        "checks": ["single_provider_call_for_two_fields", "memory_only_cache", "no_console_secret_acceptance",
                   "cache_separates_version_and_region", "required_successful_exact_api_call", "structured_and_text_results",
                   "working_task_poll", "single_pass_no_rescan", "sanitized_failure",
                   "official_signing_credentials_sma_dynamicrefs_main_preserved"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
