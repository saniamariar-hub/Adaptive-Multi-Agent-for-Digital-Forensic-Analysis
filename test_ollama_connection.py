"""Ollama Server & Model Connectivity Smoke Test.

Contacts the real local Ollama server to verify reachability and executes
a minimal prompt with the configured local model (hermes3:latest).
"""

import sys
from configs.config import config
from llm.ollama_client import OllamaClient


def main():
    print("=" * 70)
    print(" OLLAMA SERVER & MODEL CONNECTIVITY TEST")
    print("=" * 70)

    client = OllamaClient()

    print(f"[*] Target Ollama Base URL : {client.base_url}")
    print(f"[*] Target LLM Model       : {client.model_name}")
    print(f"[*] Configured Temperature : {client.temperature}")
    print(f"[*] Request Timeout        : {client.timeout_seconds}s")
    print("\n[1] Checking Ollama server health and model availability...")

    is_healthy, health_msg = client.health_check()
    if not is_healthy:
        print(f"\n[!] HEALTH CHECK FAILED:\n    {health_msg}")
        print("\nDiagnostic Checklist:")
        print("  1. Verify Ollama is running (open terminal and run 'ollama serve' or start Ollama app).")
        print(f"  2. Verify model is pulled (run 'ollama list' to check for '{client.model_name}').")
        print(f"  3. Verify port 11434 is accessible at {client.base_url}.")
        sys.exit(1)

    print(f"[+] {health_msg}")

    print("\n[2] Sending minimal smoke-test prompt to model...")
    system_prompt = "You are a forensic AI assistant. Follow the user's instructions exactly."
    user_prompt = "Respond with exactly: OLLAMA_FORENSICS_OK"

    response = client.generate(
        prompt=user_prompt,
        system_prompt=system_prompt,
        temperature=0.0,
    )

    print("=" * 70)
    print(" SMOKE TEST RESULTS")
    print("=" * 70)
    print(f"Ollama URL : {client.base_url}")
    print(f"Model      : {response.model}")
    print(f"Latency    : {response.latency_seconds:.3f} seconds")
    print(f"Success    : {response.success}")

    if response.success:
        print(f"Response   : {response.text.strip()}")
        print("\n[+] SUCCESS: Local Ollama server and hermes3:latest are fully operational.")
    else:
        print(f"Error      : {response.error_message}")
        print("\n[!] FAILURE: Generation failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
