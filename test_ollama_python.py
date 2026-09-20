import httpx

url = "http://localhost:11434/api/generate"

payload = {
    "model": "hermes3:latest",
    "prompt": "Respond with exactly: PYTHON_OLLAMA_OK",
    "stream": False
}

print("Sending request to Ollama...")

try:
    response = httpx.post(
        url,
        json=payload,
        timeout=60.0
    )

    print("HTTP status:", response.status_code)
    print("Raw response:")
    print(response.text)

except Exception as e:
    print("ERROR:", repr(e))