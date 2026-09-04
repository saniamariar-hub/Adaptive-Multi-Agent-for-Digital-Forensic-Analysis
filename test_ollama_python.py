print("PYTHON SCRIPT STARTED")

import httpx

print("HTTPX IMPORTED")

response = httpx.get(
    "http://localhost:11434/api/tags",
    timeout=10
)

print("OLLAMA RESPONSE:")
print("Status:", response.status_code)
print(response.text)