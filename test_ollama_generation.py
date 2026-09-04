import httpx

print("PYTHON SCRIPT STARTED")

payload = {
    "model": "hermes3:latest",
    "prompt": "Respond with exactly: HERMES_PYTHON_OK",
    "stream": False
}

print("SENDING REQUEST TO HERMES...")

response = httpx.post(
    "http://localhost:11434/api/generate",
    json=payload,
    timeout=120
)

print("RESPONSE RECEIVED")
print("Status:", response.status_code)

data = response.json()

print("HERMES RESPONSE:")
print(data.get("response"))