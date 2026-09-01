import ollama

response = ollama.chat(
    model="qwen3:8b",
    messages=[
        {
            "role": "user",
            "content": "Explain threat hunting in cybersecurity in 3 simple sentences."
        }
    ]
)

print(response["message"]["content"])