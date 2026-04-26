import os
import json
from openai import OpenAI

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "You are a test. Return JSON."},
        {"role": "user", "content": "Hello. Return {}"}
    ],
    response_format={"type": "json_object"}
)
print("Response content:", repr(response.choices[0].message.content))
if response.choices[0].message.refusal:
    print("Refusal:", response.choices[0].message.refusal)
