from pydantic import BaseModel
from ghost_pii import PII, unmask_pii

class User(BaseModel):
    name: PII[str]
    email: PII[str]

user = User(name="John Doe", email="john@example.com")

print(f"--- Default Print ---")
print(user)

print(f"\n--- Model Dump ---")
print(user.model_dump())

with unmask_pii():
    print(f"\n--- Unmasked Print ---")
    print(user)
