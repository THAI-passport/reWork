---
name: dbug-canary-seeding
description: Design, injection, and lifecycle management of high-entropy synthetic canary data (Gate G2). Seeds mock contacts, SMS OTPs, banking session tokens, cryptocurrency seed phrases, and clipboard strings onto the physical Android test device before malware launch. Proves exfiltration in memory dumps or network captures with zero false positives.
---

# dbug-canary-seeding (Gate G2)

Plant trackable, high-entropy synthetic data ("canary credentials") across core Android data stores so that exfiltration can be immediately identified during runtime observation.

---

## 1. Canary Data Schema (`config/mock_canaries.json`)

All canary strings must possess distinct prefixes and high entropy to eliminate accidental collisions in memory or traffic:

```json
{
  "crypto_wallets": [
    {
      "wallet_type": "bip39_seed_12",
      "canary_token": "CANARY-WALLET-ALPHA",
      "seed_phrase": "witch collapse practice feed shame open despair creek road again ice CANARYWALLETALPHASEED",
      "address": "0xCANARY7F92a39E83c14d9b6FaA472E81001007"
    }
  ],
  "banking_otp": [
    {
      "canary_token": "CANARY-SMS-OTP-9921",
      "sender": "SECURE-BANK",
      "otp_code": "984217",
      "message": "Your one-time authorization code is 984217 for transaction TX-CANARY-883921. Never share this code."
    }
  ],
  "contacts": [
    {
      "name": "Jane Canary",
      "phone": "+15550199213",
      "email": "jane.canary.vault@example.com"
    }
  ],
  "session_credentials": [
    {
      "service": "corporate_banking",
      "username": "admin_canary_user",
      "password": "CanaryPassw0rd!#9921aZ",
      "cookie": "session_id=CANARY_SESS_99281a8c9b20e"
    }
  ],
  "clipboard": [
    {
      "canary_token": "CANARY-CLIPBOARD-ETH",
      "text": "0xCANARYBEEF99217741289412A8174100918239"
    }
  ]
}
```

---

## 2. Canary Seeder Automation (`config/seed_canaries.py`)

Run via ADB from the host workstation:

```python
import json
import subprocess
import sys

def adb_shell(cmd):
    return subprocess.check_output(["adb", "shell", cmd], text=True).strip()

def seed_contacts(contacts):
    print("[*] Seeding Canary Contacts...")
    for c in contacts:
        # Insert raw contact
        raw_id = adb_shell(
            f"content insert --uri content://com.android.contacts/raw_contacts --bind account_type:s:local --bind account_name:s:local"
        ).split("=")[-1]
        # Insert display name
        adb_shell(
            f"content insert --uri content://com.android.contacts/data --bind raw_contact_id:i:{raw_id} --bind mimetype:s:vnd.android.cursor.item/name --bind data1:s:'{c['name']}'"
        )
        # Insert phone number
        adb_shell(
            f"content insert --uri content://com.android.contacts/data --bind raw_contact_id:i:{raw_id} --bind mimetype:s:vnd.android.cursor.item/phone_v2 --bind data1:s:'{c['phone']}' --bind data2:i:2"
        )

def seed_sms(sms_list):
    print("[*] Seeding Canary SMS Messages...")
    for s in sms_list:
        adb_shell(
            f"content insert --uri content://sms/inbox --bind address:s:'{s['sender']}' --bind body:s:'{s['message']}' --bind date:s:$(date +%s%3N) --bind read:i:1"
        )

def seed_clipboard(clip_text):
    print("[*] Seeding Canary Clipboard...")
    # Base64 encode to prevent shell escaping errors
    import base64
    b64 = base64.b64encode(clip_text.encode()).decode()
    adb_shell(f"am broadcast -a clipper.set -e text \"$(echo '{b64}' | base64 -d)\" 2>/dev/null || true")

def clean_canaries():
    print("[*] Cleaning seeded canaries from device...")
    adb_shell("content delete --uri content://com.android.contacts/raw_contacts --where \"account_name='local'\"")
    adb_shell("content delete --uri content://sms --where \"body LIKE '%CANARY%'\"")
    print("[+] Canary cleanup complete.")
```

---

## 3. Verification & Teardown Protocol
1. **Verification Before Run:**
   - Execute query to ensure canaries are accessible:
     `adb shell content query --uri content://sms/inbox --where "body LIKE '%CANARY%'"`
   - Assert that records are returned.
2. **Post-Run Cleanup:**
   - Always run `python3 config/seed_canaries.py --clean` during teardown to avoid contaminating subsequent sessions with stale canaries.
