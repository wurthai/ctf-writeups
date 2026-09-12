# Write Up - SCONES CTF: close enough

## Challenge Information

-   **Name:** close enough
-   **Difficulty:** easy
-   **Category:** Reverse / Misc
-   **Flag prefix:** `SCONES`

## Description

> i tried downloading this top secret data but it got stuck halfway
> through :(

The challenge provides a partial pickle file:

    out.pkl.part

and a Python file:

    ekv.py

------------------------------------------------------------------------

# 1. Analyze the provided Python code

The file `ekv.py` defines an encrypted key-value store.

``` python
class EncryptedKV:
    def __init__(self, secret):
        self.secret = secret
        self.d = {}

    def __getitem__(self, key):
        num: int = (self.d[key] ^ self.secret)
        return num.to_bytes(-(num.bit_length() // -8)).decode()

    def __setitem__(self, key, value):
        self.d[key] = int.from_bytes(value.encode()) ^ self.secret
```

The encryption method is:

    encrypted = int.from_bytes(plaintext.encode()) XOR secret

To recover the plaintext:

    plaintext = (encrypted XOR secret).to_bytes(...).decode()

------------------------------------------------------------------------

# 2. Problem with the pickle file

Trying to load the file directly:

``` python
import pickle

pickle.loads(open("out.pkl.part","rb").read())
```

fails because the download was incomplete:

    _pickle.UnpicklingError: pickle data was truncated

However, the pickle contains useful data before the truncation point.

------------------------------------------------------------------------

# 3. Inspect the pickle structure

Use:

``` bash
python -m pickletools out.pkl.part
```

or:

``` python
import pickletools

data = open("out.pkl.part","rb").read()
pickletools.dis(data)
```

The dump reveals:

-   the secret value
-   encrypted key-value entries

Important entries include:

    the three digits on the back of my credit card
    an album you should listen to
    the flag

------------------------------------------------------------------------

# 4. Recover the plaintext values

The values are integers encrypted using XOR.

Example solver:

``` python
secret = SECRET_VALUE

encrypted_values = [
    VALUE1,
    VALUE2,
    VALUE3
]

for value in encrypted_values:
    num = value ^ secret
    print(num.to_bytes(-(num.bit_length() // -8), "big").decode())
```

The decoded results are:

    067
    Mercurial World
    SCONES{y0u_got_m3_out_of_a_p1ckle}

------------------------------------------------------------------------

# 5. Flag

    SCONES{y0u_got_m3_out_of_a_p1ckle}

------------------------------------------------------------------------

# Lessons Learned

-   A corrupted or incomplete pickle file may still contain valuable
    serialized data.
-   Always inspect raw serialization formats before attempting recovery.
-   XOR encryption is reversible if the key is known.
-   Partial downloads can still leak information.
