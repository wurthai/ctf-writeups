# Ghost in the Timeline — H7CTF 2026 Write-up

> **Category:** Static Forensics  
> **Difficulty:** Medium  
> **Points:** 63  
> **Artifact:** `case_disk.img`  
> **Filesystem:** EXT4  
> **Flag:** `H7CTF{e211b7db9d4f5c9f0812}`

---

## 1. Challenge description

> An engineer stands accused of walking off with the product roadmap, and the alibi is tidy: the file predates their access, nothing was staged, nothing deleted, and every timestamp agrees.
>
> Timestamps are only as honest as whoever set them.

The wording strongly hints at **timestamp manipulation / timestomping**. The goal is therefore not simply to search for a visible flag, but to reconstruct what happened on the EXT4 filesystem and determine whether apparently trustworthy timestamps were forged.

The two main questions are:

1. Was the product roadmap really created/modified before the engineer had access?
2. Was anything staged and later deleted despite the apparently clean directory?

---

## 2. Tools used

The intended solution can be completed with standard Linux forensic utilities:

```bash
sudo apt update
sudo apt install sleuthkit unzip file binutils
```

Important Sleuth Kit commands:

| Tool | Purpose |
|---|---|
| `fls` | Enumerate files/directories, including deleted directory entries |
| `istat` | Inspect inode metadata and EXT4 timestamps |
| `icat` | Extract a file directly from an inode |
| `file` | Identify the image/filesystem |
| `strings` | Quick triage of readable strings in raw data |
| `unzip` | Inspect and extract the recovered archive |

> **Note:** `case_disk.img` is already a raw EXT4 filesystem image, not a full disk image containing a partition table. Therefore no partition offset (`-o`) is required for Sleuth Kit commands.

---

## 3. Preserve and identify the evidence

Before touching the evidence, calculate a hash so that the image can be identified later.

```bash
sha256sum case_disk.img
```

Result:

```text
dcf90af47d9400173cabd230331aba326af646aea4f9eb7d79242f62fe0af4d4  case_disk.img
```

Now identify the image:

```bash
file case_disk.img
```

Result:

```text
case_disk.img: Linux rev 1.0 ext4 filesystem data,
UUID=1703f65b-7ae7-49fc-a4dc-75da999317b3,
volume name "CASE-2026-0917" (extents) (64bit) (large files) (huge files)
```

![Initial filesystem triage](assets/01_identify_image.png)

So the artifact is a directly mountable/analyzable **EXT4 filesystem**.

---

## 4. Quick filesystem enumeration

List the filesystem recursively:

```bash
fls -r -p case_disk.img
```

The interesting live paths are:

```text
/home/jdoe/designs/notes.txt
/home/jdoe/designs/roadmap.pdf
/home/jdoe/.cache/staging/
/var/log/auth.log
```

At first glance this supports the suspect's story:

- `roadmap.pdf` exists normally.
- `.cache/staging/` appears empty.
- Nothing obvious looks like an exfiltration archive.

But the challenge description explicitly tells us not to trust the timestamps.

---

## 5. Inspect `roadmap.pdf`

From the filesystem metadata, `roadmap.pdf` is **inode 21**.

Inspect it:

```bash
istat case_disk.img 21
```

The important timestamp values are:

```text
Inode: 21
File: /home/jdoe/designs/roadmap.pdf
Size: 51 bytes

Accessed:  2026-06-01 08:30:00 UTC
Modified:  2026-06-01 08:30:00 UTC
Changed:   2026-09-25 20:22:32 UTC
Created:   2026-09-25 20:22:32 UTC
```

![roadmap.pdf timestamp mismatch](assets/02_timestomp_metadata.png)

### 5.1 Why this is suspicious

EXT4 exposes several different timestamps:

| Timestamp | Meaning |
|---|---|
| `atime` | Last access time |
| `mtime` | Last content modification time |
| `ctime` | Last inode/metadata change time |
| `crtime` / birth time | Inode creation time |
| `dtime` | Deletion time, if deleted |

The supposedly old roadmap has:

```text
atime = 2026-06-01
mtime = 2026-06-01

ctime = 2026-09-25
crtime = 2026-09-25
```

That is the central anomaly.

The file presents itself as having been accessed and modified on **June 1**, but the inode itself was created and changed on **September 25**.

A common timestomping technique is to backdate `mtime` and `atime`, for example with a command conceptually similar to:

```bash
touch -a -m -d '2026-06-01 08:30:00' roadmap.pdf
```

Changing those timestamps updates the inode's `ctime`, which is exactly why `ctime` can expose a backdating attempt.

So the visible date on `roadmap.pdf` cannot be accepted at face value.

> A newer creation/change time than the advertised `mtime` is strong evidence that the “old” modification timestamp was preserved or deliberately manipulated. In the context of this challenge, it is the intended timestomping indicator.

---

## 6. Check system logs

The filesystem also contains:

```text
/var/log/auth.log
```

The log contains the following entry:

```text
Sep 17 02:11:04 ws-jdoe sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/usr/bin/zip
```

A quick raw-image triage also exposes it:

```bash
strings -a case_disk.img | grep 'COMMAND=/usr/bin/zip'
```

Result:

```text
Sep 17 02:11:04 ws-jdoe sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/usr/bin/zip
```

This matters because the suspect supposedly staged nothing, yet `jdoe` invoked `/usr/bin/zip` under `sudo`.

That gives us a new hypothesis:

> A ZIP archive may have been created as a staging bundle and then deleted.

---

## 7. Search for deleted entries

Sleuth Kit can show deleted directory entries:

```bash
fls -r -p -d case_disk.img
```

Inside:

```text
/home/jdoe/.cache/staging/
```

we recover a deleted directory entry pointing to:

```text
q3_designs.zip
```

with **inode 23**.

This is particularly important because the live directory looks empty. The filename survives in **directory slack / stale directory-entry data**, even though the file has been unlinked.

### What is directory slack?

EXT4 directories are structured records. When a file is deleted, the filesystem does not necessarily wipe every byte of the old directory entry immediately. The active entry may expand over the deleted record, while the old filename remains in unused/slack bytes until overwritten.

That is why a forensic parser can still discover:

```text
q3_designs.zip
```

even though an ordinary directory listing would show nothing.

---

## 8. Inspect deleted inode 23

Inspect the recovered inode:

```bash
istat case_disk.img 23
```

Relevant metadata:

```text
Inode: 23
Size: 3477 bytes
Links: 0

Accessed:     2026-09-25 20:22:32 UTC
Modified:     2026-09-25 20:22:32 UTC
Changed:      2026-09-25 20:22:32 UTC
Created:      2026-09-25 20:22:32 UTC
Deleted Time: 2026-09-25 20:22:32 UTC

Data blocks:
1502 1503 1504 1505
```

![Deleted q3_designs.zip inode](assets/03_deleted_zip.png)

Two values prove that this is a deleted file:

```text
Links: 0
Deleted Time (dtime): 2026-09-25 20:22:32 UTC
```

However, deletion only removed the filesystem reference. The data blocks had **not yet been overwritten**.

The first bytes of the inode data are:

```text
50 4b 03 04
```

or:

```text
PK\x03\x04
```

This is the classic ZIP local-file-header signature.

So inode 23 is definitely the deleted staging ZIP archive.

---

## 9. Recover the deleted ZIP

Use `icat` to extract inode 23 directly:

```bash
icat -r case_disk.img 23 > q3_designs.zip
```

If your Sleuth Kit version recovers it without `-r`, this also works:

```bash
icat case_disk.img 23 > q3_designs.zip
```

Verify it:

```bash
file q3_designs.zip
unzip -t q3_designs.zip
sha256sum q3_designs.zip
```

Recovered archive SHA-256:

```text
cded6d169063da103915313eff71c204cfbc8ef7ba8afa9aa43e4d48ca4bbf33  q3_designs.zip
```

List its contents:

```bash
unzip -l q3_designs.zip
```

Result:

```text
Archive:  q3_designs.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     9240  2026-09-25 20:22   secret.txt
---------                     -------
     9240                     1 file
```

The archive contains one interesting file:

```text
secret.txt
```

---

## 10. Inspect `secret.txt`

Extract it to stdout:

```bash
unzip -p q3_designs.zip secret.txt
```

The beginning reveals an exfiltration/staging manifest:

```text
EXFIL MANIFEST :: Q3 product designs staging bundle
asset_1 designs/roadmap_part_1.pdf sha256=b05cec29f5611c5e4c9a979dcc131c1f
asset_2 designs/roadmap_part_2.pdf sha256=45ffe9c11a74f1a92d44e379acbcda3a
asset_3 designs/roadmap_part_3.pdf sha256=4182c3fb607c66c29b68be5e2e3c0915
...
```

So the deleted archive is not random cache data. It is explicitly described as a **Q3 product designs staging bundle**.

To locate the flag directly:

```bash
unzip -p q3_designs.zip secret.txt | grep -o 'H7CTF{[^}]*}'
```

Result:

```text
H7CTF{e211b7db9d4f5c9f0812}
```

![Recover the flag](assets/04_recover_flag.png)

---

## 11. Complete forensic chain

![Forensic chain](assets/05_forensic_flow.png)

The evidence chain is:

```text
roadmap.pdf appears old
        ↓
inspect inode 21
        ↓
mtime/atime = June 1
ctime/crtime = September 25
        ↓
timestamp mismatch → timestomping/backdating
        ↓
auth.log shows jdoe running /usr/bin/zip
        ↓
.cache/staging appears empty
        ↓
deleted directory slack exposes q3_designs.zip
        ↓
inode 23: links=0 + dtime set
        ↓
data blocks still intact
        ↓
icat recovers q3_designs.zip
        ↓
secret.txt = EXFIL MANIFEST
        ↓
FLAG
```

---

## 12. Why the alibi fails

The challenge description makes three implied claims:

### Claim 1 — “The roadmap predates their access.”

The visible `mtime`/`atime` says June 1, but the inode's `ctime` and creation time are September 25.

Therefore the visible old date cannot be trusted as evidence that the file existed in that state since June.

### Claim 2 — “Nothing was staged.”

`auth.log` records `jdoe` invoking `/usr/bin/zip`, and the deleted `q3_designs.zip` is recoverable from `.cache/staging`.

So data **was staged**.

### Claim 3 — “Nothing was deleted.”

Inode 23 has:

```text
Links: 0
Deleted Time: 2026-09-25 20:22:32 UTC
```

and its filename remains in directory slack.

So a staging archive **was deleted**.

---

## 13. Minimal solve path

If solving under time pressure, the entire challenge can be reduced to these commands:

```bash
# 1. Identify filesystem
file case_disk.img

# 2. Enumerate files
fls -r -p case_disk.img

# 3. Inspect suspicious roadmap inode
istat case_disk.img 21

# 4. Look specifically for deleted entries
fls -r -p -d case_disk.img

# 5. Inspect deleted ZIP inode
istat case_disk.img 23

# 6. Recover it
icat -r case_disk.img 23 > q3_designs.zip

# 7. List archive
unzip -l q3_designs.zip

# 8. Extract flag
unzip -p q3_designs.zip secret.txt | grep -o 'H7CTF{[^}]*}'
```

Output:

```text
H7CTF{e211b7db9d4f5c9f0812}
```

---

## 14. Optional raw-image triage

If Sleuth Kit is not yet installed, `strings` is useful for forming a hypothesis:

```bash
strings -a -n 4 case_disk.img | \
grep -E 'roadmap\.pdf|q3_designs\.zip|secret\.txt|COMMAND=/usr/bin/zip'
```

Interesting hits include:

```text
roadmap.pdf
q3_designs.zip
Sep 17 02:11:04 ws-jdoe sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/usr/bin/zip
secret.txt
```

However, `strings` alone is not a proper forensic explanation. It does not prove the inode relationships, deletion status, or timestamp mismatch. The stronger solution is to correlate directory entries and inode metadata with `fls`, `istat`, and `icat`.

---

## 15. Key forensic lessons

### 15.1 Never trust only `mtime`

Attackers can easily modify access and modification timestamps. On EXT4, compare them with `ctime` and birth/creation time whenever available.

### 15.2 Deletion does not equal destruction

Deleting a file usually removes references to it. Until the relevant blocks are reused, the content may still be recoverable.

### 15.3 Directory slack matters

Even when a directory appears empty, deleted names can survive in stale directory-record space.

### 15.4 Correlate multiple evidence sources

The strongest conclusion comes from combining:

- suspicious inode timestamps,
- authentication logs,
- deleted directory entries,
- inode deletion metadata,
- intact data blocks,
- contents of the recovered archive.

No single clue tells the whole story; together they reconstruct the event.

---

# Final flag

```text
H7CTF{e211b7db9d4f5c9f0812}
```

---

## Appendix — Verified artifact hashes

```text
case_disk.img
SHA256: dcf90af47d9400173cabd230331aba326af646aea4f9eb7d79242f62fe0af4d4

q3_designs.zip
SHA256: cded6d169063da103915313eff71c204cfbc8ef7ba8afa9aa43e4d48ca4bbf33

secret.txt
SHA256: 6d6937f2115c3d9b1391d21ba28bf98cbc40353552b1497c428921d40549e455
```
