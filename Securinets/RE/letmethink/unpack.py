"""Unpack the original ELF statically; optionally prepare Linux analysis copies."""
import argparse,struct,hashlib
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('binary');ap.add_argument('--compat',action='store_true');a=ap.parse_args()
p=Path(a.binary).read_bytes()
end=struct.unpack_from('<Q',p,0x28)[0]+struct.unpack_from('<H',p,0x3a)[0]*struct.unpack_from('<H',p,0x3c)[0]
s=list(range(256));key=b'letmethink';j=0
for i in range(256):
 j=(j+s[i]+key[i%len(key)])&255;s[i],s[j]=s[j],s[i]
out=bytearray(p[end:]);i=j=0
for k in range(len(out)):
 i=(i+1)&255;j=(j+s[i])&255;s[i],s[j]=s[j],s[i];out[k]^=s[(s[i]+s[j])&255]
assert out[:4]==b'\x7fELF'
d=Path('analysis');d.mkdir(exist_ok=True);(d/'layer1').write_bytes(out)
print('RC4 payload offset:',hex(end));print('ELF SHA256:',hashlib.sha256(out).hexdigest())
if a.compat:
 # Redirect sinh/cosh version requirements to their existing GLIBC_2.2.5 versions.
 for n in range(82):
  if struct.unpack_from('<H',out,0xf76+2*n)[0]==7:struct.pack_into('<H',out,0xf76+2*n,3)
 out[0x1030:0x1034]=out[0x1050:0x1054];out[0x1038:0x103c]=out[0x1058:0x105c]
 (d/'runnable').write_bytes(out);(d/'runnable').chmod(0o755)
 # Instrumented copy only: anti-debug routine returns false.
 out[0xf7d3e0:0xf7d3e3]=b'\x31\xc0\xc3'
 (d/'debug').write_bytes(out);(d/'debug').chmod(0o755)
