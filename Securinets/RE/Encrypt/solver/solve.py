#!/usr/bin/env python3
"""Solve the exact Encrypt handout. Linux x86-64, GCC, pefile and capstone."""
import argparse,base64,ctypes as C,hashlib,lzma,os,platform,struct,subprocess,sys,time,zipfile
from pathlib import Path
import pefile
MASK=(1<<64)-1
class Random:
 def __init__(self,state):self.state=state
 def next(self):
  self.state=(self.state+0x9e3779b97f4a7c13)&MASK
  x=self.state;x=((x^(x>>31))*0xbf58476d1ce4e5bb)&MASK;x=((x^(x>>26))*0x94d049bb133111e9)&MASK
  return x^(x>>33)
def rol(x,k):return((x<<k)|(x>>(64-k)))&MASK
def xoshiro(st):
 a,b,c,d=st;result=rol(b*5&MASK,11)*9&MASK;t=b<<19&MASK;c^=a;d^=b;b^=c;a^=d;c^=t;d=rol(d,43);st[:]=[a,b,c,d];return result
def unpack(archive,build):
 with zipfile.ZipFile(archive) as z:
  exe=z.read(next(i for i in z.namelist() if i.endswith('/encrypt.exe')))
  cipher=z.read(next(i for i in z.namelist() if i.endswith('/cipher.txt'))).decode().strip()
 if hashlib.sha256(exe).hexdigest()!='c8521122fcbdb4e75d465f5f1554e02e2e9141069bbe3d66e1d19b33f9d87fad':raise ValueError('Unrecognized handout')
 pe=pefile.PE(data=exe)
 for typ in pe.DIRECTORY_ENTRY_RESOURCE.entries:
  for item in typ.directory.entries:
   if str(item.name)=='FPACK':
    d=item.directory.entries[0].data.struct;inner=lzma.decompress(pe.get_data(d.OffsetToData,d.Size));(build/'inner.exe').write_bytes(inner)
    print(f'[+] FPACK: {d.Size:,} -> {len(inner):,} bytes')
    return cipher
 raise ValueError('FPACK resource missing')
def decode_outer(cipher):
 alphabet=list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_');r=Random(0x0b5e7a1dc0ffee42)
 for i in range(64,1,-1):
  j=r.next()%i;alphabet[i-1],alphabet[j]=alphabet[j],alphabet[i-1]
 alphabet=''.join(alphabet);d=base64.b64decode(cipher.translate(str.maketrans(alphabet,'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')))
 p=list(range(len(d)));r=Random((len(d)*0xbf58476d1ce4e5bb)^0x2545f4914f6cdd1d)
 for i in range(len(d),1,-1):
  j=r.next()%i;p[i-1],p[j]=p[j],p[i-1]
 return bytes(d[p[i]] for i in range(len(d)))
def header(packet,native):
 master=C.create_string_buffer(32);native.lib.master.argtypes=[C.c_void_p,C.c_uint64];native.lib.master(master,0);k=struct.unpack('<4Q',master.raw)
 tag=int.from_bytes(packet[-4:],'little');bodylen=len(packet)-18;r=Random((((tag<<20)+bodylen)^k[0]^0xd1b54a32d192ed03)&MASK);st=[]
 for i in range(4):
  if i:r.state^=k[i]
  st.append(r.next())
 h=bytes(x^(xoshiro(st)>>56) for x in packet[:14]);sec,orig,clen,salt=struct.unpack('<QHHH',h)
 return sec,orig,clen,salt,tag

def decompress_literal_xpress(data,size):
 """This stream uses literals only; reject back-references instead of guessing."""
 p=0;out=bytearray()
 while len(out)<size:
  if p+4>len(data):raise ValueError('Truncated XPRESS indicator')
  flags=int.from_bytes(data[p:p+4],'little');p+=4
  for bit in range(31,-1,-1):
   if len(out)==size:break
   if flags>>bit&1:raise ValueError('Expected literal-only XPRESS stream')
   if p==len(data):raise ValueError('Truncated XPRESS literal')
   out.append(data[p]);p+=1
 if p!=len(data):raise ValueError('Unconsumed compressed bytes')
 return bytes(out)
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('handout',type=Path);ap.add_argument('--build',type=Path,default=Path('build'));ap.add_argument('--milliseconds',type=int,help='Try a single candidate; default: 0..999');args=ap.parse_args()
 if platform.system()!='Linux' or platform.machine() not in ['x86_64','AMD64']:raise SystemExit('Use Linux x86-64, e.g. an Ubuntu/Kali VM or WSL2 x86-64.')
 build=args.build.resolve();build.mkdir(parents=True,exist_ok=True);cipher=unpack(args.handout,build);root=Path(__file__).resolve().parent
 subprocess.run(['gcc','-O2','-shared','-fPIC',str(root/'native.c'),'-o',str(build/'native.so')],check=True)
 os.environ['ENCRYPT_BUILD']=str(build)
 import native_runner as n
 import inverses as inv
 packet=decode_outer(cipher);sec,L,clen,salt,tag=header(packet,n)
 print(f'[+] Header: timestamp={sec}, original={L}, compressed={clen}, salt={salt}, tag=0x{tag:08x}')
 if (L,clen,len(packet))!=(78,90,114):raise ValueError('Unexpected packet profile')
 n.TIMESTAMP=sec;n.ORIGINAL_LEN=L;n.SALT=salt;C.c_int.in_dll(n.lib,'CLEN').value=clen
 trials=[args.milliseconds] if args.milliseconds is not None else range(1000);start=time.monotonic()
 for ms in trials:
  n.run(ms);decoded=inv.solve(packet[14:-4]);snap=n.NSnap(0x140010798);padding=snap.mem(snap.r('r14'),96)[clen:]
  if decoded[clen:]!=padding:continue
  try:secret=decompress_literal_xpress(decoded[:clen],L)
  except ValueError:continue
  if not(secret.startswith(b'Securinets{') and secret.endswith(b'}')):continue
  C.c_int.in_dll(n.lib,'CUSTOM').value=1;buf=(C.c_ubyte*65536).in_dll(n.lib,'COMPRESSED');buf[:clen]=decoded[:clen]
  regenerated=n.run(ms,secret)
  if regenerated!=cipher.encode():raise AssertionError('Re-encryption mismatch')
  (build/'packet.bin').write_bytes(packet);(build/'recovered_xpress.bin').write_bytes(decoded[:clen]);(build/'flag.txt').write_bytes(secret+b'\n');(build/'reencrypted.txt').write_bytes(regenerated)
  print(f'[+] Milliseconds: {ms}');print(f'[+] XPRESS: {clen} -> {L} bytes');print('[+] Secret:',secret.decode());print('[+] Ciphertext match: True (152/152 characters)');print(f'[+] Search + verification: {time.monotonic()-start:.2f}s');return
 raise SystemExit('No verified candidate')
if __name__=='__main__':main()
