import ctypes as C,struct,pefile,json
from capstone import *
from pathlib import Path
import os,hashlib
BUILD=Path(os.environ["ENCRYPT_BUILD"])
ORIGINAL_LEN=78
BODY_LEN=96
TIMESTAMP=1792226999
SALT=32158
LIBC=C.CDLL(None);LIBC.mmap.restype=C.c_void_p;LIBC.mmap.argtypes=[C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long]
base=0x140000000
assert LIBC.mmap(base,0x700000,7,0x100022,-1,0)==base
raw=(BUILD/'inner.exe').read_bytes()
if hashlib.sha256(raw).hexdigest()!='54189d7bb88a5bebdf768453acb9bc91728b68b413d7638a68da13ba67ceeb43':
 raise ValueError('This runner only supports the analyzed Encrypt handout.')
PE=pefile.PE(data=raw);b=PE.get_memory_mapped_image();C.memmove(base,b,len(b));lib=C.CDLL(str((BUILD/'native.so').resolve()))
p64=lambda x:struct.pack('<Q',x)
def addr(f):return C.cast(f,C.c_void_p).value
def patch(a,f):C.memmove(a,b'\xff\x25\x00\x00\x00\x00'+p64(addr(f)),14)
mp={'HeapAlloc':lib.ha,'HeapFree':lib.hf,'HeapReAlloc':lib.hr,'GetProcessHeap':lib.gh,'GetModuleHandleA':lib.gm,'GetProcAddress':lib.gp,'LoadLibraryA':lib.gm,'memcpy':lib.cp,'memmove':lib.cp,'memset':lib.st,'memcmp':lib.cmp,'GetCurrentProcess':lib.gh}
for ent in PE.DIRECTORY_ENTRY_IMPORT:
 for imp in ent.imports:
  name=(imp.name or b'').decode()
  if name in mp:C.memmove(imp.address,p64(addr(mp[name])),8)
patch(0x14000fae0,lib.compress)
regnames=['r15','r14','r13','r12','r11','r10','r9','r8','rdi','rsi','rbp','rbx','rdx','rcx','rax','flags']
profiles={};swaps=[];jitbytes=b''
class NSnap:
 def __init__(self,ad):self.stack,self.regs,self.blocks=profiles[ad]
 def q(self,o):return int.from_bytes(self.stack[o:o+8],'little')
 def r(self,k):return self.regs[k]
 def mem(self,p,n):
  for a,b in self.blocks:
   if a<=p and p+n<=a+len(b):return b[p-a:p-a+n]
  raise ValueError((hex(p),n,[(hex(a),len(b)) for a,b in self.blocks]))
@C.CFUNCTYPE(None,C.c_uint64,C.c_void_p)
def callback(ad,saved):
 global jitbytes
 try:
  rs=dict(zip(regnames,struct.unpack('<16Q',C.string_at(saved,128))));sp=saved+128;stack=C.string_at(sp,0xcb0);blocks=[]
  q=lambda o:int.from_bytes(stack[o:o+8],'little')
  def save(p,n):blocks.append((p,C.string_at(p,n)))
  if ad==0x140010798:save(rs['r14'],96)
  if ad==0x140010c23:save(q(0x188),16*q(0x180))
  if ad==0x1400118b6:save(q(0x100),96)
  if ad==0x140014328:
   jitbytes=C.string_at(rs['rdi'],rs['rbp']);save(q(0x100),96)
  if ad==0x140012d00:
   for r in ['r13','r15','r12']:save(rs[r],96)
  if ad==0x140012e2c:
   for r in ['r15','r14','rdi']:save(rs[r],96)
  if ad==0x1400136cf:
   save(rs['r8'],96);save(rs['r14'],96)
  if ad==0x1400108cf:swaps.append((rs['rsi']-1,rs['rdx']))
  profiles[ad]=(stack,rs,blocks)
 except BaseException as e:print('CALLBACK ERROR',hex(ad),str(e),flush=True);raise
cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True;nexttr=base+0x500000
def hook(ad):
 global nexttr
 tr=nexttr;nexttr+=0x1000;orig=[];n=0
 for i in cs.disasm(C.string_at(ad,64),ad):
  orig.append(i);n+=i.size
  if n>=14:break
 code=bytearray(b'\x9c')
 # push rax rcx rdx rbx rbp rsi rdi r8..r15
 code+=b'\x50\x51\x52\x53\x55\x56\x57'
 for x in range(8):code+=bytes([0x41,0x50+x])
 code+=b'\x48\x81\xec\x00\x01\x00\x00'
 for j in range(16):
  code+= (b'\xf3\x44' if j>=8 else b'\xf3')+b'\x0f\x7f'+bytes([0x84+((j%8)<<3),0x24])+struct.pack('<I',j*16)
 code+=b'\x48\xbf'+p64(ad)+b'\x48\x8d\xb4\x24\x00\x01\x00\x00'
 code+=b'\x48\xb8'+p64(addr(callback))+b'\xff\xd0'
 for j in range(16):code+=(b'\xf3\x44' if j>=8 else b'\xf3')+b'\x0f\x6f'+bytes([0x84+((j%8)<<3),0x24])+struct.pack('<I',j*16)
 code+=b'\x48\x81\xc4\x00\x01\x00\x00'
 for x in reversed(range(8)):code+=bytes([0x41,0x58+x])
 code+=b'\x5f\x5e\x5d\x5b\x5a\x59\x58\x9d'
 for ins in orig:
  ib=bytearray(ins.bytes)
  if ins.disp_size and any(op.type==CS_OP_MEM and op.mem.base==X86_REG_RIP for op in ins.operands):
   disp=ins.address+ins.size+ins.disp-(tr+len(code)+ins.size);ib[ins.disp_offset:ins.disp_offset+ins.disp_size]=int(disp).to_bytes(ins.disp_size,'little',signed=True)
  if ins.mnemonic in ['call','jmp'] and ins.operands[0].type==CS_OP_IMM:
   disp=ins.operands[0].imm-(tr+len(code)+ins.size);ib[ins.imm_offset:ins.imm_offset+ins.imm_size]=int(disp).to_bytes(ins.imm_size,'little',signed=True)
  code+=ib
 code+=b'\xff\x25\x00\x00\x00\x00'+p64(ad+n)
 C.memmove(tr,bytes(code),len(code));C.memmove(ad,b'\xff\x25\x00\x00\x00\x00'+p64(tr),14)
from capstone.x86_const import X86_REG_RIP
for ad in [0x140010798,0x1400108cf,0x140010c23,0x1400118b6,0x140014328,0x140012d00,0x140012e2c,0x1400136cf]:hook(ad)
lib.encrypt.argtypes=[C.c_void_p,C.c_void_p,C.c_uint64,C.c_void_p]
def run(ms,source=None):
 if source is None:source=b'A'*ORIGINAL_LEN
 profiles.clear();swaps.clear();src=C.create_string_buffer(source);out=C.create_string_buffer(24);params=C.create_string_buffer(struct.pack('<QQHH',TIMESTAMP,0,ms,SALT));lib.encrypt(out,src,len(source),params);cap,p,n=struct.unpack('<3Q',out.raw);res=C.string_at(p,n);return res
