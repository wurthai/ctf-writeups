from pathlib import Path
import struct,hashlib
CODE=Path(__file__).with_name('bytecode.bin').read_bytes()
def run(inp,start=0,stack=None,stop=None):
 c=bytearray(CODE);s=[] if stack is None else stack[:];pc=start;ix=0;out=[];eq=[]
 def push(x):s.append(x&0xffffffff)
 while pc<len(c):
  at=pc;op=c[pc];pc+=1
  if stop is not None and at==stop:return s,eq,out
  if op in (0xa7,0x58,0xa2,0xc3):
   v=struct.unpack_from('<I',c,pc)[0];pc+=4
   if op==0xa7:push(v)
   elif op==0xc3:pc=v
   else:
    x=s.pop()
    if (op==0x58 and x==0) or (op==0xa2 and x!=0):pc=v
  elif op==0:break
  elif op==0x55:pass
  elif op==0xe1:push(inp[ix] if ix<len(inp) else 0);ix+=1
  elif op==0x7a:push(s[-1])
  elif op==0x3e:s.pop()
  elif op==0x2f:out.append(chr(s.pop()&255))
  elif op==0x9a:
   b=s.pop();a=s.pop();push(sum(inp[a:b]))
  elif op==0xd7:
   h=hashlib.sha256(struct.pack('<I',s.pop())).digest();s.extend(h[::-1])
  elif op==0x4e:
   n=s.pop();push(sum(s.pop() for _ in range(n)))
  elif op==0x19:
   k=s.pop()&255
  elif op in (0xf2,0x1b,0x94,0xe3,0x8c,0xb3,0xd4,0x6d):
   b=s.pop();a=s.pop()
   if op==0xf2:push(a+b)
   elif op==0x1b:push(a-b)
   elif op==0x94:push(a^b)
   elif op==0xe3:push(a&b)
   elif op==0x8c:push(a|b)
   elif op==0xb3:push(a<<b if b<32 else 0)
   elif op==0xd4:push(a*b)
   elif op==0x6d:eq.append((at,a,b));push(int(a==b))
  else:raise Exception((hex(at),hex(op),s[-10:]))
 return s,eq,''.join(out)
if __name__=='__main__':
 s,e,o=run(b'Securinets{'+b'A'*44+b'}');print(o);print('stack',s);print('equals',len(e));print(e[:15]);print(e[-5:])
