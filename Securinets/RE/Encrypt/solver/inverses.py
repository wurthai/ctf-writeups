"""Inverse transformations for the analyzed Encrypt binary."""
import struct
from capstone import *
import native_runner as n
Snap=n.NSnap
mask=(1<<64)-1
def rol(x,n,w=64):
 n%=w;return ((x<<n)|(x>>(w-n)))&((1<<w)-1)

def xo(st):
 a,b,c,d=st;v=rol(b*5&mask,11)*9&mask;t=b<<19&mask;c^=a;d^=b;b^=c;a^=d;c^=t;d=rol(d,43);st[:]=[a,b,c,d];return v

def inv_tail(data):
 s=Snap(0x1400136cf);N=len(data);d=bytearray(data)
 for i in range(N-1):d[i]=(d[i]-d[i+1])&255
 sb=s.stack[0xb50:0xc50]
 for i in range(N-1,0,-1):d[i]^=sb[d[i-1]]
 stream=s.mem(s.r('r8'),N);prev=n.ORIGINAL_LEN^0xa7
 for i,y in enumerate(d):
  d[i]=((y^rol(prev,3,8))-stream[i])&255;prev=y
 return bytes(d)

def tf(x,a,b,nb):return (x+((a|(x*x))^(2*x*b)))&((1<<nb)-1)

def tf_inv(y,a,b,nb):
 x=0
 for i in range(nb):
  if ((tf(x,a,b,nb)^y)>>i)&1:x|=1<<i
 assert tf(x,a,b,nb)==y
 return x

def jit_ops():
 ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(n.jitbytes,0));chunks=[]
 for i in ins:
  if i.mnemonic=='movabs' and i.op_str.startswith('r8, '):chunks.append([int(i.op_str.split(', ')[1],16),[]])
  elif chunks:chunks[-1][1].append((i.mnemonic,i.op_str))
 ops=[]
 for k,seq in chunks:
  ss=set(seq)
  if ('imul','rax, r8') in ss:typ='mul'
  elif ('xor','rax, r8') in ss:typ='xor'
  elif ('add','rax, r8') in ss:typ='add'
  elif ('sub','rax, r8') in ss:typ='bswap_sub'
  elif ('rol','rax, cl') in ss:typ='rol'
  elif ('shl','r9, cl') in ss:typ='xshl'
  elif ('shr','r9, cl') in ss:typ='xshr'
  else:raise ValueError(seq)
  ops.append((typ,k))
 return ops

def jit_inv(y,t,ops):
 for op,k in reversed(ops):
  c=k^t
  if op=='mul':y=y*pow(c|1,-1,1<<64)&mask
  elif op=='xor':y^=c
  elif op=='add':y=(y-c)&mask
  elif op=='bswap_sub':y=int.from_bytes(((y+c)&mask).to_bytes(8,'little'),'big')
  elif op=='rol':y=rol(y,-(c%63+1))
  else:
   n=c%31+1;z=y
   for sh in range(n,64,n):z^=(y<<sh)&mask if op=='xshl' else y>>sh
   y=z
 return y

def inv_jit(data):
 s=Snap(0x140014328);prev=s.q(0x60);ops=jit_ops();out=bytearray()
 for i in range(0,len(data),8):
  y=int.from_bytes(data[i:i+8],'little');v=y^rol(prev,17);x=jit_inv(v,(i//8*0x9e3779b97f4a7c13)&mask,ops);out+=x.to_bytes(8,'little');prev=y
 return bytes(out)

def gf(a,b):
 v=0
 while b:
  if b&1:v^=a
  a=((a<<1)^ (0x11d if a&128 else 0))&255;b>>=1
 return v

def invmat(A):
 a=[row[:]+[int(i==j) for j in range(4)] for i,row in enumerate(A)]
 for i in range(4):
  j=next(j for j in range(i,4) if a[j][i]);a[i],a[j]=a[j],a[i]
  v=next(v for v in range(1,256) if gf(a[i][i],v)==1);a[i]=[gf(v,x) for x in a[i]]
  for j in range(4):
   if i!=j:
    v=a[j][i];a[j]=[x^gf(v,y) for x,y in zip(a[j],a[i])]
 return [row[4:] for row in a]

def mix(x,A):
 out=[]
 for k in range(0,16,4):
  for row in A:
   z=0
   for a,b in zip(row,x[k:k+4]):z^=gf(a,b)
   out.append(z)
 return out

def spn_params():
 s=Snap(0x140010c23);sb=list(s.stack[0xb50:0xc50]);inv=[sb.index(i) for i in range(256)];R=s.q(0x180)-1;key=s.mem(s.q(0x188),16*(R+1));iv=[s.q(i)&255 for i in [0x98,0xb0,0xb8,0x88,0x60,0x90,0x40]]+[s.r('r15')&255,s.q(0x38)&255]+[s.r(k)&255 for k in ['rsi','rbx','rbp','rdi','r13','r14','rax']]
 return sb,inv,R,key,iv

def inv_spn(data):
 sb,inv,R,key,iv=spn_params();out=[]
 for k in range(0,len(data),16):
  ct=list(data[k:k+16]);x=ct[:]
  for r in range(R,0,-1):
   x=[a^b for a,b in zip(x,key[r*16:r*16+16])]
   if r<R:x=mix(x,IM)
   z=[0]*16
   for i,j in enumerate(perm):z[j]=inv[x[i]]
   x=z
  pt=[a^b^c for a,b,c in zip(x,key[:16],iv)];out+=pt;iv=[a^b for a,b in zip(ct,pt)]
 return bytes(out)

MAT=[[7,3,2,5],[5,7,3,2],[2,5,7,3],[3,2,5,7]]
IM=invmat(MAT)
perm=[0,5,14,11,4,9,2,15,8,13,6,3,12,1,10,7]
def inv_tf(data):
 nb=len(data)*8;x=int.from_bytes(data,'little');s=Snap(0x140012e2c)
 a=int.from_bytes(s.mem(s.r('r14'),96),'little');b=int.from_bytes(s.mem(s.r('rdi'),96),'little');x=tf_inv(x,a,b,nb)
 s=Snap(0x140012d00);x=rol(x,-s.r('rsi'),nb);a=int.from_bytes(s.mem(s.r('r15'),96),'little');b=int.from_bytes(s.mem(s.r('r12'),96),'little');x=tf_inv(x,a,b,nb)
 return x.to_bytes(96,'little')

def inv_initial(data):
 d=bytearray(data)
 for i,j in reversed(n.swaps):d[i],d[j]=d[j],d[i]
 s=Snap(0x140010798);st=list(struct.unpack('<4Q',s.stack[0x1b0:0x1d0]));sb=s.stack[0xb50:0xc50];iv=[sb.index(i) for i in range(256)]
 for i,y in enumerate(d):d[i]=iv[rol(y,-(n.ORIGINAL_LEN+3*i),8)]^(xo(st)>>56)
 return bytes(d)

def solve(data):
 for f in [inv_tail,inv_tf,inv_jit,inv_spn,inv_initial]:data=f(data)
 return data

