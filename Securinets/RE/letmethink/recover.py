from vm import run
inp=bytearray(b'Securinets{'+b'A'*44+b'}')
_,eq,_=run(inp)
checks=eq[-57:-1]
print('checks',len(checks),[(hex(p),a,b) for p,a,b in checks[:3]])
start=0x82f
for i,(pc,_,_) in enumerate(checks):
 good=[]
 for v in range(32,127):
  inp[i]=v
  s,_,_=run(inp,start=start,stack=[],stop=pc)
  if s[-2]==s[-1]:good.append(v)
 # The first 11 bytes also define the common mask, so retain the verified event prefix.
 if i<11:
  inp[i]=b'Securinets{'[i]
  print(i,repr(chr(inp[i])), 'candidates', ''.join(map(chr,good)))
 else:
  print(i,repr(''.join(map(chr,good))),flush=True)
  if len(good)!=1:raise ValueError((i,good))
  inp[i]=good[0]
 start=pc+2
print(inp.decode());print(run(inp)[2])
