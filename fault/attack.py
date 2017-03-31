#!/usr/bin/python
import random, sys, subprocess, os, Crypto.Cipher.AES as AES
from aes_params import SubBytes, SubBytesInverse, Rcon
from galois_multiples import MultiplicationTables

target = subprocess.Popen(args   = os.path.realpath(sys.argv[1]),
                          stdout = subprocess.PIPE,
                          stdin  = subprocess.PIPE)

target_out = target.stdout
target_in  = target.stdin

def Interact(fault, message):
  target_in.write(fault + "\n")
  target_in.write("%X\n" % message)
  target_in.flush()

  c = target_out.readline()
  x = [int(c[i:i+2], 16) for i in range(0, len(c) - 1, 2)]
  return int(c, 16), x

def StepOne(x, x_faulty):
  equations = [[[] for a in range(256)] for b in range(16)]
  for i in range(16):
    if i in [0, 2, 9, 11]:
      ind = "2"
    elif i in [5, 7, 12, 14]:
      ind = "3"
    else:
      ind = "1"
    ### find all k in 0 -> 256 such that the equations hold
    for k in range(256):
      d_i = SubBytesInverse[x[i] ^ k] ^ SubBytesInverse[x_faulty[i] ^ k]
      for cnt, d in enumerate(MultiplicationTables[ind]):
        if d_i == d:
          equations[i][cnt].append(k)

m = random.getrandbits(128)

c, x = Interact("", m)
c_faulty ,x_faulty= Interact("8,1,0,0,0", m)

print("%X\n" % c)
print("%X\n" % c_faulty)
print(MultiplicationTables["2"])