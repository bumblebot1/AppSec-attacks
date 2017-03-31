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

  m = target_out.readline()
  x = [int(m[i:i+2], 16) for i in range(0, len(m) -1, 2)]
  return int(m, 16), x

def StepOne(x, x_faulty):
  for i in range(16):
    for k in range(256):
      d_i = SubBytesInverse[x[i] ^ k] ^ SubBytesInverse[x_faulty[i] ^ k]

m = random.getrandbits(128)

c, x = Interact("", m)
c_faulty ,x_faulty= Interact("8,1,0,0,0", m)

print("%X\n" % c)
print("%X\n" % c_faulty)
print(MultiplicationTables["2"])