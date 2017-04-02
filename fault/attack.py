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

def StepOne(x, x_faulty, index0, index1, index2, index3):
  equations = [[[] for a in range(256)] for b in range(16)]
  k_0, k_1, k_2, k_3 = [], [], [], []
  for i in range(256):
    k_0_byte = i
    delta = SubBytesInverse[x[index0] ^ k_0_byte] ^ SubBytesInverse[x_faulty[index0] ^ k_0_byte]

    k_1_hyp, k_2_hyp, k_3_hyp = [], [], []
    for j in range(256):
      if delta == SubBytesInverse[x[index1] ^ j] ^ SubBytesInverse[x_faulty[index1] ^ j]:
        k_1_hyp.append(j)
    if len(k_1_hyp) == 0:
      continue
    
    for j in range(256):
      if MultiplicationTables["2"][delta] == SubBytesInverse[x[index2] ^ j] ^ SubBytesInverse[x_faulty[index2] ^ j]:
        k_2_hyp.append(j)
    if len(k_2_hyp) == 0:
      continue

    for j in range(256):
      if MultiplicationTables["3"][delta] == SubBytesInverse[x[index3] ^ j] ^ SubBytesInverse[x_faulty[index3] ^ j]:
        k_3_hyp.append(j)
    if len(k_3_hyp) == 0:
      continue
    
    k_0.append(k_0_byte)
    k_1.append(k_1_hyp)
    k_2.append(k_2_hyp)
    k_3.append(k_3_hyp)
  
  return k_0, k_1, k_2, k_3

m = random.getrandbits(128)
c, x = Interact("", m)
c_faulty ,x_faulty= Interact("8,1,0,0,0", m)
k10, k13, k0, k7 = StepOne(x, x_faulty, 10, 13, 0, 7)
k1, k4, k11, k14 = StepOne(x, x_faulty, 1, 4, 11, 14)
k8, k15, k2, k5 = StepOne(x, x_faulty, 8, 15, 2, 5)
k3, k6, k9, k12 = StepOne(x, x_faulty, 3, 6, 9, 12)

print(k0)
print("\n")
print(k1)
print("\n")
print(k2)
print("\n")
print(k3)
print("\n")
print(k4)
print("\n")
print(k5)
print("\n")
print(k6)
print("\n")
print(k7)
print("\n")
print(k8)
print("\n")
print(k9)
print("\n")
print(k10)
print("\n")
print(k11)
print("\n")
print(k12)
print("\n")
print(k13)
print("\n")
print(k14)
print("\n")
print(k15)
print("\n")