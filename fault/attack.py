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

def InvertKey(k):
  r = []
  for i in range(15, 4, -1):
    r.append(k[i] ^ k[i - 4])
  r.append(SubBytes[r[12]] ^ k[3])
  r.append(SubBytes[r[15]] ^ k[2])
  r.append(SubBytes[r[14]] ^ k[1])
  r.append(SubBytes[r[13]] ^ k[0] ^ Rcon[10])
  return r[::-1]

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

key = []
for byte10, byte13, byte0, byte7 in ((a,b,c,d) for index, a in enumerate(k10) for b in k13[index] for c in k0[index] for d in k7[index]):
  for byte1, byte4, byte11, byte14 in ((a,b,c,d) for index, a in enumerate(k1) for b in k4[index] for c in k11[index] for d in k14[index]):
    for byte8, byte15, byte2, byte5 in ((a,b,c,d) for index, a in enumerate(k8) for b in k15[index] for c in k2[index] for d in k5[index]):
      for byte3, byte6, byte9, byte12 in ((a,b,c,d) for index, a in enumerate(k3) for b in k6[index] for c in k9[index] for d in k12[index]):
        key.append([byte0, byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8, byte9, byte10, byte11, byte12, byte13, byte14, byte15])
print key