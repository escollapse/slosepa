#!/usr/bin/python3
#
# slosepa.py
# SLOw hash SEcure Password Author
# ver 0.31 - 20191122
#   -minor fix to seeds' init's
# ver 0.3 - 20191121
#   random-randomization
#   -unique, randomer seeds to each hash function
#   -randomly bounded seeds' lengths
#   -randomlier randomized selection of digest nibble
#   -triple conversion dict's
#   -random conversion dict selection
#   -randomer final char (to meet user requirement)
#   -(not so random) import optimizations
#
# **************
# * escollapse *
# * CISSP, PT+ *
# *  20191008  *
# **************
#
# usage:
#   1 - specify desired password length
#   2 - specify number of hashing rounds
#   3 - press play
#
# future operations:
#   1 - argument inputs
#   2 - gui
#   3 - browser plugin?

from string import ascii_letters, digits, punctuation
from secrets import choice as ch
from secrets import randbelow as randb
from hashlib import blake2b, sha3_512, sha512

# future args
pwLength = 30
rounds = 500000

# initializations
conversionDict1 = {}
conversionDict2 = {}
conversionDict3 = {}
allChar = ascii_letters + digits + punctuation
allChar1 = list(allChar)
for i in range(len(allChar1)):
    temp = ch(allChar1)
    allChar1.remove(temp)
    conversionDict1[hex(i)] = temp
allChar2 = list(allChar)
for i in range(len(allChar2)):
    temp = ch(allChar2)
    allChar2.remove(temp)
    conversionDict2[hex(i)] = temp
allChar3 = list(allChar)
for i in range(len(allChar3)):
    temp = ch(allChar3)
    allChar3.remove(temp)
    conversionDict3[hex(i)] = temp

# generate seeds to hashing functions
seed1 = ''
for i in range(pwLength * randb(1337) + 1):
    j = randb(3)
    if j == 0:
        seed1 += ch(list(conversionDict1.values()))
    elif j == 1:
        seed1 += ch(list(conversionDict2.values()))
    elif j == 2:
        seed1 += ch(list(conversionDict3.values()))
# uncomment to print
#print("'seed1' = " + seed1)
seed2 = ''
for i in range(pwLength * randb(1337) + 1):
    j = randb(3)
    if j == 0:
        seed2 += ch(list(conversionDict1.values()))
    elif j == 1:
        seed2 += ch(list(conversionDict2.values()))
    elif j == 2:
        seed2 += ch(list(conversionDict3.values()))
# uncomment to print
#print("\n'seed2' = " + seed2)
seed3 = ''
for i in range(pwLength * randb(1337) + 1):
    j = randb(3)
    if j == 0:
        seed3 += ch(list(conversionDict1.values()))
    elif j == 1:
        seed3 += ch(list(conversionDict2.values()))
    elif j == 2:
        seed3 += ch(list(conversionDict3.values()))
# uncomment to print
#print("\n'seed3' = " + seed3)

blaked = blake2b()
sha3d = sha3_512()
sha2d = sha512()

blaked.update(bytearray(seed1, 'utf-8'))
sha3d.update(bytearray(seed2, 'utf-8'))
sha2d.update(bytearray(seed3, 'utf-8'))

for i in range(rounds):
    blaked.update(bytearray(blaked.hexdigest(), 'utf-8'))
    sha3d.update(bytearray(sha3d.hexdigest(), 'utf-8'))
    sha2d.update(bytearray(sha2d.hexdigest(), 'utf-8'))

preprefinal = ''
for i in range(pwLength):
    j = randb(3)
    if j == 0:
        preprefinal += blaked.hexdigest()[randb(128)]
    elif j == 1:
        preprefinal += sha3d.hexdigest()[randb(128)]
    elif j == 2:
        preprefinal += sha2d.hexdigest()[randb(128)]
prefinal = [i+j for i, j in zip(preprefinal[::2], preprefinal[1::2])]

rblaked = blaked.hexdigest()[::-1]
rsha3d = sha3d.hexdigest()[::-1]
rsha2d = sha2d.hexdigest()[::-1]

preprefinal2 = ''
for i in range(pwLength):
    j = randb(3)
    if j == 0:
        preprefinal2 += rblaked[randb(128)]
    elif j == 1:
        preprefinal2 += rsha3d[randb(128)]
    elif j == 2:
        preprefinal2 += rsha2d[randb(128)]
prefinal2 = [i+j for i, j in zip(preprefinal2[::2], preprefinal2[1::2])]

# first half
for i in range(pwLength // 2):
    j = randb(3)
    if j == 0:
        if hex(int(prefinal[i], 16)) in conversionDict1.keys():
            prefinal[i] = conversionDict1[hex(int(prefinal[i], 16))]
        elif hex(int(prefinal[i], 16) % 94) in conversionDict1.keys():
            prefinal[i] = conversionDict1[hex(int(prefinal[i], 16) % 94)]
    elif j == 1:
        if hex(int(prefinal[i], 16)) in conversionDict2.keys():
            prefinal[i] = conversionDict2[hex(int(prefinal[i], 16))]
        elif hex(int(prefinal[i], 16) % 94) in conversionDict2.keys():
            prefinal[i] = conversionDict2[hex(int(prefinal[i], 16) % 94)]
    elif j == 2:
        if hex(int(prefinal[i], 16)) in conversionDict3.keys():
            prefinal[i] = conversionDict3[hex(int(prefinal[i], 16))]
        elif hex(int(prefinal[i], 16) % 94) in conversionDict3.keys():
            prefinal[i] = conversionDict3[hex(int(prefinal[i], 16) % 94)]
final = ''.join(prefinal)

# second half
for i in range(pwLength // 2):
    j = randb(3)
    if j == 0:
        if hex(int(prefinal2[i], 16)) in conversionDict1.keys():
            prefinal2[i] = conversionDict1[hex(int(prefinal2[i], 16))]
        elif hex(int(prefinal2[i], 16) % 94) in conversionDict1.keys():
            prefinal2[i] = conversionDict1[hex(int(prefinal2[i], 16) % 94)]
    elif j == 1:
        if hex(int(prefinal2[i], 16)) in conversionDict2.keys():
            prefinal2[i] = conversionDict2[hex(int(prefinal2[i], 16))]
        elif hex(int(prefinal2[i], 16) % 94) in conversionDict2.keys():
            prefinal2[i] = conversionDict2[hex(int(prefinal2[i], 16) % 94)]
    elif j == 2:
        if hex(int(prefinal2[i], 16)) in conversionDict3.keys():
            prefinal2[i] = conversionDict3[hex(int(prefinal2[i], 16))]
        elif hex(int(prefinal2[i], 16) % 94) in conversionDict3.keys():
            prefinal2[i] = conversionDict3[hex(int(prefinal2[i], 16) % 94)]
final += ''.join(prefinal2)

# ensure user requirement is met
#   ...seriously, one char that is less outrageously random is okay
if len(final) != pwLength:
    idx = str(randb(len(allChar)))
    addToFinal = conversionDict3[hex(int(idx))]
    final += ''.join(addToFinal)
    print("\n'final' = " + final)
else:
    print("\n'final' = " + final)
