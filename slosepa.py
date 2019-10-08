#!/usr/bin/python3
#
# slosepa.py
# ver 0.1
# 20191008
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
#   1 - gui with argument inputs

import string
import secrets
import hashlib

# initializations
allOfTheAbove = string.ascii_letters + string.digits + string.punctuation
pwLength = 30
rounds = 500000
conversionDict = {}
for i in range(94):
    conversionDict[hex(i)] = allOfTheAbove[i]

# generate seed to hashing functions
seedClass = secrets.SystemRandom()
seed = ''
for i in range(pwLength):
    seed += seedClass.choice(allOfTheAbove)
print("'seed' = " + seed)

blaked = hashlib.blake2b()
sha3d = hashlib.sha3_512()
sha2d = hashlib.sha512()

blaked.update(bytearray(seed, 'utf-8'))
sha3d.update(bytearray(seed, 'utf-8'))
sha2d.update(bytearray(seed, 'utf-8'))

for i in range(rounds):
    blaked.update(bytearray(blaked.hexdigest(), 'utf-8'))
    sha3d.update(bytearray(sha3d.hexdigest(), 'utf-8'))
    sha2d.update(bytearray(sha2d.hexdigest(), 'utf-8'))

preprefinal = ''
for i in range(pwLength):
    if i % 3 == 0:
        preprefinal += blaked.hexdigest()[i]
    elif i % 3 == 1:
        preprefinal += sha3d.hexdigest()[i]
    else: # i % 3 = 2
        preprefinal += sha2d.hexdigest()[i]
prefinal = [i+j for i, j in zip(preprefinal[::2], preprefinal[1::2])]

rblaked = blaked.hexdigest()[::-1]
rsha3d = sha3d.hexdigest()[::-1]
rsha2d = sha2d.hexdigest()[::-1]

preprefinal2 = ''
for i in range(pwLength):
    if i % 3 == 0:
        preprefinal2 += rblaked[i]
    elif i % 3 == 1:
        preprefinal2 += rsha3d[i]
    else: # i % 3 = 2
        preprefinal2 += rsha2d[i]
prefinal2 = [i+j for i, j in zip(preprefinal2[::2], preprefinal2[1::2])]

# first half
for i in range(pwLength // 2):
    if hex(int(prefinal[i], 16)) in conversionDict.keys():
        prefinal[i] = conversionDict[hex(int(prefinal[i], 16))]
    elif hex(int(prefinal[i], 16) % 94) in conversionDict.keys():
        prefinal[i] = conversionDict[hex(int(prefinal[i], 16) % 94)]
final = ''.join(prefinal)

# second half
for i in range(pwLength // 2):
    if hex(int(prefinal2[i], 16)) in conversionDict.keys():
        prefinal2[i] = conversionDict[hex(int(prefinal2[i], 16))]
    elif hex(int(prefinal2[i], 16) % 94) in conversionDict.keys():
        prefinal2[i] = conversionDict[hex(int(prefinal2[i], 16) % 94)]
final += ''.join(prefinal2)

# ensure user requirement is met
if len(final) != pwLength:
    addToFinal = str(secrets.randbelow(len(allOfTheAbove)))
    addToFinal = conversionDict[hex(int(addToFinal))]
    final += ''.join(addToFinal)
    print("'final' = " + final)
else:
    print("'final' = " + final)
