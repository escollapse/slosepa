#!/usr/bin/python3
#
# slosepa.py
# SLOw hash SEcure Password Author
# ver 0.2 - 20191017
#   black-box-ification
#   -randomized dict init
#   -randomized selection of digest nibble
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
#   2 - triple seed
#   3 - triple dict
#   4 - gui
#   5 - browser plugin?

import string
import secrets
import hashlib

# initializations
allChar = string.ascii_letters + string.digits + string.punctuation
allChar = list(allChar)
pwLength = 30
rounds = 500000
conversionDict = {}
temp = ''
for i in range(len(allChar)):
    temp = secrets.choice(allChar)
    allChar.remove(temp)
    conversionDict[hex(i)] = temp

# generate seed to hashing functions
seed = ''
for i in range(pwLength):
    seed += secrets.choice(list(conversionDict.values()))
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
    j = secrets.randbelow(3)
    if j == 0:
        preprefinal += blaked.hexdigest()[i]
    elif j == 1:
        preprefinal += sha3d.hexdigest()[i]
    elif j == 2:
        preprefinal += sha2d.hexdigest()[i]
prefinal = [i+j for i, j in zip(preprefinal[::2], preprefinal[1::2])]

rblaked = blaked.hexdigest()[::-1]
rsha3d = sha3d.hexdigest()[::-1]
rsha2d = sha2d.hexdigest()[::-1]

preprefinal2 = ''
for i in range(pwLength):
    j = secrets.randbelow(3)
    if j == 0:
        preprefinal2 += rblaked[i]
    elif j == 1:
        preprefinal2 += rsha3d[i]
    elif j == 2:
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
    addToFinal = str(secrets.randbelow(len(allChar)))
    addToFinal = conversionDict[hex(int(addToFinal))]
    final += ''.join(addToFinal)
    print("'final' = " + final)
else:
    print("'final' = " + final)
