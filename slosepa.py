#!/usr/bin/env python3
#
# slosepa.py
# SLOw hash SEcure Password Author
# ver 0.4 - 20191125
#   like a dev
#   -optimizations and refactoring, many thanks @mpetruzelli - seriously, go check his github
#   -structure-ization
#   -randomererer seed generation
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
#   0 - multi-threading
#   1 - argument inputs
#   2 - gui
#   3 - release as an exe
#   4 - browser plugin?

from string import ascii_letters, digits, punctuation
from secrets import choice as ch
from secrets import randbelow as randb
from hashlib import blake2b, sha3_512, sha512
from itertools import repeat

# constants; note that i excluded space from char's
DIGEST_LENGTH = 128
ALL_CHAR = ascii_letters + digits + punctuation

# future args
pwLength = 30
rounds = 500000


def createConvDict(srcStr: str) -> dict:
    """Creates a dictionary with hexadecimal keys and randomly permuted characters as values, given a source string"""
    cDict = {}
    tempDict = list(srcStr)
    for i in range(len(tempDict)):
        temp = ch(tempDict)
        tempDict.remove(temp)
        cDict[hex(i)] = temp
    return cDict


def genSeed(length: int) -> str:
    """Creates a randomly generated string from length to length*1337"""
    seed = ''
    convDictList = [createConvDict(ALL_CHAR), createConvDict(ALL_CHAR), createConvDict(ALL_CHAR)]
    for _ in repeat(None, length * randb(1337) + 1):
        j = randb(len(convDictList))
        seed += ch(list(convDictList[j].values()))
    return seed


def selectNibbles(length: int, hash1: hash(object), hash2: hash(object), hash3: hash(object)) -> str:
    """Creates a length-long string of hexadecimal values, randomly selected from three 512-bit, hashlib hash objects"""
    nibbles = ''
    hashList = [hash1, hash2, hash3]
    for _ in repeat(None, length):
        j = randb(len(hashList))
        nibbles += hashList[j].hexdigest()[randb(DIGEST_LENGTH)]
    return nibbles


def selectNibblesFromStr(length: int, str1: str, str2: str, str3: str) -> str:
    """Creates a string of hexadecimal values, randomly selected from three DIGEST_LENGTH-char hex-strings"""
    nibbles = ''
    strList = [str1, str2, str3]
    for _ in repeat(None, length):
        j = randb(len(strList))
        nibbles += strList[j][randb(DIGEST_LENGTH)]
    return nibbles


def mapper(length: int, hexbytes: list, convDict1: dict, convDict2: dict, convDict3: dict) -> list:
    """Randomly maps a list of hexadecimal bytes to the corresponding character from one of three hash tables"""
    retList = hexbytes
    for i in range(length // 2):
        j = randb(3)
        if j == 0:
            # guess how much fun this type-nightmare was?
            if hex(int(hexbytes[i], 16)) in convDict1.keys():
                retList[i] = convDict1[hex(int(hexbytes[i], 16))]
            elif hex(int(hexbytes[i], 16) % 94) in convDict1.keys():
                retList[i] = convDict1[hex(int(hexbytes[i], 16) % 94)]
        elif j == 1:
            if hex(int(hexbytes[i], 16)) in convDict2.keys():
                retList[i] = convDict2[hex(int(hexbytes[i], 16))]
            elif hex(int(hexbytes[i], 16) % 94) in convDict2.keys():
                retList[i] = convDict2[hex(int(hexbytes[i], 16) % 94)]
        elif j == 2:
            if hex(int(hexbytes[i], 16)) in convDict3.keys():
                retList[i] = convDict3[hex(int(hexbytes[i], 16))]
            elif hex(int(hexbytes[i], 16) % 94) in convDict3.keys():
                retList[i] = convDict3[hex(int(hexbytes[i], 16) % 94)]
    return retList


seed1 = genSeed(pwLength)
seed2 = genSeed(pwLength)
seed3 = genSeed(pwLength)

blaked = blake2b()
sha3d = sha3_512()
sha2d = sha512()

blaked.update(bytearray(seed1, 'utf-8'))
sha3d.update(bytearray(seed2, 'utf-8'))
sha2d.update(bytearray(seed3, 'utf-8'))

# how many times do we actually hash?
for _ in repeat(None, rounds):
    blaked.update(bytearray(blaked.hexdigest(), 'utf-8'))
    sha3d.update(bytearray(sha3d.hexdigest(), 'utf-8'))
    sha2d.update(bytearray(sha2d.hexdigest(), 'utf-8'))

forwardNibbles = selectNibbles(pwLength, blaked, sha3d, sha2d)
rblaked = blaked.hexdigest()[::-1]
rsha3d = sha3d.hexdigest()[::-1]
rsha2d = sha2d.hexdigest()[::-1]
revNibbles = selectNibblesFromStr(pwLength, rblaked, rsha3d, rsha2d)

# yields a list of hex-bytes
prefinal = [i+j for i, j in zip(forwardNibbles[::2], forwardNibbles[1::2])]
prefinal2 = [i+j for i, j in zip(revNibbles[::2], revNibbles[1::2])]

# randomly map hex-bytes to chars and cat to final result
prefinal = mapper(pwLength, prefinal, createConvDict(ALL_CHAR), createConvDict(ALL_CHAR), createConvDict(ALL_CHAR))
final = ''.join(prefinal)
prefinal2 = mapper(pwLength, prefinal2, createConvDict(ALL_CHAR), createConvDict(ALL_CHAR), createConvDict(ALL_CHAR))
final += ''.join(prefinal2)

# ensure user requirement is met
#   ...seriously, one char that is less outrageously random is okay
if len(final) != pwLength:
    idx = str(randb(len(ALL_CHAR)))
    addToFinal = createConvDict(ALL_CHAR)[hex(int(idx))]
    final += ''.join(addToFinal)
    print("\nsecret = " + final)
else:
    print("\nsecret = " + final)


if __name__ == "__main__":
    print("\n\tSLOSEPA\nSLOw hash SEcure Password Author\n\tde escollapse (c) 2019")
