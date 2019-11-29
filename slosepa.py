#!/usr/bin/env python3
#
# slosepa.py
# SLO       SE     P        A
# SLOw hash SEcure Password Author
# ver 0.5 - 20191128
#   pen-penultimate
#   -multithreading
#   -arg inputs from cmd line
#   -cleaned up mapper function
#   -resolved logic bug in seed generator
#
# **************
# * escollapse *
# * CISSP, PT+ *
# *  20191008  *
# **************
#
# future operations:
#   1 - gui (penultimate)
#   2 - release as an exe (for the masses, with instructions)
#   3 - OOP-ification (2.0?)
#   4 - browser plug-in (3.0?)

from string import ascii_letters, digits, punctuation
from secrets import choice as ch
from secrets import randbelow as randb
from hashlib import blake2b, sha3_512, sha512
from itertools import repeat
from multiprocessing import Process
from argparse import ArgumentParser as ap

# constants; note that i excluded space from char's
DIGEST_LENGTH = 128
ALL_CHAR = ascii_letters + digits + punctuation

def createConvDict(srcStr: str) -> dict:
    """Creates a dictionary with hexadecimal keys and randomly permuted characters as values, given a source string"""
    cDict = {}
    tempDict = list(srcStr)
    for i in range(len(tempDict)):
        temp = ch(tempDict)
        tempDict.remove(temp)
        cDict[hex(i)] = temp
    return cDict


def genSeed(length: int, seed: str) -> None:
    """Creates a randomly generated string from length to length*1337"""
    convDictList = [createConvDict(ALL_CHAR), createConvDict(ALL_CHAR), createConvDict(ALL_CHAR)]
    for _ in repeat(None, length * (randb(1337) + 1)):
        j = randb(len(convDictList))
        seed += ch(list(convDictList[j].values()))
    return


def hashUpdater(hash: hash(object), rounds: int) -> None:
    for _ in repeat(None, rounds):
        hash.update(bytearray(hash.hexdigest(), 'utf-8'))


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
    convDictList = [convDict1, convDict2, convDict3]
    for i in range(length // 2):
        j = randb(3)
        retList[i] = convDictList[j][hex(int(hexbytes[i], 16) % 94)]
    return retList


def main():
    parser = ap(description="Creates an essentially random password by leveraging hash algorithms")
    parser.add_argument("-l", "--length", action="store", type=int, dest="length",
                        default=30, help="specify password length (default=30)")
    parser.add_argument("-r", "--rounds", action="store", type=int, dest="numRounds",
                        default=500000, help="specify number of hashing rounds (default=500000)")
    args = parser.parse_args()
    pwLength = args.length
    rounds = args.numRounds
    seed1 = ""
    seed2 = ""
    seed3 = ""

    procList = []
    p1 = Process(target=genSeed, args=(pwLength, seed1))
    p2 = Process(target=genSeed, args=(pwLength, seed2))
    p3 = Process(target=genSeed, args=(pwLength, seed3))
    procList.append(p1)
    procList.append(p2)
    procList.append(p3)
    for i in range(3):
        procList[i].start()
    for i in range(3):
        procList[i].join()

    blaked = blake2b()
    sha3d = sha3_512()
    sha2d = sha512()

    blaked.update(bytearray(seed1, 'utf-8'))
    sha3d.update(bytearray(seed2, 'utf-8'))
    sha2d.update(bytearray(seed3, 'utf-8'))

    procList2 = []
    p21 = Process(target=hashUpdater, args=(blaked, rounds))
    p22 = Process(target=hashUpdater, args=(sha3d, rounds))
    p23 = Process(target=hashUpdater, args=(sha2d, rounds))
    procList2.append(p21)
    procList2.append(p22)
    procList2.append(p23)
    for i in range(3):
        procList2[i].start()
    for i in range(3):
        procList2[i].join()

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
        idx = randb(len(ALL_CHAR))
        addToFinal = createConvDict(ALL_CHAR)[hex(idx)]
        final += ''.join(addToFinal)
        print("\nsecret = " + final)
    else:
        print("\nsecret = " + final)


if __name__ == "__main__":
    main()
    print("\n\tSLOSEPA\nSLOw hash SEcure Password Author\n\tde escollapse (c) 2019")
