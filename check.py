from charm.toolbox.pairinggroup import *
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.conversion import *
try:
    from charm.core.math.pairing import G1, G2, pair, ZR, GT
except Exception as err:
    print(err)
    exit(-1)

group = PairingGroup('SS512')
#
# # print(G1)
# # print(G2)
# # print(pair)
# # print(ZR)
# # print(GT)
# message = group.random(GT)
#
# print(message)
#
# number = [123456789,123123]
#
# print(type(number))
#
# number = group.hash(number)
#
# print(number)
# print(type(number))

import pickle

file = open("CipherText.pkl", 'rb')
pickelFile = pickle.load(file)

print(bytesToObject(pickelFile,group))
