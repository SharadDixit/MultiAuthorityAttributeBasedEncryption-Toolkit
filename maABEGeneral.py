import pickle
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.pairinggroup import *
from charm.toolbox.secretutil import SecretUtil
import sys
import re

try:
    from charm.core.math.pairing import G1, G2, pair, ZR, GT
except Exception as err:
    print(err)
    exit(-1)

group = PairingGroup('SS512')

util = SecretUtil(group, False)
H = lambda x: group.hash(x, G2)
F = lambda x: group.hash(x, G2)


def setup():
    g1 = group.random(G1)
    g2 = group.random(G2)
    egg = pair(g1, g2)
    gpWithoutHF = {'g1': g1, 'g2': g2, 'egg': egg}
    return gpWithoutHF


def authSetup(readFileGP, authName):
    pickelFileGP = pickleLoad(readFileGP)
    gp = byToOb(pickelFileGP)
    #     No need to update the file with H and F
    alpha, y = group.random(), group.random()
    egga = gp['egg'] ** alpha
    gy = gp['g1'] ** y
    pk = {'name': authName, 'egga': egga, 'gy': gy}
    sk = {'name': authName, 'alpha': alpha, 'y': y}
    print("Authsetup: %s" % authName)
    print(pk)
    print(sk)
    return pk, sk


def mergePublicKeys(publicKeysFileNameAuthority):
    publicKeyDic = {}
    for publicKeyEachFileNameAuthority in publicKeysFileNameAuthority:
        pickleKey = readFile(publicKeyEachFileNameAuthority)
        byteKey = pickleLoad(pickleKey)
        publicKey = byToOb(byteKey)
        publicKeyWithAuthName = {publicKey['name']: publicKey}
        publicKeyDic.update(publicKeyWithAuthName)
    return publicKeyDic


def multiAttributesKeygen(readFileGP, readFileSK, gid, attributes):
    pickleFileGP = pickleLoad(readFileGP)
    gp = byToOb(pickleFileGP)
    # Add H and F to gp as keygen requires those keys in dictionary
    gp.update({'H': H, 'F': F})

    pickleFileSK = pickleLoad(readFileSK)
    sk = byToOb(pickleFileSK)

    uk = {}
    for attribute in attributes:
        uk[attribute] = keygen(gp, sk, gid, attribute)
    # Can create a folder for each GID and save each user keys in that to have more organized storage of secret keys
    # But, Right now in the main directory
    fileNameSecretKey = gid + '_' + 'secretKey' + '@' + sk['name'] + '.pkl'
    return uk, fileNameSecretKey


def keygen(gp, sk, gid, attribute):
    _, auth, _ = unpackAttributes(attribute)

    assert sk['name'] == auth, "Attribute %s does not belong to authority %s" % (attribute, sk['name'])

    t = group.random()
    K = gp['g2'] ** sk['alpha'] * gp['H'](gid) ** sk['y'] * gp['F'](attribute) ** t
    KP = gp['g1'] ** t
    print("Keygen")
    print("User: %s, Attribute: %s" % (gid, attribute))
    print({'K': K, 'KP': KP})
    return {'K': K, 'KP': KP}


def unpackAttributes(attribute):
    # Unpacks an attribute in attribute name, authority name and index
    # :param.attribute: The attribute to unpack
    # :return: The attribute name, authority name and the attribute index,if present.

    parts = re.split(r"[@_]", attribute)
    assert len(parts) > 1, "No @ char in [attribute@authority] name"
    return parts[0], parts[1], None if len(parts) < 3 else parts[2]


def mergeSecretKeysUser(keyListFileNames):
    mergeSecret = {}

    for pickleKeyFileName in keyListFileNames:
        pickleKey = readFile(pickleKeyFileName)
        byteKey = pickleLoad(pickleKey)
        key = byToOb(byteKey)
        mergeSecret.update(key)
    return mergeSecret


def encrypt(readFileGP, readFilePublicKeyDic, message, policyString):
    pickleFileGP = pickleLoad(readFileGP)
    print("Policy:" + policyString)
    gp = byToOb(pickleFileGP)
    # Add H and F to gp as keygen requires those keys in dictionary
    gp.update({'H': H, 'F': F})

    pickleFilePublicKeyDic = pickleLoad(readFilePublicKeyDic)
    pks = byToOb(pickleFilePublicKeyDic)

    s = group.random()  # secret to be shared
    w = group.init(ZR, 0)  # 0 to be shared

    policy = util.createPolicy(policyString)
    attribute_list = util.getAttributeList(policy)

    secret_shares = util.calculateSharesDict(s, policy)  # These are correctly set to be exponents in Z_p
    zero_shares = util.calculateSharesDict(w, policy)

    C0 = message * (gp['egg'] ** s)
    C1, C2, C3, C4 = {}, {}, {}, {}
    for i in attribute_list:
        attributeName, auth, _ = unpackAttributes(i)
        attr = "%s@%s" % (attributeName, auth)
        tx = group.random()
        C1[i] = gp['egg'] ** secret_shares[i] * pks[auth]['egga'] ** tx
        C2[i] = gp['g1'] ** (-tx)
        C3[i] = pks[auth]['gy'] ** tx * gp['g1'] ** zero_shares[i]
        C4[i] = gp['F'](attr) ** tx

    print("Encrypt")
    print(message)

    return {'policy': policyString, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4}


def decrypt(readFileGP, readFileUserSecretKey, readFileCipherText):
    pickleFileGP = pickleLoad(readFileGP)
    gp = byToOb(pickleFileGP)
    gp.update({'H': H, 'F': F})

    pickleFileUserSecretKey = pickleLoad(readFileUserSecretKey)
    sk = byToOb(pickleFileUserSecretKey)

    pickleFileCipherText = pickleLoad(readFileCipherText)
    ct = byToOb(pickleFileCipherText)

    policy = util.createPolicy(ct['policy'])
    coefficients = util.getCoefficients(policy)
    pruned_list = util.prune(policy, sk['keys'].keys())

    if not pruned_list:
        raise Exception("You don't have the required attributes for decryption!")

    B = group.init(GT, 1)
    for i in range(len(pruned_list)):
        x = pruned_list[i].getAttribute()  # without the underscore
        y = pruned_list[i].getAttributeAndIndex()  # with the underscore
        B *= (ct['C1'][y] * pair(ct['C2'][y], sk['keys'][x]['K']) * pair(ct['C3'][y], gp['H'](sk['GID'])) * pair(
            sk['keys'][x]['KP'], ct['C4'][y])) ** coefficients[y]

    print("Decrypt")
    # print("SK:")
    # print(sk)
    print("Decrypted Message:")
    print(ct['C0'] / B)
    # return ct['C0'] / B


def pickleDump(bytes, fileName):
    pickle.dump(bytes, open(fileName, 'wb'))


def pickleLoad(pickelFile):
    return pickle.load(pickelFile)


def obToBy(dic):
    return objectToBytes(dic, group)


def byToOb(bytes):
    return bytesToObject(bytes, group)


def readFile(fileName):
    readF = open(fileName, 'rb')
    return readF


def checkPickle():
    readFile = open(sys.argv[2], 'rb')
    dic = pickle.load(readFile)
    print(dic)
    print(bytesToObject(dic, group))


if __name__ == '__main__':

    # arguments > setup
    if sys.argv[1] == 'setup':
        gpWithoutHF = setup()
        byteGPWithoutHF = obToBy(gpWithoutHF)
        fileName = "GlobalParameters.pkl"
        pickleDump(byteGPWithoutHF, fileName)

    # arguments > authSetup, GlobalParameters.pkl, authorityName
    elif sys.argv[1] == 'authSetup':
        readFileGP = readFile(sys.argv[2])
        authName = sys.argv[3]
        pk, sk = authSetup(readFileGP, authName)
        bytePK = obToBy(pk)
        byteSK = obToBy(sk)
        fileNamePK = 'PK' + '@' + authName + '.pkl'
        fileNameSK = 'SK' + '@' + authName + '.pkl'
        pickleDump(bytePK, fileNamePK)
        pickleDump(byteSK, fileNameSK)

    # arguments > mergePublicKeysAuthority, publickey1, publickey2 (Complete List)
    elif sys.argv[1] == 'mergePublicKeysAuthority':
        publicKeysAuthorityName = sys.argv[2:]
        publicKeyDic = mergePublicKeys(publicKeysAuthorityName)
        publicKeyDicFileName = 'PublicKeyDic' + '.pkl'
        bytePublicKeyDic = obToBy(publicKeyDic)
        pickleDump(bytePublicKeyDic, publicKeyDicFileName)
        print(publicKeyDic)


    # arguments > multiAttributesKeygen, GlobalParameters.pkl, secretKey.pkl, gid, attribute1, attribute2 (complete list)
    # attribute should be annotated with @ , student@UT  (attibute@Authority)
    elif sys.argv[1] == 'multiAttributesKeygen':
        readFileGP = readFile(sys.argv[2])
        readFileSK = readFile(sys.argv[3])
        gid = sys.argv[4]
        attributes = sys.argv[5:]
        uk, fileNameSecretKey = multiAttributesKeygen(readFileGP, readFileSK, gid, attributes)
        byteSecretKey = obToBy(uk)
        print(fileNameSecretKey)
        pickleDump(byteSecretKey, fileNameSecretKey)
        print("UK", uk)

    # arguments > mergeSecretKeysUser, GID, key1, key2 (complete list of keys for specified GID)
    elif sys.argv[1] == 'mergeSecretKeysUser':
        gid = sys.argv[2]
        keyListFileNames = sys.argv[3:]
        secretKey = {'GID': gid, 'keys': mergeSecretKeysUser(keyListFileNames)}
        secretKeyFileName = gid + '_' + 'SecretKey' + '.pkl'
        byteSecretKey = obToBy(secretKey)
        pickleDump(byteSecretKey, secretKeyFileName)
        print(secretKey)

    # arguments > encrypt, GlobalParameters.pkl, publicKeyDic, message, policyString
    # policy parenthesis to be written with \ to provide bash to read it  \(Check\)
    elif sys.argv[1] == 'encrypt':
        readFileGP = readFile(sys.argv[2])
        readFilePublicKeyDic = readFile(sys.argv[3])
        message = sys.argv[4]
        randomMessage = group.random(GT)  # Not able to insert message string as algorithm is based on pairing groups
        policyString = sys.argv[5]
        # print(policyString)
        cipherText = encrypt(readFileGP, readFilePublicKeyDic, randomMessage, policyString)
        print("CipherText", cipherText)
        cipherTextFileName = "CipherText" + ".pkl"
        byteCipherText = obToBy(cipherText)
        pickleDump(byteCipherText, cipherTextFileName)

    # arguments > decrypt, GlobalParameters.pkl, User_SecretKey.pkl, CipherText.pkl
    elif sys.argv[1] == 'decrypt':
        readFileGP = readFile(sys.argv[2])
        readFileUserSecretKey = readFile(sys.argv[3])
        readFileCipherText = readFile(sys.argv[4])
        decrypt(readFileGP, readFileUserSecretKey, readFileCipherText)

    else:
        print("Wrong Arguments Entered")
