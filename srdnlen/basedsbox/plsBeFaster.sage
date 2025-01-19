from binascii import unhexlify
from Crypto.Util.number import long_to_bytes as ltb
from server import *

import random as rnd
import string

from pwn import *
from time import time

proof.all(False)

# from sage.misc.verbose import verbose, set_verbose
# set_verbose(2)
# set_verbose(1)

# ROUNDS = 2 # instant
# ROUNDS = 4 # instant
# ROUNDS = 5 # 26s -> 7.4s -> 1.4s
# ROUNDS = 6 # DNF -> 5.2s -> 2s
ROUNDS = 7 # DNF -> 2m8s (synthetic)

forwardsRounds = ROUNDS // 2
backwardsRounds = ROUNDS - forwardsRounds

print(f'{backwardsRounds = }')
print(f'{forwardsRounds = }')

CIPHERROUNDS = 7
blockSize = 16
# key = os.urandom(8)
key = b'\xca\xfe\xba\xbe' * 2
assert len(key) == 8
cipher = Feistel(key, rounds = ROUNDS, block_size = blockSize)

P.<x> = PolynomialRing(GF(2))
poly = x^64 + x^4 + x^3 + x + 1
Q.<y> = GF(2^poly.degree(), 'y', modulus = poly)

R = PolynomialRing(Q, ROUNDS, 'z')
subkeys = R.gens()
z = subkeys[0]
print(f'{subkeys = }')

firstAdd = Q.from_integer(0x01d_5b)
secondAdd = Q.from_integer(0x_15_ba5ed)
knownConstantTerms = firstAdd + secondAdd

def f(l, r, key):
	return l + 1/(r + key) + knownConstantTerms

def encryptBlockAlgebraically(l, r, rounds = ROUNDS):
	for i in range(rounds):
		l, r = r, f(l, r, subkeys[i])
	return l, r

def decryptBlockAlgebraically(l, r, rounds = ROUNDS):
	revsubkeys = subkeys[::-1]
	for i in range(rounds):
		l, r = f(r, l, revsubkeys[i]), l
	return l, r

def plsNoFractionField(left, right):
	# a/b - c/d = 0
	# =>
	# (a * d - c * b) / bd = 0
	# =>
	# a * d - c * b = 0
	# we do this manually since sage is slow and doesn't know that the denominator will get immediately thrown out
	# return (left - right).numerator()
	leftNum = left.numerator()
	leftDen = left.denominator()
	rightNum = right.numerator()
	rightDen = right.denominator()
	return leftNum * rightDen - rightNum * leftDen

def splitLR(block: bytes):
	assert len(block) == blockSize
	return R(Q.from_integer(int.from_bytes(block[:blockSize // 2], 'big'))), R(Q.from_integer(int.from_bytes(block[blockSize // 2:], 'big')))

def sanityTestCipher():
	# Sanity test cipher
	pt = b'0123456789abcdef'
	ct = cipher._encrypt_block(pt)
	pt0 = cipher._decrypt_block(ct)
	assert pt == pt0

	# Sanity test cipher partial encryption
	tmp = cipher._encrypt_block_custom(pt, forwardsRounds)
	ct0 = cipher._encrypt_block_custom(tmp, cipher._rounds, start = forwardsRounds)
	assert ct == ct0, (ct, ct0)
	print(f'[sanityTestCipher] WORKS')

def testF():
	# sanity test cipher's f and our f
	tmp0 = int.from_bytes(b'01234567', 'big')
	tmp1 = int.from_bytes(b'abcdefgh', 'big')
	tmp2 = int.from_bytes(b'ABCDEFGH', 'big')
	tmp3 = Q.from_integer(cipher._f_generic(tmp0, tmp1, tmp2))
	tmp4 = f(Q.from_integer(tmp0), Q.from_integer(tmp1), Q.from_integer(tmp2))
	assert tmp3 == tmp4
	print(f'[testF] WORKS')

def testEncryptionCorrectness():
	# sanity test cipher's block encryption and our block encryption
	block = b'fjkhdlajiaksfhkl'
	ct = cipher._encrypt_block(block)
	rks = list(map(Q.from_integer, cipher._round_keys))
	# print(f'{rks = }')
	assert len(subkeys) == len(cipher._round_keys) == len(rks)
	realSkMapping = {sk: rk for sk, rk, in zip(subkeys, rks)}
	l, r = splitLR(block)
	oracleL, oracleR = splitLR(ct)

	assert l != r # are we splitting correctly?
	assert l != oracleL and r != oracleR # are we splitting seperate things?

	guessL, guessR = encryptBlockAlgebraically(l, r)
	guessL = guessL.subs(realSkMapping)
	guessR = guessR.subs(realSkMapping)
	# print(f'{oracleL = }')
	# print(f'{guessL = }')
	assert guessL == oracleL # is our encryption correct?
	assert guessR == oracleR # -||-
	print(f'[testEncryptionCorrectness] WORKS')

def testNoFF():
	left = R.random_element(degree = 5) / R.random_element(degree = 5)
	right = R.random_element(degree = 5) / R.random_element(degree = 5)
	assert (left - right).numerator() == plsNoFractionField(left, right), ((left - right).numerator(), plsNoFractionField(left, right))
	print(f'[testNoFF] WORKS')

def testOurEncDec():
	# sanity test decrypt(encrypt(l, r)) == l, r for our encryption
	for _ in range(5):
		l = R(Q.random_element())
		r = R(Q.random_element())

		# print(f'{l = }')
		# print(f'{r = }')

		encL, encR = encryptBlockAlgebraically(l, r)
		# print(f'{encL = }')
		# print(f'{encR = }')
		decL, decR = decryptBlockAlgebraically(encL, encR)
		# print(f'{decL = }')
		# print(f'{decR = }')

		skMapping = dict()
		for _ in range(5):
			for subkey in subkeys:
				skMapping[subkey] = Q.random_element()

			# should be a good enough sanity test according to the Schwartz–Zippel lemma
			assert l.subs(skMapping) == decL.subs(skMapping)
			assert r.subs(skMapping) == decR.subs(skMapping)

	print(f'[testOurEncDec] WORKS')

def testMitm():
	pt = b'3f792fohofuefhou'
	ct = cipher._encrypt_block(pt)

	rks = list(map(Q.from_integer, cipher._round_keys))
	realSkMapping = {sk: rk for sk, rk, in zip(subkeys, rks)}

	ptl, ptr = splitLR(pt)
	forwards = encryptBlockAlgebraically(ptl, ptr, forwardsRounds)

	ctl, ctr = splitLR(ct)
	backwards = decryptBlockAlgebraically(ctl, ctr, backwardsRounds)

	relations = []
	for left, right in zip(forwards, backwards):
		plsWorky = plsNoFractionField(left, right).subs(realSkMapping)
		assert plsWorky == 0
		# print(f'{plsWorky = }')

	print(f'[testMitm] WORKS')


def test():
	print('PERFORMING SELF-TESTS')
	sanityTestCipher()
	testF()
	testEncryptionCorrectness()
	testNoFF()
	testOurEncDec()
	testMitm()

# test()

if args.REMOTE:
	conn = remote('basedsbox.challs.srdnlen.it', 46173)
else:
	conn = process(['sage', '-python', 'server.py'])

pt = (  # ChatGPT cooked a story for us
   "Once upon a time, after linear and differential cryptanalysis had revolutionized the cryptographic landscape, "
   "and before Rijndael was selected as the Advanced Encryption Standard (AES), the field of cryptography was in a unique state of flux. "
   "New cryptanalytic methods exposed vulnerabilities in many established ciphers, casting doubt on the long-term security of systems "
   "once thought to be invulnerable. In response, the U.S. National Institute of Standards and Technology (NIST) "
   "launched a competition to find a successor to the aging DES. In 2000, Rijndael was chosen, setting a new standard for secure encryption. "
   "But even as AES became widely adopted, new challenges, like quantum computing, loomed on the horizon."
).encode()
paddedPt = cipher._pad(pt, blockSize)
# encCt = cipher.encrypt(pt)
encCt = unhexlify(conn.recvline().strip())
blocks = [cipher.xor(encCt[i:i + blockSize], paddedPt[i: i + blockSize]) for i in range(0, len(paddedPt), blockSize)]
cts = [encCt[i: i + blockSize] for i in range(blockSize, len(encCt), blockSize)]
print(f'{len(pt) = }')
print(f'{len(encCt) = }')

assert len(blocks) == len(cts), (len(blocks), len(cts))

relations = []
# blocks = [b'0123456789abcdef', b'hfdskjlfhasfdjlk', b'Fsa3fF#FDH012345', b'dd307dgcdww0gadc']
# blocks = [b'0123456789abcdef', b'hfdskjlfhasfdjlk', b'Fsa3fF#FDH012345', b'dd307dgcdww0gadc', b'D#qf3f..fhjksdhf']
# printable = string.ascii_lowercase + string.ascii_uppercase + string.digits

# # for _ in range(15):
# for _ in range(40):
# 	blocks.append(''.join(rnd.choices(printable, k = 16)).encode())

for enum, pt in enumerate(blocks):
	# ct = cipher._encrypt_block(pt)
	ct = cts[enum]

	ptl, ptr = splitLR(pt)
	forwards = encryptBlockAlgebraically(ptl, ptr, forwardsRounds)

	ctl, ctr = splitLR(ct)
	backwards = decryptBlockAlgebraically(ctl, ctr, backwardsRounds)

	for left, right in zip(forwards, backwards):
		zeroAtRootsPoly = plsNoFractionField(left, right)
		tmp = zeroAtRootsPoly.factor()
		relations.append(zeroAtRootsPoly)

# print(f'{relations[0] = }')
# print(f'{relations = }')
# GCDREL = gcd(relations[0], relations[2])
# print(f'{GCDREL = }')
# print(relations[0].resultant(relations[1]))
AUTISM = True
if AUTISM:
	# for elem in relations:
	# 	print('-' * 40)
	# 	print(elem)

	print('#' * 40)
I = Ideal(relations)

# singular:groebner = 3s
# singular:std = 3s
# singular:stdhilb = 6.2s
# singular:stdfglm = 2.9s
# singular:slimgb = 2s

variety = [0] * len(subkeys)
start = time()
if AUTISM:
	print('TODO: make sure that pt and ct are correctly aligned')
	G = I.groebner_basis(algorithm = 'singular:slimgb')
	for elem in G:
		print('=' * 40)
		# print(elem.variables())
		print(elem)
		# pray that we get a z_x - blah
		variable = elem.variables()[0]
		idx = subkeys.index(variable)
		# print(f'{variable = }, {idx = }, {variable == subkeys[-1]}')
		root = elem.univariate_polynomial().roots()[0][0]
		variety[idx] = root
		# print(elem.roots())
groebnerTime = time() - start
print(f'{groebnerTime = }')

key = 0
for idx in range(len(subkeys)):
	guess = variety[idx].to_integer()
	key ^^= guess
	# known = cipher._round_keys[idx]
	# print(known, guess)

key = ltb(key).hex()
conn.sendline(key)
conn.interactive()

exit()
"""
variety = I.variety(proof = False)
reducedRound = ROUNDS != CIPHERROUNDS
print(f'CONFIGURATION: {ROUNDS}/{CIPHERROUNDS} ({"Reduced round" if reducedRound else "Full round"} spec)')
print(f'ORACLE: {cipher._round_keys = }')
print(f'{len(variety) = }')
for possibleSolution in variety:
	print('=' * 40)
	# print(possibleSolution)
	for key, value in possibleSolution.items():
		print(f'{key}: {value.to_integer()}')
"""
