def xorshift128(state0, state1):
	s1 = state0
	s0 = state1
	state0 = s0
	s1 ^^= s1 << 23 
	s1 &= 0xFFFFFFFFFFFFFFFF
	s1 ^^= s1 >> 17
	s1 ^^= s0
	s1 ^^= s0 >> 26
	state1 = s1
	return state0 & 0xFFFFFFFFFFFFFFFF, state1 & 0xFFFFFFFFFFFFFFFF

class XorShift128:

	def __init__(self, state0, state1):
		self.state0 = state0
		self.state1 = state1

	def next(self):
		self.state0, self.state1 = xorshift128(self.state0, self.state1)
		return self.state0 + self.state1

	def choice(self, l):
		return l[self.next() % len(l)]

def leftShiftVector(vec, amt):
	l = len(vec)
	new = [0] * l
	for idx in range(0, l - amt):
		new[idx + amt] = vec[idx]
	
	return vector(vec[0].parent(), new)

K = GF(2)
assert leftShiftVector(vector(K, [1, 1, 0, 0, 1, 0, 1, 1]), 3) == vector(K, [0, 0, 0, 1, 1, 0, 0, 1])

def rightShiftVector(vec, amt):
	l = len(vec)
	new = [0] * l
	for idx in range(amt, l):
		new[idx - amt] = vec[idx]
	
	return vector(vec[0].parent(), new)

assert rightShiftVector(vector(K, [1, 1, 0, 0, 1, 0, 1, 1]), 3) == vector(K, [0, 1, 0, 1, 1, 0, 0, 0])

def symbxorshift128(state0, state1):
	s1 = state0
	s0 = state1
	state0 = s0
	s1 += leftShiftVector(s1, 23)
	s1 += rightShiftVector(s1, 17)
	s1 += s0
	s1 += rightShiftVector(s0, 26)
	state1 = s1
	return state0, state1

class SymbXorShift128:
	def __init__(self, state0, state1):
		self.state0 = state0
		self.state1 = state1

	def next(self):
		raise NotImplementedError()
		self.state0, self.state1 = symbxorshift128(self.state0, self.state1)
		return 
	

	def bit(self):
		self.state0, self.state1 = symbxorshift128(self.state0, self.state1)
		return self.state0[0] + self.state1[0]

	def skip(self):
		self.bit()

	def choice(self, l):
		return l[self.next() % len(l)]

"""
if __name__ == '__main__':
	import secrets
	import tqdm
	SIZE = 64
	s0 = secrets.randbits(SIZE)
	s1 = secrets.randbits(SIZE)


	print('NOTE: not worky')
	prng = XorShift128(s0, s1)
	symbPrng = SymbXorShift128(s0, s1)
	# for _ in tqdm.trange(100):
	for _ in range(100):
		oracle = prng.next() & 1 
		guess = symbPrng.bit()
		assert oracle == guess

	print('worky')
"""
