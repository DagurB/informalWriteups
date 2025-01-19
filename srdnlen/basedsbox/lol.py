mods = {64: 0x1b, 128: 0x87}
n = 64
mod = mods[n]

def mul(a, b, n=64):
	r = 0
	for i in range(n):
		r <<= 1
		if r & (1 << n):
			r ^= (1 << n) | mod
		if a & (1 << (n - 1 - i)):
			r ^= b
	return r

def pow(x, e, n=64):
	if e < 0:
		raise ValueError("e must be non-negative")
	if e == 0:
		return 1
	if e == 1:
		return x
	r = pow(x, e >> 1)
	r = mul(r, r, n=n)
	if e & 1:
		r = mul(r, x, n=n)
	return r

