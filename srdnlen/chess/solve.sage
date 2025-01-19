import os
os.environ['TERM'] = 'xterm-256color'
os.environ['TERMINFO'] = '/usr/share/terminfo'

load('prng.sage')

from tqdm import trange
from pwn import *
from sys import stderr

legalPossibleMoves = [b'h2h4', b'f2f4', b'd2d4', b'b2b4']
moveToIndexMap = {legalPossibleMoves[idx][2:4]: idx for idx in range(len(legalPossibleMoves))}

players = [
    "Magnus Carlsen", "Hikaru Nakamura", "Garry Kasparov", "Bobby Fischer",
    "Viswanathan Anand", "Vladimir Kramnik", "Fabiano Caruana", "Ding Liren",
    "Ian Nepomniachtchi", "Anatoly Karpov", "Mikhail Tal", "Alexander Alekhine",
    "Jose Raul Capablanca", "Paul Morphy", "Judith Polgar", "Wesley So",
    "Levon Aronian", "Maxime Vachier-Lagrave", "Sergey Karjakin", "Shakhriyar Mamedyarov",
    "Teimour Radjabov", "Boris Spassky", "Tigran Petrosian", "Veselin Topalov",
    "Peter Svidler", "Anish Giri", "Richard Rapport", "Jan-Krzysztof Duda",
    "Viktor Korchnoi", "Bent Larsen", "David Bronstein", "Samuel Reshevsky",
    "Efim Geller", "Mikhail Botvinnik", "Alexander Grischuk", "Vassily Ivanchuk",
    "Nigel Short", "Michael Adams", "Gata Kamsky", "Ruslan Ponomariov",
    "Vladimir Akopian", "Peter Leko", "Evgeny Bareev", "Alexei Shirov",
    "Vladimir Malakhov", "Boris Gelfand", "Vladimir Fedoseev", "Daniil Dubov",
    "Wei Yi", "Alireza Firouzja" , "Vladislav Artemiev", "Dmitry Andreikin", 
    "Radoslaw Wojtaszek", "Leinier Dominguez", "Pentala Harikrishna", "Sergey Movsesian",
    "Ernesto Inarkiev", "David Navara", "Vladislav Kovalev", "Jorden Van Foreest",
    "Nihal Sarin", "Vincent Keymer", "Awonder Liang", "Jeffery Xiong",
    "Praggnanandhaa Rameshbabu", "Raunak Sadhwani"
]

dim = 128
B = BooleanPolynomialRing(dim, 'b')
gens = B.gens()
s0 = vector(B, gens[:64])
s1 = vector(B, gens[64:])
symbPrng = SymbXorShift128(s0, s1)
genMapping = {gens[idx]: idx for idx in range(len(gens))}


if args.REMOTE:
	conn = remote('chess.challs.srdnlen.it', 4012)
else:
	conn = process(['pypy3', 'main.py'], stderr = stderr)

leaks = []
relations = []
iterations = 200
# iterations = 5
for _ in trange(iterations):
	conn.sendlineafter(b'): ', b'1\nl')
	conn.recvuntil(b'\n\n1. ')
	move = conn.recvline().split(b' ')[0]
	idx = moveToIndexMap[move]
	bit = idx & 1
	leaks.append(bit)

	poly = symbPrng.bit()
	rel = [0] * dim
	for elem in poly.monomials():
		rel[genMapping[elem]] = 1
	
	relations.append(rel)

	for _ in range(3):
		symbPrng.skip()
	# print(f'{move = }, {moveToIndexMap[move] = }')

K = GF(2)
M = Matrix(K, relations)
b = vector(K, leaks)

S = M.solve_right(b)
binrep = ''.join(map(str, S))
print(f'{binrep = }')
state0 = int(binrep[:64][::-1], 2)
state1 = int(binrep[64:][::-1], 2)
print(f'{state0 = }, {state1 = }')

prng = XorShift128(state0, state1)
for _ in range(iterations * 4):
	prng.next()

conn.sendline(b'3')
triviaSize = 50
for _ in trange(triviaSize):
	player = prng.choice(players)
	conn.sendlineafter(b'of?\n', player.encode())

conn.interactive()
