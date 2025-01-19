# basedsbox
## Gameplan
use known pt to symbolically walk the cipher forwards.

This should result in a poly-over-poly state element.

Since the subkeys are 64 bit elements, we can't brute them or anything like that

Let $x/y$ and $z/w$ be two state elements, and $c_0$ and $c_1$ be the corresponding ciphertexts. The subkeys should be roots of both $x/y - c_0$ and $z/w - c_1$.

By trivial algebraic manipulation, we get that $x - c_0 * y$ and $z - c_1*w$ must also have the subkeys as roots.

Since, afaik, there is no good way of doing gcd for multivariate polynomial rings, we have to use gröber. This may not work due to how ungodly slow it is.

UPDATE:

Instead of walking all the way forwards, we walk the pt halfway forwards, and the ct halfway backwards, that should result smaller degree polynomials.
