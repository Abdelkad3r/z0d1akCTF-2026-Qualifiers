"""LLL reduction.

Prefers fpylll (fast, numerically robust). Falls back to a pure-python
fraction-free integer LLL (Cohen, "A Course in Computational Algebraic Number
Theory", Alg. 2.6.3) so the solver runs with no third-party dependency, at the
cost of speed on higher dimensions.
"""

def _lll_fpylll(B):
    from fpylll import IntegerMatrix, LLL
    A = IntegerMatrix.from_matrix([list(map(int, row)) for row in B])
    LLL.reduction(A)
    return [[A[i, j] for j in range(A.ncols)] for i in range(A.nrows)]


def _lll_pure(B):
    B = [list(map(int, row)) for row in B]
    n = len(B); m = len(B[0])
    def dot(u, v): return sum(u[i] * v[i] for i in range(len(u)))
    d = [0] * (n + 1); d[0] = 1
    lam = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1):
            u = dot(B[i], B[j])
            for k in range(j):
                u = (d[k + 1] * u - lam[i][k] * lam[j][k]) // d[k]
            if j < i: lam[i][j] = u
            else: d[i + 1] = u
    def REDI(k, l):
        if 2 * abs(lam[k][l]) <= d[l + 1]: return
        q = (2 * lam[k][l] + d[l + 1]) // (2 * d[l + 1])
        Bk, Bl = B[k], B[l]
        for t in range(m): Bk[t] -= q * Bl[t]
        lam[k][l] -= q * d[l + 1]
        for i in range(l): lam[k][i] -= q * lam[l][i]
    def SWAPI(k):
        B[k], B[k - 1] = B[k - 1], B[k]
        for j in range(k - 1): lam[k][j], lam[k - 1][j] = lam[k - 1][j], lam[k][j]
        lmb = lam[k][k - 1]
        Bv = (d[k - 1] * d[k + 1] + lmb * lmb) // d[k]
        for i in range(k + 1, n):
            tt = lam[i][k]
            lam[i][k] = (d[k + 1] * lam[i][k - 1] - lmb * tt) // d[k]
            lam[i][k - 1] = (Bv * tt + lmb * lam[i][k]) // d[k + 1]
        d[k] = Bv
    k = 1
    while k < n:
        REDI(k, k - 1)
        if 4 * d[k + 1] * d[k - 1] >= (3 * d[k] * d[k] - 4 * lam[k][k - 1] * lam[k][k - 1]):
            for l in range(k - 2, -1, -1): REDI(k, l)
            k += 1
        else:
            SWAPI(k); k = max(1, k - 1)
    return B


def lll(B):
    try:
        return _lll_fpylll(B)
    except Exception:
        return _lll_pure(B)
