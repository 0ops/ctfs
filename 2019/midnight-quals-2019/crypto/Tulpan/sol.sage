flag = "XXXXXXXXXXXXXXXXXXXXXXXXX"
p = 257
k = 26

F = GF(p)
FF.<x> = GF(p)[]
r = FF.random_element(k - 1)
secret = 141+56*x^1+14*x^2+221*x^3+102*x^4+34*x^5+216*x^6+33*x^7+204*x^8+223*x^9+194*x^10+174*x^11+179*x^12+67*x^13+226*x^14+101*x^15+79*x^16+236*x^17+214*x^18+198*x^19+129*x^20+11*x^21+52*x^22+148*x^23+180*x^24+49*x^25
masked = (r * secret).mod(x^k + 1)


B = Matrix(Zmod(p),[138, 65, 77, 143, 200, 174, 177, 59, 122, 87, 28, 150, 123, 53, 46, 105, 199, 133, 76, 235, 95, 215, 233, 158, 181, 136])
a = [141, 56, 14, 221, 102, 34, 216, 33, 204, 223, 194, 174, 179, 67, 226, 101, 79, 236, 214, 198, 129, 11, 52, 148, 180, 49]
A = Matrix(Zmod(p),26,26)
A[0] = a
for i in range(1,26):
    A[i]=[-d for d in a[-i:]]+a[:26-i]
#print A
#print B
CCC = list(list(A.solve_left(B))[0])
print "".join([chr(d) for d in CCC])



