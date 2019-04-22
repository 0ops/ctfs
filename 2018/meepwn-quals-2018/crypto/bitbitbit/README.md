# Writeup

1. list all possible value of `(p - q)&(2^t2-1)`, namely `gamma-2000 ~ gamma+2000`
2. solve the equation `x * (x + g) == n mod (2^t2)` and get the low bits of p and q
3. use Known Low bits of Factor Attack to factor n
4. decrypt flag with private key

