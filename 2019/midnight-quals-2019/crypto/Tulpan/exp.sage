

bb = [138, 229, 245, 162, 184, 116, 195, 143, 68, 1, 94, 35, 73, 202, 113, 235, 46, 97, 100, 148, 191, 102, 60, 118, 230, 256, 9, 175, 203, 136, 232, 82, 242, 236, 37, 201, 37, 116, 149, 90, 240, 200, 100, 179, 154, 69, 243, 43, 186, 167, 94, 99, 158, 149, 218, 137, 87, 178, 187, 195, 59, 191, 194, 198, 247, 230, 110, 222, 117, 164, 218, 228, 242, 182, 165, 174, 149, 150, 120, 202, 94, 148, 206, 69, 12, 178, 239, 160, 7, 235, 153, 187, 251, 83, 213, 179, 242, 215, 83, 88, 1, 108, 32, 138, 180, 102, 34]


#bb = [36, 15, 133, 7, 40, 86, 43, 85, 66, 127, 192, 216, 196, 229, 222, 190, 156, 255, 151, 174, 175, 247, 206, 231, 102, 2, 191, 164, 159, 252, 104, 170, 229, 47, 168, 113, 63, 122, 66, 187, 100, 66, 183, 125, 83, 30, 141, 28, 255, 53, 145, 233, 211, 100, 48, 46, 112, 149, 149, 126, 49, 180, 232, 163, 49, 71, 85, 206, 207, 247, 109, 241, 183, 197, 159, 149, 163, 170, 222, 172, 185, 6, 167, 253, 254, 8, 170, 6, 174, 101, 119, 73, 158, 47, 248, 225, 239, 125, 184, 192, 21, 174, 223, 256, 141, 107, 213]
#b = [1, 6, 123, 456, 57, 86, 121]
#q = 929
#k = 3
#size = 7
for index in range(107):
    for data in range(257):
        b = bb[:]
        b[index]=data
        q = 257
        k = 26
        size = 107
        a = []
        for i in range(size):
            a.append(i)

        FF.<x> = GF(q)[]

        error_num = int((size-k)//2)

        M = Matrix(Zmod(q),size,size)
        #part 1
        for j in range(error_num):
            for i in range(size):
                M[i,j] = b[i]*(a[i]**j)
        #part 2
        for j in range(size-error_num):
            for i in range(size):
                M[i,j+error_num] = -(a[i]**j)

        #print M
        B = []
        for i in range(size):
            B.append(-b[i]*(a[i]**error_num))
        B = Matrix(Zmod(q),B)
        #print B
        try:
            res = list(list(M.solve_right(B.T).T)[0])
        except:
            continue
        #print res


        def create(a):
            res = str(a[0])
            for i in range(1,len(a)):
                res+=("+"+str(a[i])+"*x**"+str(i))
            #print res
            return eval(res)

        E = create(res[:error_num]+[1])
        Q = create(res[error_num:])
        AAA = (Q/E)
        if Q%E==0:
            print AAA.parent()
            print FF(AAA).list()
            print AAA
            print "aaaaaaaaaa===========aaaaaaaaaaaaaaaaaaaaaaa========================"
            raw_input()
        #print AAA



