__author__ = "polaris"

from pwn import *
context.log_level = "debug"
r = remote("ppc-01.v7frkwrfyhsjtbpfcppnu.ctfz.one",2445)


while True:
    a = r.recvline()[:-1].decode()
    a = a.split(" ")
    print(a)
    res = float(a[-1])
    data = a[:-1]
    dp = [[{} for i in range(len(data))] for j in range(len(data))]
    for i in range(len(data)):
        dp[i][i][data[i]]=str(data[i])
    for i in range(len(data),-1,-1):
        for j in range(i+1,len(data)):
            for k in range(i,j):
                print(i,j,k)
                for d1 in dp[i][k]:
                    temp1 = dp[i][k][d1]
                    if k>i:
                        temp1 = "("+temp1+")"
                    for d2 in dp[k+1][j]:
                        temp2 = dp[k+1][j][d2]
                        if j>k+1:
                            temp2 = "("+temp2+")"
                        temp = []
                        temp.append(temp1+"+"+temp2)
                        temp.append(temp1+"-"+temp2)
                        temp.append(temp1+"*"+temp2)
                        temp.append(temp1+"/"+temp2)
                        for t in temp:
                            try:
                                d = eval(t)
                            except:
                                continue
                            dp[i][j][str(d)]=t
    senddata = ""
    for d in dp[0][len(data)-1]:
        if abs(float(d)-res)<0.000001:
            senddata = dp[0][len(data)-1][d]
    print(senddata)
    r.sendline(senddata)
    print(r.recvline())