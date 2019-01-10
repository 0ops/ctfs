import csv

data = []
headers = ['A','B','C','D','E','R1','R2','B1','B2','G1','G2','LAT','CLK','OE','Label']

"""
pre = {'A': '0', 'C': '0', 'B': '0', 'E': '0', 'D': '1', 'G1': '0', 'CLK': '0', 'OE': '0', 'R2': '0', 'R1': '0', 'Label': '-1.0000000e-03', 'B1': '0', 'B2': '0', 'LAT': '0', 'G2': '0'}
with open('blink.csv') as f:
    f_csv = csv.DictReader(f)
    for r in f_csv:
        flag = False
        for a in range(len(headers)-1):
            if pre[headers[a]]!=r[headers[a]]:
                flag = True
                break
        if flag:
            pre = r
            data.append(r)


print len(data)
print data[0:10]



with open('blink2.csv','w') as f:
    f_csv = csv.DictWriter(f, headers)
    f_csv.writeheader()
    f_csv.writerows(data)
"""
"""
first = False
test = []
with open("blink2.csv") as f:
    f_csv = csv.DictReader(f)
    for r in f_csv:
        now = r['A']+r['B']+r['C']+r['D']+r['E']
        if r['CLK']=='1' and r['LAT']=='0':
            if now=='00001':
                first = True
                data.append(r)
                test.append(1 if r['R1']=='1' else 0)
            else:
                if first:
                    break
                    

for i in range(2):
    for j in range(64):
        print test[i*64+j],
    print 
print len(data)
with open("test.csv","w") as f:
    f_csv = csv.DictWriter(f,headers)
    f_csv.writeheader()
    f_csv.writerows(data)
"""

"""
pre = "aaaaaaa"
with open("blink2.csv") as f:
    f_csv = csv.DictReader(f)
    for r in f_csv:
        if r['OE']=='0' and r['LAT']=='0' and r['CLK']=='1':
            now = r['A']+r['B']+r['C']+r['D']+r['E']
            if now!=pre:
                data.append(now)
                pre = now
print data
print len(data)
#data = set(['10000', '10001', '10101', '10100', '01101', '01100', '11111', '11110', '11010', '11011', '01000', '01001', '00111', '00110', '00010', '00011', '10011', '10010', '10110', '10111', '01110', '01111', '11001', '11000', '11100', '11101', '01011', '01010', '00001', '00000', '00100', '00101'])
"""



test = []
i = 0
res = []
dic = {"000000":0,"101000":0,"010100":0,"001000":0,"100000":0}
with open("blink2.csv") as f:
    f_csv = csv.DictReader(f)
    for r in f_csv:
        if r['CLK']=='1':
            now1 = r['E']+r['D']+r['C']+r['B']+r['A']
            now2 = r['R1']+r['R2']+r['G1']+r['G2']+r['B1']+r['B2']
            dic[now2]+=1;
            data.append(' ' if now2=="000000" else '1')
        if r['LAT']=='1':
            print i,
            i+=1
            print len(data)
            #print data
            res.append(data[:])
            data = []
            #raw_input(

for i in res:
    a = "".join(i)
    print a.rjust(128," ")


print dic
