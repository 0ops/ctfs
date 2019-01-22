from threading import Thread
from Queue import Queue
import requests
import base64

res = {}

def getEncrypted(recipientName,drink):
    data = {'recipientName':recipientName,'drink':drink}
    r = requests.post('http://drinks.teaser.insomnihack.ch/generateEncryptedVoucher', json=data)
    return len(base64.b64decode(''.join(r.text.split('\n')[2:-3])))

def doWork():
    global res
    while True:
        recipientName = q.get()
        num = getEncrypted(recipientName,"beer")
        dic[recipientName[-1]] = num
        q.task_done()


concurrent = 50
q = Queue(concurrent)
for i in range(concurrent):
    t = Thread(target=doWork)
    t.daemon = True
    t.start()

def dictmin(dictio):
    mmm = 10000000
    mmmc = []
    for k in dictio:
        if dictio[k]<mmm:
            mmm = dictio[k]
    for k in dictio:
        if mmm==dictio[k]:
            mmmc.append(k)
    return mmmc;


#flag = '||G1MME_B33R_PLZ_1M_S0' 
#flag = '||G'
flag = '||G1MME_B33R_PLZ_1M_S0_V3RY_TH1R' 
while 1:
    dic = {}
    for i in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!?@_":
        q.put(flag + i)
    q.join()
    print dic
    print dictmin(dic)
    c = raw_input()
    flag+=c
    print flag
