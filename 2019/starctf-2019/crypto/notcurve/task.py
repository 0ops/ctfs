import os,random,sys,string
from hashlib import sha256
import SocketServer
import signal
from Crypto.Util.number import *
from gmpy2 import *
from flag import FLAG

def p_Builder():
    pi = getPrime(15)
    qi = getPrime(15)
    return pi*qi
p = 2^128-7
#global p
def i(x):
    return invert(x,p)

def check_point(A):
    (u,v) = A
    if (u**3+10*u-2)%p == (v**2)%p:
        return 1
    else:
        return 0
def add(A,B):
    assert check_point(A)==1 and check_point(B) == 1
    (u,v),(w,x) = A,B
    assert u!=w or v == x
    if u == w:
        m = (3*u*w+10)*i(v+x)
    else:
        m = (x-v)*i(w-u)
    y = m*m - u - w
    z = m*(u-y) - v
    return int(y % p), int(z % p)

def sub(A):
    (u,v) = A
    v = v%p
    if v > 2**11:
        print u//v
        return u//v
    else:
        return 0

def mul(t,A,B=0):
    assert check_point(A)==1
    #assert B==0 or check_point(B)==1
    if not t:
        #print B
        return B
    else:
        return mul(t//2, add(A,A), B if not t&1 else add(B,A) if B else A)

def div(t,A,B=0):
    (u,v) = A
    if (u*v) %p != 1:
        #print u*v*sub((p,t))%p
        return u*v*sub((p,t))%p
    else:
        return B

    
class Task(SocketServer.BaseRequestHandler):
    def proof_of_work(self):
        random.seed(os.urandom(8))
        proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in xrange(20)])
        digest = sha256(proof).hexdigest()
        self.request.send("sha256(XXXX+%s) == %s\n" % (proof[4:],digest))
        self.request.send('Give me XXXX:')
        x = self.request.recv(10)
        x = x.strip()
        if len(x) != 4 or sha256(x+proof[4:]).hexdigest() != digest: 
            return False
        return True
    def recvnum(self,sz):
        try:
            print sz
            r = sz
            res =""
            while r>0:
                res += self.request.recv(r)
                if res.endswith('\n'):
                    r = 0
                else:
                    r = sz - len(res)
            res = res.strip()
            t = int(res)
        except:
            res = ''
            t = 0
        return t
    def recvpoint(self, sz):
        try:
            r = sz
            res = ''
            while r>0:
                res += self.request.recv(r)
                if res.endswith('\n'):
                    r = 0
                else:
                    r = sz - len(res)
            res = res.strip()
            str1 = res.split(',')[0]
            str2 = res.split(',')[-1]
            assert str1 != str2
            x = int(str1.replace('(','').strip())
            y = int(str2.replace(')','').strip())
            #res = res.decode('hex')
        except:
            res = ''
            x = 0
            y = 0
        return (x,y)
    
    def dosend(self, msg):
        try:
            self.request.sendall(msg)
        except:
            pass

    def menu(self):
        #self.dosend("Welcome to the baby RSA-CURVES system!\n")
        #self.dosend("here are some options!\n")
        self.dosend("1. ADD.\n")
        self.dosend("2. SUB.\n")
        self.dosend("3. MUL.\n")
        self.dosend("4. DIV.\n")
        self.dosend("5. EXIT\n")
        self.dosend("input>> ")
    
    def ADD(self):
        self.dosend('input point A: \n')
        A = self.recvpoint(30)
        self.dosend('input point B: \n')
        B = self.recvpoint(30)
        C = add(A,B)
        self.dosend("the result is :"+str(C)+'\n')

    def SUB(self):
        self.dosend('Under Construction!\n')

    def MUL(self):
        self.dosend('input point A: \n')
        A = self.recvpoint(30)
        self.dosend('input number t: \n')
        t = self.recvnum(10)
        B = mul(t,A)
        self.dosend("the result is :"+str(B)+'\n')

    def DIV(self):
        self.dosend('input point A: \n')
        A = self.recvpoint(30)
        self.dosend('input number t: \n')
        t = self.recvnum(10)
        C = div(t,A)
        self.dosend("the result is :"+str(C)+'\n')

    def handle(self):
        signal.alarm(500)
        if not self.proof_of_work():
            return
        signal.alarm(450)
        self.dosend("Welcome to BABY CURVES FACTOR SYSTEM!\n")
        self.dosend("here are some options!\n")
        global p
        p = p_Builder()
        print p
        for j in xrange(4000):
            try:
                self.menu() 
                r = self.recvnum(4)
                if r == 1:
                    self.ADD()
                elif r==2:
                    self.SUB()
                elif r==3:
                    self.MUL()
                elif r==4:
                    self.DIV()
                elif r==5:
                    break
            except:
                self.dosend(">.<\n")
                #self.recvnum(4)
        self.dosend("please give me a point(pi,qi): \n")
        R = self.recvpoint(30)
        (u,v) = R
        print R
        if (u*v)%p == 0:
            self.dosend("%s\n" % FLAG)
        else:
            self.dosend(">.<\n")
        self.request.close()

class ForkingServer(SocketServer.ForkingTCPServer, SocketServer.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 20005
    print HOST
    print PORT
    server = ForkingServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
