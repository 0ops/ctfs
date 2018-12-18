#!/usr/bin/env python

def get_number(x, freq,rge):
    y = np.sin(2*np.pi*x*freq)*rge
    return y

def divide_flag(token):
    flag_list = []
    flag = "****************************************************************"
    for i in range(0,64,2):
        flag_list.append(int(flag[i]+flag[i+1],16))
    return flag,flag_list

def game(level,flag_list):

    level = level*4
    freq_list = flag_list[level:level+4]

    x = np.linspace(0,1,1500)
    y = []
    for freq in freq_list:
        if y == []:
            y = get_number(x,freq,7)
        else:
            y += get_number(x,freq,7)
    return y,freq_list

def start_game(tcpClisock,token,userlogger):

    flag,flag_list = divide_flag(token)
    level = 0
    while True:
        if level == 8:
            tcpClisock.sendall((CONGRATULATION_TXT.format("hctf{"+flag+"}")).encode("utf-8"))
            break
        y,freq_list = game(level,flag_list)
        send_data = json.dumps(list(y)).encode("utf-8")
        tcpClisock.sendall(send_data)
        req_data = tcpClisock.recv(1024).decode("utf-8").replace("\n","")
        req = req_data.split(" ")
        req.sort()
        freq_list.sort()
        if req == freq_list:
            level += 1
            continue
        else:
            break
    tcpClisock.close()