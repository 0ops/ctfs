import re

def solve2(filename, addr):
    flag = 0
    data = []
    res = None
    for line in open(filename):
        if hex(addr)[2:] in line:
            flag = 1
            print 'start2'
        if flag:
            match = re.search(r'movl.*?\$(.*?),.*\(%rbp\)', line)
            if match:
                tmp = eval(match.group(1))
                data.append(tmp)
            match = re.search(r'cmp.*?\$(.*?),%eax', line)
            if match:
                res = eval(match.group(1))
                break
    data = [data[i:i+10] for i in range(0, 30, 10)]
    # for i in data:
    #     print i
    res = data[2].index(res)
    res = data[1].index(res)
    res = data[0].index(res)
    res += 48
    return res

def solve1(filename, addr):
    flag = 0
    data = []
    res = None
    for line in open(filename):
        if hex(addr)[2:] in line:
            flag = 1
            print 'start1'
        if flag:
            match = re.search(r'movl.*?\$(.*?),.*\(%rbp\)', line)
            if match:
                tmp = eval(match.group(1))
                data.append(tmp)
            match = re.search(r'cmp.*?\$(.*?),%eax', line)
            if match:
                res = eval(match.group(1))
                break
    data = [data[i:i+5] for i in range(0, 10, 5)]
    # for i in data:
    #     print i
    res = data[1].index(res)
    res = data[0].index(res)
    res += 48
    return res

def solve3(filename, addr):
    flag = 0
    data = []
    res = None
    for line in open(filename):
        if hex(addr)[2:] in line:
            flag = 1
            print 'start3'
        if flag:
            match = re.search(r'movl.*?\$(.*?),.*\(%rbp\)', line)
            if match:
                tmp = eval(match.group(1))
                data.append(tmp)
            match = re.search(r'cmp.*?\$(.*?),%eax', line)
            if match:
                res = eval(match.group(1))
                break
    data = [data[i:i+64] for i in range(0, 192, 64)]
    # for i in data:
    #     print i
    res = data[2].index(res)
    res = data[1].index(res)
    res = data[0].index(res)
    res += 48
    return res

if __name__ == '__main__':
    print solve2('a.txt', 0x3846B8A)
    print solve1('a.txt', 0x3846CD9)
    print solve3('a.txt', 0x38463FD)
