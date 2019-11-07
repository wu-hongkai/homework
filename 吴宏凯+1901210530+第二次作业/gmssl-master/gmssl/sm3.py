import binascii
from math import ceil

from gmssl import func

from .func import rotl, bytes_to_list

# 十进制表示,大端
IV = [
    1937774191, 1226093241, 388252375, 3666478592,
    2842636476, 372324522, 3817729613, 2969243214,
]
# msg常规计算得到的最终hash值
IV_new = [
    1724379380, 1659825625, 3522352235, 3692094690,
    1097319559, 1559426978, 696098859, 2404100320,
]

T_j = [
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042
]

def sm3_ff_j(x, y, z, j):
    if 0 <= j and j < 16:
        ret = x ^ y ^ z
    elif 16 <= j and j < 64:
        ret = (x & y) | (x & z) | (y & z)
    return ret

def sm3_gg_j(x, y, z, j):
    if 0 <= j and j < 16:
        ret = x ^ y ^ z
    elif 16 <= j and j < 64:
        #ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
        ret = (x & y) | ((~ x) & z)
    return ret

def sm3_p_0(x):
    return x ^ (rotl(x, 9 % 32)) ^ (rotl(x, 17 % 32))

def sm3_p_1(x):
    return x ^ (rotl(x, 15 % 32)) ^ (rotl(x, 23 % 32))

def sm3_cf(v_i, b_i):
    w = []
    for i in range(16):
        weight = 0x1000000
        data = 0
        for k in range(i*4, (i+1)*4):
            data = data + b_i[k]*weight
            weight = int(weight/0x100)
        w.append(data)

    for j in range(16, 68):
        w.append(0)
        w[j] = sm3_p_1(w[j-16] ^ w[j-9] ^ (rotl(w[j-3], 15 % 32))) ^ (rotl(w[j-13], 7 % 32)) ^ w[j-6]
        str1 = "%08x" % w[j]
    w_1 = []
    for j in range(0, 64):
        w_1.append(0)
        w_1[j] = w[j] ^ w[j+4]
        str1 = "%08x" % w_1[j]

    a, b, c, d, e, f, g, h = v_i

    for j in range(0, 64):
        ss_1 = rotl(
            ((rotl(a, 12 % 32)) +
            e +
            (rotl(T_j[j], j % 32))) & 0xffffffff, 7 % 32
        )
        ss_2 = ss_1 ^ (rotl(a, 12 % 32))
        tt_1 = (sm3_ff_j(a, b, c, j) + d + ss_2 + w_1[j]) & 0xffffffff
        tt_2 = (sm3_gg_j(e, f, g, j) + h + ss_1 + w[j]) & 0xffffffff
        d = c
        c = rotl(b, 9 % 32)
        b = a
        a = tt_1
        h = g
        g = rotl(f, 19 % 32)
        f = e
        e = sm3_p_0(tt_2)

        a, b, c, d, e, f, g, h = map(
            lambda x:x & 0xFFFFFFFF ,[a, b, c, d, e, f, g, h])

    v_j = [a, b, c, d, e, f, g, h]
    return [v_j[i] ^ v_i[i] for i in range(8)]

#对消息进行补位、补长度标识
def plug(len1, msg):
    reserve1 = len1 % 64
    reserve1 = reserve1 + 1
    msg.append(0x80)
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64
    for i in range(reserve1, range_end):
        msg.append(0x00)
    bit_length = len1 * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)

    for i in range(8):
        msg.append(bit_length_str[7 - i])
    return msg

def sm3_hash(msg):
    # print(msg)
    len1 = len(msg)
    # 引入随机虚构的消息，长度与msg相同
    msg_new = func.bytes_to_list(b'a'*len1)
    len2 = len(msg_new)
    # 对msg、msg_new做补位操作
    msg = plug(len1, msg)
    msg_new = plug(len2, msg_new)

    # test作为附加值
    str_test = ['t', 'e', 's', 't']
    for i in range(4):
        msg_new.append(ord(str_test[i]))
        msg.append(ord(str_test[i]))
    len1 = len(msg)
    len2 = len(msg_new)
    # msg、msg_new重新补位，加长度标识
    msg = plug(len1, msg)
    msg_new = plug(len2, msg_new)
    group_count_new = round(len(msg_new) / 64)
    group_count = round(len(msg) / 64)
    B1 = []
    for i in range(0, group_count):
        B1.append(msg[i*64:(i+1)*64])

    B2 = []
    for i in range(0, group_count_new):
        B2.append(msg_new[i*64:(i+1)*64])

    V1 = []
    V1.append(IV)
    for i in range(0, group_count):
        V1.append(sm3_cf(V1[i], B1[i]))

    V2 = []
    V2.append(IV_new)  # 将原明文求得的hash作为msg_new的链变量
    V2.append(sm3_cf(V2[0], B2[1]))  # msg_new取最后一个分组和V2链变量做一次压缩
    y1 = V1[i+1]
    y2 = V2[1]

    result1 = ""
    result2 = ""
    for i in y1:
        result1 = '%s%08x' % (result1, i)
    for i in y2:
        result2 = '%s%08x' % (result2, i)
    print("y1="+result1)
    print("y2="+result2)
    if result1 == result2:
        print("ATTACK SUCCESS!")
    else:
        print("ATTACK FAIL!")

def sm3_kdf(z, klen): # z为16进制表示的比特串（str），klen为密钥长度（单位byte）
    klen = int(klen)
    ct = 0x00000001
    rcnt = ceil(klen/32)
    zin = [i for i in bytes.fromhex(z.decode('utf8'))]
    ha = ""
    for i in range(rcnt):
        msg = zin  + [i for i in binascii.a2b_hex(('%08x' % ct).encode('utf8'))]
        ha = ha + sm3_hash(msg)
        ct += 1
    return ha[0: klen * 2]
