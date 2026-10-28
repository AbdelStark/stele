"""Q25/Q26 research: exact base-256 multiplication with static M31 side bounds."""
from certified_exp import require

WIDTH = 20
BASE = 256
CARRY_LIMIT = 8192
LEFT_BOUND = WIDTH*255*255+CARRY_LIMIT-1
RIGHT_BOUND = 255+BASE*(CARRY_LIMIT-1)
assert 2*max(LEFT_BOUND,RIGHT_BOUND) < (1 << 31)-1


def digits(value,count):
    require(type(value) is int and 0 <= value < 1 << (8*count),'LimbDomain')
    return [(value >> (8*i)) & 255 for i in range(count)]


def multiply(a,b):
    left,right = digits(a,WIDTH),digits(b,WIDTH)
    output,carries = [],[0]
    for k in range(2*WIDTH):
        total = carries[-1]+sum(left[i]*right[k-i] for i in range(WIDTH) if 0 <= k-i < WIDTH)
        carry,value = divmod(total,BASE)
        output.append(value);carries.append(carry)
    require(carries[-1] == 0,'LimbIdentity')
    return dict(output=output,carries=carries)


def verify(a,b,record):
    left,right = digits(a,WIDTH),digits(b,WIDTH)
    require(type(record) is dict and set(record) == {'output','carries'}
            and type(record['output']) is list and len(record['output']) == 2*WIDTH
            and type(record['carries']) is list and len(record['carries']) == 2*WIDTH+1,'LimbShape')
    output,carries = record['output'],record['carries']
    require(all(type(v) is int and 0 <= v < BASE for v in output)
            and all(type(v) is int and 0 <= v < CARRY_LIMIT for v in carries),'LimbRange')
    require(carries[0] == carries[-1] == 0,'LimbIdentity')
    for k in range(2*WIDTH):
        lhs = carries[k]+sum(left[i]*right[k-i] for i in range(WIDTH) if 0 <= k-i < WIDTH)
        rhs = output[k]+BASE*carries[k+1]
        require(lhs <= LEFT_BOUND and rhs <= RIGHT_BOUND and lhs == rhs,'LimbIdentity')
    return sum(v << (8*i) for i,v in enumerate(output))
