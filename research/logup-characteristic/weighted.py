"""Q31 grouped-unit preparation; no authenticated source, PCS or lookup authority."""
from check_sumcheck import P, scalar, add, neg, mul


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def shape(m,b):
    require(type(m) is int and type(b) is int and 0 <= b <= min(m,30) and m <= 63, 'Shape')
    return 1 << m,1 << b,1 << (m-b),m-b


def unit(group,point,d):
    """MSB-first Boolean equality basis on public group bits; no division."""
    value = scalar(1,d)
    for k,r in enumerate(point):
        factor = r if group >> (len(point)-k-1) & 1 else add(scalar(1,d),neg(r))
        value = mul(value,factor)
    return value


def unit_tree(leaves,b,point,d):
    """Virtual fraction tree: ordinary within groups, weighted above them."""
    require(len(leaves) > 0 and len(leaves) & (len(leaves)-1) == 0,'Shape')
    m = len(leaves).bit_length()-1
    shape(m,b)
    require(type(d) is int and d in (4,8),'Field')
    canonical = lambda x: type(x) in (tuple,list) and len(x) == d and all(type(v) is int and 0 <= v < P for v in x)
    require(len(point) == m-b and all(canonical(x) for x in point),'Point')
    require(all(type(pair) in (tuple,list) and len(pair) == 2 and all(canonical(x) for x in pair) for pair in leaves),'Record')
    state = list(leaves)
    for level in range(m):
        parents = []
        for i in range(0,len(state),2):
            p0,q0 = state[i]
            p1,q1 = state[i+1]
            left,right = mul(p0,q1),mul(p1,q0)
            if level >= b:
                r = point[m-1-level]
                left,right = mul(add(scalar(1,d),neg(r)),left),mul(r,right)
            parents.append((add(left,right),mul(q0,q1)))
        state = parents
    return state[0]


class Source:
    """One logical record visit, not a device/IO counter or source authenticator."""
    def __init__(self,records):
        self.records = records
        self.reads = self.visits = 0

    def visit(self,count):
        require(self.visits == 0,'SourceReused')
        require(len(self.records) == count,'SourceLength')
        self.visits += 1

        def records():
            for record in self.records:
                self.reads += 1
                yield record
        return records()


def prepare(source,table,m,b,point,d):
    results,stats = prepare_many(source,table,m,b,[point],d)
    return results[0],stats


def prepare_many(source,table,m,b,points,d):
    """Honest histogram preparation from actual selected tuples, before alpha/beta."""
    n,capacity,groups,h = shape(m,b)
    require(type(d) is int and d in (4,8),'Field')
    require(type(table) in (tuple,list) and 0 < len(table) <= 1 << 16,'Table')
    require(type(table[0]) is tuple and len(table[0]) > 0,'Table')
    width = len(table[0])
    canonical = lambda x: type(x) is tuple and len(x) == width and all(type(v) is int and 0 <= v < P for v in x)
    require(all(canonical(t) for t in table) and len(set(table)) == len(table),'Table')
    require(type(points) in (tuple,list) and len(points) in (1,2),'Point')
    for point in points:
        require(type(point) in (tuple,list) and len(point) == h and all(
            type(r) in (tuple,list) and len(r) == d and all(type(v) is int and 0 <= v < P for v in r)
            for r in point),'Point')
    index = {t:i for i,t in enumerate(table)}
    counts = [0]*len(table)
    results = [[scalar(0,d)]*len(table) for _ in points]
    increments = 0
    records = source.visit(n)
    for group in range(groups):
        weights = [unit(group,point,d) for point in points]
        for _ in range(capacity):
            record = next(records)
            require(type(record) in (tuple,list) and len(record) == 2,'Record')
            selected,value = record
            require(type(selected) is int and selected in (0,1),'Selector')
            require(canonical(value),'Record')
            if selected:
                require(value in index,'OutsideTable')
                counts[index[value]] += 1
                increments += 1
        # Fixed full table scan. Each integer count is <= capacity < P.
        for t,count in enumerate(counts):
            for result,weight in zip(results,weights):
                result[t] = add(result[t],tuple(count*limb % P for limb in weight))
            counts[t] = 0
    return tuple(tuple(result) for result in results),dict(
        reads=source.reads,increments=increments,scan_slots=groups*len(table),
        unit_products=len(points)*groups*h,count_slots=len(table),
        multiplicity_slots=len(points)*len(table),accumulator_updates=len(points)*groups*len(table))
