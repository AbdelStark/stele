"""Q26/Q31 capped M31 ranges: consumed A3 and lookup research, full reveals."""
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
for folder in ('sumcheck','zerocheck','logup-characteristic','cqis-tables'):
    sys.path.insert(0,str(ROOT/folder))
import check_zerocheck as zc
import lookup as lu
import table_identity as table
import limbs

sc=lu.sc
need=lu.require
TABLE=table.Descriptor('range_8',1,b'')
PREFIX=b'stele/research/q26/capped-range/v1\0'
COLUMN_BOUND=2*255+1


@dataclass(frozen=True)
class Spec:
    identity: int
    source: int
    caps: tuple
    repetitions: int


def derive(p,d):
    need(2*COLUMN_BOUND<sc.P,'FieldBound')
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<56 and type(p.source) is int and 2<=p.source<1<<64,'Spec')
    need(type(p.repetitions) is int and p.repetitions in (1,2) and type(p.caps) is tuple and p.caps,'Spec')
    need(len(p.caps)<=4096,'Capacity')
    need(all(type(v) is int and 0<=v<sc.P for v in p.caps),'Spec')
    a=(len(p.caps)-1).bit_length(); n=1<<a; base=(1<<63)+64*p.identity
    need(not base<=p.source<base+64,'Spec')
    raw=PREFIX+struct.pack('<BBBQQI',1,d,p.repetitions,p.identity,p.source,len(p.caps))
    raw+=b''.join(struct.pack('<I',v) for v in p.caps)+table.table_id(TABLE)
    return a,n,base,raw


def vector(values,size):
    need(type(values) is list and len(values)==size,'OpeningShape')
    need(all(type(x) is int and 0<=x<sc.P for x in values),'NoncanonicalField')


def root(identity,values):
    return lu.commit(identity,[struct.pack('<I',x) for x in values],4)


def source_root(p,words):
    _,n,_,_=derive(p,4); vector(words,n)
    return root(p.source,words)


def lookup_plan(p,d):
    a,n,base,_=derive(p,d)
    # Static 8N<=32768<p: the complete vector is one characteristic-safe unit.
    return dict(id=p.identity,m=a+3,b=a+3,r=p.repetitions,sources=(base,),
                mus=tuple(base+2+j for j in range(p.repetitions)),
                table=table.canonical_rows(TABLE),sigma=(1,)*(8*n))


def witness(p,values):
    _,n,_,_=derive(p,4)
    need(type(values) is list and len(values)==len(p.caps) and
         all(type(v) is int and 0<=v<=cap for v,cap in zip(values,p.caps)),'Range')
    words=values+[0]*(n-len(values)); caps=list(p.caps)+[0]*(n-len(values))
    slack=[cap-x for cap,x in zip(caps,words)]
    bs=[x >> (8*j) & 255 for xs in (words,slack) for j in range(4) for x in xs]
    cs=[]; carry=[0]*n
    for j in range(4):
        carry=[(bs[j*n+i]+bs[(4+j)*n+i]+carry[i])//256 for i in range(n)]; cs.extend(carry)
    return words,bs,cs


def columns(spec,provided,identity,source,repetitions):
    """Static coordinate caps from a limb schema; original word/column relations remain separate."""
    cert=limbs.derive(spec)
    count=spec.count*(len(cert['left_caps'])+len(cert['right_caps']))+len(cert['result_caps'])+len(cert['carry_caps'])
    need(count<=4096,'Capacity')  # Before inspecting or iterating supplied payloads.
    need(type(provided) is dict and set(provided)=={'left','right','result','carry'},'Witness')
    caps=[]; values=[]; roles=[]
    for side in ('left','right','result','carry'):
        rows=provided[side] if side in ('left','right') else (provided[side],)
        bounds=cert[side+'_caps']; expected=spec.count if side in ('left','right') else 1
        need(type(rows) is tuple and len(rows)==expected and
             all(type(row) is tuple and len(row)==len(bounds) for row in rows),'Witness')
        for i,row in enumerate(rows):
            for j,value in enumerate(row): caps.append(bounds[j]); values.append(value); roles.append((side,i,j))
    p=Spec(identity,source,tuple(caps),repetitions); derive(p,4); vector(values,count)
    return p,values,tuple(roles)


def parts(p,words,bs,cs,d):
    a,n,base,_=derive(p,d)
    for xs,size in ((words,n),(bs,8*n),(cs,4*n)): vector(xs,size)
    caps=list(p.caps)+[0]*(n-len(p.caps)); fields=lambda xs:[sc.scalar(v,d) for v in xs]
    def item(name,index,m,ids,terms,rows):
        return name,dict(id=4*p.identity+index,m=m,k=0,ids=ids,
            terms=[(sc.scalar(c,d),factors) for c,factors in terms]),[fields(xs) for xs in rows]
    return [item('Reconstruction',0,a,[p.source]+[base+8+j for j in range(4)],
                 [(1,[0])]+[(-(1<<(8*j)),[1+j]) for j in range(4)],
                 [words]+[bs[j*n:(j+1)*n] for j in range(4)]),
            item('CapRelation',1,a+2,[base+16,base+17,base+18,base+1,base+19],
                 [(1,[0]),(1,[1]),(1,[2]),(-256,[3]),(-1,[4])],
                 [bs[:4*n],bs[4*n:],[0]*n+cs[:3*n],cs,[cap>>(8*j)&255 for j in range(4) for cap in caps]]),
            item('CarryBoolean',2,a+2,[base+1],[(1,[0,0]),(-1,[0])],[cs]),
            item('TerminalCarry',3,a,[base+21],[(1,[0])],[cs[3*n:]])]


class Transcript(zc.Transcript):
    def __init__(self,public,d):
        self.draws=Counter(); super().__init__(public,d)

    def challenge(self,label=zc.tr.CHALLENGE):
        self.draws[label]+=1
        return super().challenge(label)


def transcript(p,expected,proof,d,lookup_state):
    raw=derive(p,d)[-1]
    return Transcript(raw+expected+proof['byte_root']+proof['carry_root']+lookup_state,d)


def eq_weights(point,d):
    """RFC-0006 A3 MSB-first equality table, O(2^m) without inverses."""
    one=sc.scalar(1,d); values=[one]
    for x in point:
        pair=(sc.add(one,sc.neg(x)),x)
        values=[sc.mul(value,weight) for value in values for weight in pair]
    return values


def zero_prove(t,i,tables):
    """RFC-0006 A3 k=0 folded strategy; byte-identical to the naive oracle."""
    zc.describe(i,t.degree); zc.shape(i,tables,t.degree); need(i['k']==0,'InvalidZerocheck')
    d=t.degree; alpha=zc.start(t,i); state=[list(xs) for xs in tables]; rounds=[]
    for h in range(i['m']):
        weights=eq_weights(alpha[h+1:],d); row=[]
        for x in range(sc.degree(i)+1):
            folded=[sc.fold(xs,sc.scalar(x,d)) for xs in state]
            row.append(zc.total((sc.mul(w,sc.compose(i['terms'],values,d)) for w,values in zip(weights,zip(*folded))),d))
        rounds.append(row); t.absorb(zc.tr.ROUND,sc.message(i,h,row)); point=sc.challenge(t)
        state=[sc.fold(xs,point) for xs in state]
    final=[[xs[0]] for xs in state]; t.absorb(zc.FINAL,zc.final_bytes(i,final))
    return dict(skip=[],rounds=rounds,final=final)


def assemble(p,words,bs,cs,d):
    """Arithmetic producer also used by adversarial tests; acceptance is verify's job."""
    instances=parts(p,words,bs,cs,d); _,_,base,_=derive(p,d)
    lookup,receipt=lu.prove(lookup_plan(p,d),[bs],d)
    proof=dict(byte_root=root(base,bs),carry_root=root(base+1,cs),words=list(words),carry=list(cs),lookup=lookup,zero=[])
    t=transcript(p,source_root(p,words),proof,d,receipt['state'])
    proof['zero']=[zero_prove(t,i,rows) for _,i,rows in instances]
    return proof,t.state


def prove(p,values,d):
    derive(p,d)
    return assemble(p,*witness(p,values),d)


def verify(p,expected,proof,d):
    a,n,base,_=derive(p,d)
    need(type(expected) is bytes and len(expected)==32,'Root')
    need(type(proof) is dict and set(proof)=={'byte_root','carry_root','words','carry','lookup','zero'},'ProofShape')
    need(all(type(proof[k]) is bytes and len(proof[k])==32 for k in ('byte_root','carry_root')),'Root')
    need(type(proof['zero']) is list and len(proof['zero'])==4 and type(proof['lookup']) is dict,'ProofShape')
    source=proof['lookup'].get('sources'); need(type(source) is list and len(source)==1,'ProofShape'); bs=source[0]
    words,cs=proof['words'],proof['carry']
    for xs,size in ((words,n),(bs,8*n),(cs,4*n)): vector(xs,size)
    need(root(p.source,words)==expected and root(base,bs)==proof['byte_root'] and root(base+1,cs)==proof['carry_root'],'CommitmentMismatch')
    lookup=lu.verify(lookup_plan(p,d),[proof['byte_root']],proof['lookup'],d)
    t=transcript(p,expected,proof,d,lookup['state']); records=[]; claims=[]
    for (name,i,tables),part in zip(parts(p,words,bs,cs,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
             and type(part['rounds']) is list and len(part['rounds'])==i['m'] and
             all(type(row) is list and len(row)==sc.degree(i)+1 for row in part['rounds']) and
             type(part['final']) is list and len(part['final'])==len(i['ids']) and
             all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        try: receipt,_=zc.verify(t,i,part,tables)
        except ValueError as error: raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']); claims.extend(receipt['claims'])
    account=lookup['account']
    return dict(state=t.state,lookup_state=lookup['state'],lookup_claims=lookup['claims'],
                lookup_draws=dict(Counter(label for tag,label in lookup['events'] if tag==1)),
                claims=claims,sc=records,draws=dict(t.draws),
                account=dict(identity_numerator=account['identity_numerator'],identity_power=account['identity_power'],
                    lookup_reduction_numerator=account['reduction_numerator'],range_reduction_numerator=sum(v['numerator'] for v in records),
                    denominator=account['denominator']))
