"""Draft RFC-0004 A3/A6; RFC-0009 A1: actual masked attained score maximum.

O(N) byte views and five A3s, plus eight complete range/lookup children.
Full source openings and public-view evaluation are revealing reference costs.
"""
from dataclasses import dataclass
import struct
import attention_max_bounds as maximum
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/attention-maximum/v1\0'
ROLES=('source','maximum','selection','difference')
CHILDREN=('source','maximum','offset','difference','gap','source_carry','difference_carry','first_carry')
AUXILIARY=('offset','gap','source_carry','difference_carry','first_carry')


@dataclass(frozen=True)
class Spec:
    schema: maximum.Spec
    position: int
    positions: tuple
    window: int
    start: int
    stop: int
    identity: int
    source: int
    maximum: int
    selection: int
    difference: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');bounds=maximum.derive(p.schema);s=p.schema
    need(type(p.position) is int and 0<=p.position<s.length,'Position')
    need(type(p.positions) is tuple and 1<=len(p.positions)<=s.length and all(type(j) is int and 0<=j<s.length for j in p.positions) and all(x<y for x,y in zip(p.positions,p.positions[1:])),'Positions')
    need(all(type(x) is int for x in (p.window,p.start,p.stop)) and 0<=p.window<=s.length and 0<=p.start<=p.position<p.stop<=s.length,'Mask')
    allowed=tuple(p.start<=j<p.stop and j<=p.position and (p.window==0 or p.position-j<p.window) for j in p.positions);need(any(allowed),'EmptyRow')
    need(type(p.identity) is int and 0<=p.identity<1<<48 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec');count=len(p.positions);need(count<=16384,'Capacity')
    a=(count-1).bit_length();n=1<<a;base=(1<<63)+(1<<14)*p.identity;ids=tuple(getattr(p,name) for name in ROLES)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<14) for x in ids) and len(set(ids))==4,'Spec')
    caps=((1<<32)-1,)*count;masked=tuple(bounds['delta_max']*int(bit) for bit in allowed);carry=(1,)*count+(0,)*(n-count)
    sources=(p.source,p.maximum,base+1,p.difference,base+2,base+3,base+4,base+5)
    limits=(caps,((1<<32)-1,),(bounds['score_offset_max'],)*count,masked,masked,carry*4,carry*4,carry*4)
    ranges={name:r.Spec(256*p.identity+index,source,cap,p.repetitions) for index,(name,source,cap) in enumerate(zip(CHILDREN,sources,limits),1)}
    widths=[r.derive(child,d)[3] for child in ranges.values()];need(max(widths)<=4 and 2*511<r.sc.P,'FieldBound')
    raw=PREFIX+struct.pack('<BBB'+'Q'*5+'I'*5,1,d,p.repetitions,p.identity,*ids,p.position,p.window,p.start,p.stop,count)+maximum.encode(s)+b''.join(struct.pack('<I',j) for j in p.positions)
    return dict(ranges=ranges,bounds=bounds,count=count,a=a,n=n,base=base,allowed=allowed,bo=widths[2].bit_length()-1,bd=widths[3].bit_length()-1,raw=raw)


def selection(p,v,selected):
    need(type(selected) is int and selected in p.positions,'Selection');index=p.positions.index(selected);need(v['allowed'][index],'Selection');return index


def carry_values(left,right,n):
    result=[];incoming=[0]*n
    for k in range(4):
        incoming=[((x>>(8*k)&255)+(y>>(8*k)&255)+z)//256 for x,y,z in zip(left,right,incoming)];result.extend(incoming)
    return result


def witness(p,xs):
    v=derive(p,4);S=p.schema.score_max;n=v['n'];count=v['count'];need(type(xs) is list and len(xs)==count and all(type(x) is int and -S<=x<=S for x in xs),'Input')
    index=max((i for i,b in enumerate(v['allowed']) if b),key=lambda i:xs[i]);selected=p.positions[index];delta=[xs[index]-x if bit else 0 for x,bit in zip(xs,v['allowed'])];need(max(delta)<=v['bounds']['delta_max'],'Domain')
    prefix=[int(bit and j<selected) for j,bit in zip(p.positions,v['allowed'])];gap=[x-y for x,y in zip(delta,prefix)];offset=[x+S for x in xs];raw=[x%(1<<32) for x in xs];pad=lambda row:row+[0]*(n-count)
    return dict(selected=selected,maximum=xs[index],source=raw,offset=offset,difference=delta,gap=gap,
                source_carry=carry_values(pad(raw),[S]*count+[0]*(n-count),n),difference_carry=carry_values(pad([x*int(b) for x,b in zip(offset,v['allowed'])]),pad(delta),n),first_carry=carry_values(pad(gap),pad(prefix),n))


def roots(p,proof):
    v=derive(p,4);selection(p,v,proof['selected'])
    return [r.source_root(v['ranges'][name],proof[name]['words']) if name!='selection' else r.root(p.selection,[proof['selected']]) for name in ROLES]


def expected_roots(p,xs):
    v=derive(p,4);w=witness(p,xs)
    return [r.root(p.selection,[w['selected']]) if name=='selection' else r.source_root(v['ranges'][name],r.witness(v['ranges'][name],[w['maximum']%(1<<32)] if name=='maximum' else w[name])[0]) for name in ROLES]


def parts(p,proof,d):
    v=derive(p,d);n=v['n'];count=v['count'];index=selection(p,v,proof['selected']);rows={}
    for name,child in v['ranges'].items():
        _,_,size,width,_,_=r.derive(child,d);row=proof[name]['words'];r.vector(row,size*width);rows[name]=row+[0]*(4*n-len(row)) if name in ('offset','difference','gap') else row
    U,O,D,G=tuple(rows[name] for name in ('source','offset','difference','gap'));C0,C1,C2=tuple(rows[name] for name in AUXILIARY[2:]);mask=[int(bit) for bit in v['allowed']]+[0]*(n-count)
    bias=[(p.schema.score_max>>(8*k)&255) if j<count else 0 for k in range(4) for j in range(n)]
    selected=[O[k*n+index] if j<count else 0 for k in range(4) for j in range(n)]
    prefix=[int(bit and j<proof['selected']) for j,bit in zip(p.positions,v['allowed'])]+[0]*(4*n-count)
    incoming=lambda carry:[0]*n+carry[:-n]
    def item(name,index,m,start,terms,tables):
        return name,dict(id=1024*p.identity+128+index,m=m,k=0,ids=list(range(v['base']+start,v['base']+start+len(tables))),terms=[(r.sc.scalar(c,d),factors) for c,factors in terms]),[[r.sc.scalar(x,d) for x in row] for row in tables]
    return [item('SourceOffset',0,v['a']+2,16,[(1,[0]),(1,[1]),(1,[2]),(-1,[3]),(-256,[4])],[U,bias,incoming(C0),O,C0]),
            item('Difference',1,v['a']+2,21,[(1,[0,1]),(1,[2]),(1,[3]),(-1,[1,4]),(-256,[5])],[O,mask*4,D,incoming(C1),selected,C1]),
            item('FirstMaximum',2,v['a']+2,27,[(1,[0]),(1,[1]),(1,[2]),(-1,[3]),(-256,[4])],[G,prefix,incoming(C2),D,C2]),
            item('Terminal',3,v['a'],32,[(1,[0]),(1,[1])],[C1[-n:],C2[-n:]]),
            item('Attainment',4,2,34,[(1,[0]),(-1,[1])],[[U[k*n+index] for k in range(4)],rows['maximum']])]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==9 and type(states) is list and len(states)==8 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,xs,d):
    v=derive(p,d);w=witness(p,xs)
    return {name:r.prove(child,[w['maximum']%(1<<32)] if name=='maximum' else w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,selected,d):
    """Producer only; supplied child states and selected IDs confer no acceptance."""
    v=derive(p,d);selection(p,v,selected);proof={name:pairs[name][0] for name in CHILDREN};proof.update(selected=selected,roots={name:r.source_root(v['ranges'][name],pairs[name][0]['words']) for name in AUXILIARY})
    t=transcript(v,roots(p,proof)+[proof['roots'][name] for name in AUXILIARY],[pairs[name][1] for name in CHILDREN],d);proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    return proof,t.state


def prove(p,xs,d):
    return assemble(p,prepare(p,xs,d),witness(p,xs)['selected'],d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==4 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(CHILDREN)|{'roots','selected','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(AUXILIARY) and type(proof['zero']) is list and len(proof['zero'])==5,'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');selection(p,v,proof['selected']);need(r.root(p.selection,[proof['selected']])==expected[2],'Selection:CommitmentMismatch')
    targets=dict(zip(ROLES,expected));targets.update(proof['roots']);children=[]
    for name,child in v['ranges'].items():
        try:children.append(r.verify(child,targets[name],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    t=transcript(v,expected+[proof['roots'][name] for name in AUXILIARY],[child['state'] for child in children],d);records=[];claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==len(i['ids']) and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
        try:receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error:raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']);claims.extend(receipt['claims'])
    accounts=[child['account'] for child in children]
    account=dict(identities=[(item['identity_numerator'],item['identity_power']) for item in accounts],lookup_reduction_numerator=sum(item['lookup_reduction_numerator'] for item in accounts),range_reduction_numerator=sum(item['range_reduction_numerator'] for item in accounts)+sum(row['numerator'] for row in records),denominator=r.sc.P**d)
    return dict(state=t.state,children=children,sc=records,claims=claims,draws=dict(t.draws),account=account)
