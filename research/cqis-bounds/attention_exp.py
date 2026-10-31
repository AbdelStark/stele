"""RFC-0021 §2.1 / Draft RFC-0004 A3: consumed canonical exponential outputs.

O(N) byte views plus complete canonical tables and range/lookup/A3 consumers.
Revealing research; the actual maximum source remains a separate obligation.
"""
from dataclasses import dataclass
from functools import lru_cache
import struct
import attention_exp_index as index

r=index.r
fn=index.fn
need=r.need
PREFIX=b'stele/research/q26/attention-exp/v1\0'


@dataclass(frozen=True)
class Spec:
    row: index.attained.Spec
    representation: fn.Representation
    identity: int
    output: int


@lru_cache(maxsize=4,typed=True)
def tables(rep):
    """Only expected definitions enter; canonical file padding is NOT membership."""
    result=[]
    for descriptor in fn.dependencies(rep):
        rows=fn.table.canonical_rows(descriptor)[:fn.table.shape(descriptor)[0]]
        result.append((rows,tuple(tuple(x%r.sc.P for x in row) for row in rows)))
    return tuple(result)


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');mv=index.attained.derive(p.row,d)
    need(type(p.representation) is fn.Representation and type(p.representation.function) is fn.Function,'Representation');rep=p.representation;f=rep.function;f.__post_init__();rep.__post_init__()
    need((f.name,rep.mode) in (('exp_q/product',1),('exp_q/nearest',0),('exp_q/nearest',2)),'Representation');B,F,E=f.params[:3]
    need((B,F)==(p.row.schema.domain_bits,p.row.schema.fraction),'FunctionScope')
    need(type(p.identity) is int and 0<=p.identity<1<<42,'Spec');base=(1<<63)+(1<<20)*p.identity
    need(base+(1<<20)<=mv['base'] or mv['base']+(1<<14)<=base,'Spec')
    ids=tuple(getattr(p.row,name) for name in index.attained.ROLES)+(p.output,)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<20) and not mv['base']<=x<mv['base']+(1<<14) for x in ids) and len(set(ids))==5,'Spec')
    mode=rep.mode;n=mv['n'];mask=tuple(int(b) for b in mv['allowed'])+(0,)*(n-mv['count']);Q=1<<E;need(2*max(Q*Q+Q-1,Q+3)<r.sc.P,'FieldBound')
    child=index.Spec(p.row,rep,256*p.identity+1,base+1,base+2) if mode else None
    if child:index.derive(child,d)
    roles=[('output',p.output,Q)]
    if mode:
        roles += [('high_value',base+3,Q),('low_value',base+4,Q)]
        if mode==2:roles += [('quotient',base+5,Q)]
        roles += [('remainder',base+6,Q-1)]
        if mode==2:roles += [('correction',base+7,3)]
    else:roles += [('difference',p.row.difference,mv['bounds']['delta_max'])]
    ranges={name:r.Spec(16384*p.identity+j,source,tuple(cap*int(b) for b in mv['allowed']),p.row.repetitions) for j,(name,source,cap) in enumerate(roles,1)}
    for part in ranges.values():r.derive(part,d)
    names=('direct',) if mode==0 else ('high','low')+ (('correction',) if mode==2 else ())
    canonical=tables(rep);rows={name:entry[0] for name,entry in zip(names,canonical)}
    lookups={name:dict(id=16384*p.identity+128+j,m=mv['a'],b=mv['a'],r=p.row.repetitions,sources=(base+16+2*j,base+17+2*j),mus=tuple(base+24+2*j+k for k in range(p.row.repetitions)),table=entry[1],sigma=mask) for j,(name,entry) in enumerate(zip(names,canonical))}
    aux=(('high_index','low_index') if mode else ())+tuple(name for name in ranges if name not in ('output','difference'))
    function=fn.encode(f);representation=fn.encode_representation(rep)
    raw=PREFIX+struct.pack('<BBBQQI',1,d,p.row.repetitions,p.identity,p.output,len(mv['raw']))+mv['raw']+struct.pack('<H',len(function))+function+struct.pack('<H',len(representation))+representation
    return dict(index=child,ranges=ranges,rows=rows,lookups=lookups,aux=aux,mode=mode,Q=Q,a=mv['a'],n=n,count=mv['count'],allowed=mv['allowed'],mask=mask,cap=mv['bounds']['delta_max'],base=base,raw=raw)


def witness(p,us):
    v=derive(p,4);need(type(us) is list and len(us)==v['count'] and all(type(u) is int and 0<=u<=(v['cap'] if bit else 0) for u,bit in zip(us,v['allowed'])),'Input');B=p.representation.function.params[0];rows=v['rows'];w=dict(difference=us.copy())
    if v['mode']==0:w['output']=[rows['direct'][(1<<B)-u][1] if bit else 0 for u,bit in zip(us,v['allowed'])];return w
    split=index.witness(v['index'],us);hs=split['high'];ls=split['low'];hv=[rows['high'][h][1] if bit else 0 for h,bit in zip(hs,v['allowed'])];lv=[rows['low'][l][1] if bit else 0 for l,bit in zip(ls,v['allowed'])];qr=[divmod(h*l,v['Q']) for h,l in zip(hv,lv)];qs=[q for q,_ in qr]
    w.update(high_index=hs,low_index=ls,high_value=hv,low_value=lv,remainder=[rem for _,rem in qr],output=qs)
    if v['mode']==2:
        cs=[rows['correction'][(1<<B)-u][1] if bit else 0 for u,bit in zip(us,v['allowed'])];w.update(quotient=qs,correction=[x+int(bit) for x,bit in zip(cs,v['allowed'])],output=[q+x for q,x in zip(qs,cs)])
    return w


def sources(v,proof,d):
    result={name:(child,proof['ranges'][name]['words']) for name,child in v['ranges'].items()}
    if v['index']:
        iv=index.derive(v['index'],d)
        for name,label in (('difference','difference'),('high_index','high'),('low_index','low')):result[name]=(iv['ranges'][label],proof['index'][label]['words'])
    return result


def values(v,proof,d):
    result={}
    for name,(child,words) in sources(v,proof,d).items():
        _,_,n,width,_,_=r.derive(child,d);r.vector(words,n*width);result[name]=[sum(words[k*n+j]<<(8*k) for k in range(width)) for j in range(n)]
    return result


def columns(v,proof,d):
    w=values(v,proof,d);negative=[-u%r.sc.P for u in w['difference']]
    if v['mode']==0:return dict(direct=[negative,w['output']])
    result=dict(high=[w['high_index'],w['high_value']],low=[w['low_index'],w['low_value']])
    if v['mode']==2:result['correction']=[negative,[(x-bit)%r.sc.P for x,bit in zip(w['correction'],v['mask'])]]
    return result


def roots(p,proof):
    v=derive(p,4);src=sources(v,proof,4);return [r.source_root(*src[name]) for name in ('difference','output')]


def expected_roots(p,us):
    v=derive(p,4);w=witness(p,us);child=index.derive(v['index'],4)['ranges']['difference'] if v['index'] else v['ranges']['difference']
    return [r.source_root(part,r.witness(part,w[name])[0]) for name,part in (('difference',child),('output',v['ranges']['output']))]


def parts(p,proof,d):
    v=derive(p,d)
    if v['mode']==0:return []
    w=values(v,proof,d)
    def item(name,j,terms,rows):
        return name,dict(id=65536*p.identity+512+j,m=v['a'],k=0,ids=list(range(v['base']+32+4*j,v['base']+36+4*j)),terms=[(r.sc.scalar(value,d),factors) for value,factors in terms]),[[r.sc.scalar(x,d) for x in row] for row in rows]
    q=w['output'] if v['mode']==1 else w['quotient']
    result=[item('Product',0,[(1,[0,1]),(-v['Q'],[2]),(-1,[3])],[w['high_value'],w['low_value'],q,w['remainder']])]
    if v['mode']==2:result.append(item('Correction',1,[(1,[0]),(1,[1]),(-1,[2]),(-1,[3])],[q,w['correction'],v['mask'],w['output']]))
    return result


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==2+len(v['aux'])+2*len(v['lookups']) and type(states) is list and len(states)==int(v['index'] is not None)+len(v['ranges'])+len(v['lookups']) and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,us,d):
    v=derive(p,d);w=witness(p,us);pairs=dict(ranges={name:r.prove(child,w[name],d) for name,child in v['ranges'].items()});proof=dict(ranges={name:pair[0] for name,pair in pairs['ranges'].items()})
    if v['index']:pairs['index']=index.prove(v['index'],us,d);proof['index']=pairs['index'][0]
    actual=columns(v,proof,d);pairs['lookups']={}
    for name,plan in v['lookups'].items():
        part,receipt=r.lu.prove(plan,actual[name],d);pairs['lookups'][name]=(part,receipt['state'])
    return pairs


def assemble(p,pairs,d):
    """Producer only; supplied child states confer no acceptance."""
    v=derive(p,d);proof={kind:{name:pair[0] for name,pair in pairs[kind].items()} for kind in ('ranges','lookups')};states=[]
    if v['index']:proof['index']=pairs['index'][0];states.append(pairs['index'][1])
    src=sources(v,proof,d);proof['roots']={name:r.source_root(*src[name]) for name in v['aux']};actual=columns(v,proof,d)
    bound=roots(p,proof)+[proof['roots'][name] for name in v['aux']]+sum((r.lu.source_roots(plan,actual[name]) for name,plan in v['lookups'].items()),[])
    states += [pairs[kind][name][1] for kind in ('ranges','lookups') for name in v[kind]];t=transcript(v,bound,states,d);proof['zero']=[r.zero_prove(t,i,rows) for _,i,rows in parts(p,proof,d)]
    return proof,t.state


def prove(p,us,d):
    return assemble(p,prepare(p,us,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    keys={'ranges','lookups','roots','zero'}|({'index'} if v['index'] else set());need(type(proof) is dict and set(proof)==keys,'ProofShape')
    need(all(type(proof[kind]) is dict and set(proof[kind])==set(v[kind]) for kind in ('ranges','lookups')) and type(proof['roots']) is dict and set(proof['roots'])==set(v['aux']) and type(proof['zero']) is list and len(proof['zero'])==v['mode'],'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');child=None;states=[]
    if v['index']:
        try:child=index.verify(v['index'],[expected[0],proof['roots']['high_index'],proof['roots']['low_index']],proof['index'],d)
        except ValueError as error:raise ValueError('Index:'+str(error)) from None
        states.append(child['state'])
    ranges=[]
    for name,plan in v['ranges'].items():
        target=expected[1] if name=='output' else expected[0] if name=='difference' else proof['roots'][name]
        try:ranges.append(r.verify(plan,target,proof['ranges'][name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    states += [item['state'] for item in ranges];actual=columns(v,proof,d);lookups=[];lookup_roots=[]
    for name,plan in v['lookups'].items():
        try:
            part=proof['lookups'][name];need(type(part) is dict and 'sources' in part,'ProofShape');r.lu.source_roots(plan,part['sources']);need(part['sources']==actual[name],'SourceJoin');bound=r.lu.source_roots(plan,actual[name]);lookups.append(r.lu.verify(plan,bound,part,d));lookup_roots += bound
        except ValueError as error:raise ValueError(name.title()+'Lookup:'+str(error)) from None
    states += [item['state'] for item in lookups];t=transcript(v,expected+[proof['roots'][name] for name in v['aux']]+lookup_roots,states,d);records=[];claims=[]
    for (name,i,rows),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==4 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
        try:receipt,_=r.zc.verify(t,i,part,rows)
        except ValueError as error:raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']);claims.extend(receipt['claims'])
    ca=[child['account']] if child else [];ra=[item['account'] for item in ranges];la=[item['account'] for item in lookups]
    account=dict(identities=sum((x['identities'] for x in ca),[])+[(x['identity_numerator'],x['identity_power']) for x in ra+la],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in ca+ra)+sum(x['reduction_numerator'] for x in la),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in ca+ra)+sum(x['numerator'] for x in records),denominator=r.sc.P**d)
    return dict(state=t.state,index=child,ranges=ranges,lookups=lookups,sc=records,claims=claims,draws=dict(t.draws),account=account)
