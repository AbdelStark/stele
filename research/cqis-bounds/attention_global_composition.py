"""Draft RFC-0004 A3/A6/A8: complete global sources through output conversion.

Stream upstream records per head; retain their contexts and the complete
output proof. All child peaks remain additional. No wrapper challenge.
"""
import copy
from dataclasses import dataclass
from itertools import islice
import struct
import attention_global_offset as off
import attention_global_probability_sum as prob
import attention_output_conversion as out

r=off.r
need=r.need
PREFIX=b'stele/research/q26/attention-global-composition/v1\0'


@dataclass(frozen=True)
class Spec:
    row: out.Spec
    identity: int
    offsets: tuple
    probabilities: tuple


def derive(p,d):
    need(type(p) is Spec and type(p.identity) is int and 0<=p.identity<1<<23 and type(p.row) is out.Spec and p.row.identity==2*p.identity,'Spec');row=out.derive(p.row,d);s=p.row.schema;constants=out.norm.bounds.constants(s);B=(s.length+1023)//1024;h=p.row.heads;base=(1<<63)+(1<<39)*p.identity
    need(all(type(family) is tuple and len(family)==h and all(type(xs) is tuple and len(xs)==B for xs in family) for family in (p.offsets,p.probabilities)),'Spec')
    ids=[x for family in (p.offsets,p.probabilities) for xs in family for x in xs]+[x for xs in p.row.sources for j,x in enumerate(xs) if s.accumulation=='exact' or j!=1]+[p.row.scale,p.row.output]
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<39) for x in ids) and len(set(ids))==len(ids),'Spec')
    raw_bound=1024*constants['probability_max']*constants['restored_max']
    # Draft adapter: probability caps depend only on L/Q, never this auxiliary shift.
    drop=s.drop if s.accumulation=='block1024' else next(k for k in range(63) if (raw_bound+(1<<k)//2)//(1<<k)<=32767)
    schema=prob.bounds.Spec(s.length,s.width,s.fraction,s.exponent,s.value_mode,s.scale,drop);offsets=[];probabilities=[]
    for j in range(h):
        op=off.Spec(s,(1<<19)*p.identity+(1<<18)+2*j,p.offsets[j],p.row.sources[j][0],p.row.repetitions)
        zp=prob.Spec(schema,tuple(range(B)),(1<<21)*p.identity+(1<<20)+8*j+4,p.probabilities[j],p.row.sources[j][2],p.row.repetitions)
        off.derive(op,d);prob.derive(zp,d);offsets.append(op);probabilities.append(zp)
    raw=PREFIX+struct.pack('<BBQII',1,d,p.identity,B,len(row['raw']))+row['raw']+b''.join(struct.pack('<Q',x) for family in (p.offsets,p.probabilities) for xs in family for x in xs)
    return dict(row=row,offset=offsets,probability=probabilities,B=B,base=base,constants=constants,raw=raw)


def normalize(p,zss,offset_totals):
    """Producer-only integer witnesses; complete child verifiers authorize joins."""
    v=derive(p,4);s=p.row.schema;need(type(zss) is list and type(offset_totals) is list and len(zss)==len(offset_totals)==p.row.heads,'Input');zs=[];totals=[]
    for j,(weights,values) in enumerate(zip(zss,offset_totals)):
        caps=prob.derive(v['probability'][j],4)['caps'];need(type(weights) is list and len(weights)==v['B'] and all(type(z) is int and 0<=z<=cap for z,cap in zip(weights,caps)),'Input')
        need(type(values) is list and len(values)==s.width and all(type(x) is int and 0<=x<=2*v['constants']['total_max'] for x in values),'Input');Z=sum(weights);H=Z*v['constants']['restored_max'] if s.accumulation=='exact' else v['constants']['total_max'];T=[x-H for x in values]
        out.norm.bounds.inputs(s,Z,tuple(T));zs.append(Z);totals.append(T)
    return zs,totals


def flatten(v,expected):
    h=len(v['offset']);need(type(expected) is dict and set(expected)=={'offsets','probabilities','output'},'Root');values=[]
    for family in ('probabilities','offsets'):
        xs=expected[family];need(type(xs) is list and len(xs)==h and all(type(row) is list and len(row)==v['B'] for row in xs),'Root');values.extend(x for row in xs for x in row)
    need(all(type(x) is bytes and len(x)==32 for x in values),'Root');return values+out.flatten(v['row'],expected['output'])


def transcript(v,expected,states,d):
    bound=flatten(v,expected);need(type(states) is list and len(states)==2*len(v['offset'])+1 and all(type(x) is bytes and len(x)==32 for x in states),'Root');return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def words(p,v,values):
    return [x>>(8*k)&255 for k in range(8) for x in values+[0]*(v['row']['nh']-p.row.schema.width)]


def prove(p,inputs,d):
    v=derive(p,d);inputs=off.iterator(inputs);end=object();states=[];expected=dict(probabilities=[],offsets=[]);zss=[];sums=[];zroots=[]
    for j in range(p.row.heads):
        item=next(inputs,end);need(type(item) is tuple and len(item)==2,'StreamShape');weights,blocks=item;child,state=prob.prove(v['probability'][j],weights,d);roots=prob.roots(v['probability'][j],child)
        states.append(state);zss.append(weights.copy());expected['probabilities'].append(roots[:-1]);zroots.append(roots[-1]);yield dict(head=j,probability=child);del child
        summed=[0]*p.row.schema.width;bound=[];blocks=off.iterator(blocks)
        def observe():
            for b in range(v['B']):
                values=next(blocks,end);need(type(values) is list and len(values)==p.row.schema.width and all(type(x) is int and x>=0 for x in values),'Input')
                bound.append(r.root(p.offsets[j][b],words(p,v,values)))
                for k,x in enumerate(values):summed[k]+=x
                yield values
            need(next(blocks,end) is end,'StreamShape')
        states.append((yield from off.prove(v['offset'][j],observe(),d)));sums.append(summed);expected['offsets'].append(bound)
    need(next(inputs,end) is end,'StreamShape');zs,totals=normalize(p,zss,sums);child,state=out.prove(p.row,zs,totals,d);expected['output']=out.roots(p.row,child);index=v['row']['roles'].index('probability')
    for j in range(p.row.heads):need(zroots[j]==expected['output']['heads'][j][index] and r.root(p.row.sources[j][0],words(p,v,sums[j]))==expected['output']['heads'][j][0],'SourceJoin')
    states.append(state);t=transcript(v,expected,states,d);yield dict(output=child);return t.state


def aggregate(probabilities,offsets,output,d):
    rc=output['account'];up=[child['account'] for pair in zip(probabilities,offsets) for child in pair];accounts=up+[rc]
    return dict(identities=[x for part in accounts for x in part['identities']],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts),product_identity_numerators=[x['account']['product_identity_numerator'] for x in probabilities]+rc['product_identity_numerators'],product_reduction_numerator=sum(x['account']['product_reduction_numerator'] for x in probabilities)+rc['product_reduction_numerator'],projection_identity_numerators=[x['account']['projection_identity_numerator'] for x in offsets],sum_reduction_numerator=sum(x['account']['sum_reduction_numerator'] for x in offsets),selection_reduction_numerator=rc['selection_reduction_numerator'],denominator=r.sc.P**d)


def verify(p,expected,records,d):
    v=derive(p,d);flatten(v,expected);expected=copy.deepcopy(expected);records=off.iterator(records);end=object();probabilities=[];offsets=[];states=[];index=v['row']['roles'].index('probability')
    for j in range(p.row.heads):
        header=next(records,end);need(type(header) is dict and set(header)=={'head','probability'} and type(header['head']) is int and header['head']==j,'StreamShape')
        try:result=prob.verify(v['probability'][j],expected['probabilities'][j]+[expected['output']['heads'][j][index]],header['probability'],d)
        except ValueError as error:raise ValueError('Head'+str(j)+':Probability:'+str(error)) from None
        probabilities.append(result);states.append(result['state']);del header
        # Exact child window plus child EOF; any extra record fails the next outer role.
        try:result=off.verify(v['offset'][j],expected['offsets'][j]+[expected['output']['heads'][j][0]],islice(records,v['B']+1),d)
        except ValueError as error:raise ValueError('Head'+str(j)+':Offset:'+str(error)) from None
        offsets.append(result);states.append(result['state'])
    tail=next(records,end);need(type(tail) is dict and set(tail)=={'output'},'StreamShape');need(next(records,end) is end,'StreamShape')
    try:result=out.verify(p.row,expected['output'],tail['output'],d)
    except ValueError as error:raise ValueError('Output:'+str(error)) from None
    states.append(result['state']);t=transcript(v,expected,states,d)
    return dict(state=t.state,probability=probabilities,offset=offsets,output=result,draws=dict(t.draws),account=aggregate(probabilities,offsets,result,d))
