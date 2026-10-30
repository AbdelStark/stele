# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26/Q31 consumed Requant: independent signed arithmetic and actual source attacks."""
import copy
from dataclasses import replace
import hashlib
import json
import random
import sys
import requant_consumer as q

lp=q.lp
r=q.ss.r


def rejects(reason,call):
    try: call()
    except ValueError as error: assert str(error)==reason,(reason,str(error))
    else: raise AssertionError('accepted '+reason)


def corpus():
    rng=random.Random(2672); digest=hashlib.sha256(); accepted=0
    for case in range(10000):
        spec=q.req.Spec(rng.randrange(1,65536),rng.randrange(63),(8,16)[case%2])
        p=q.Spec(spec,case,53,59,1+case%2); v=q.derive(p,4)
        acc=rng.randrange(-(1<<31),1<<31); divisor=1<<spec.shift
        magnitude=(2*abs(acc)*spec.mantissa+divisor)//(2*divisor)
        output=(-1 if acc<0 else 1)*magnitude
        if not -(1<<(spec.bits-1))<=output<1<<(spec.bits-1):
            rejects('OutputRange',lambda:q.req.witness(spec,acc)); continue
        w=q.req.witness(spec,acc); assert w['output']==output
        assert abs(acc)*spec.mantissa+v['cert']['bias']==magnitude*divisor+w['remainder']
        assert 0<=w['remainder']<divisor and abs(output)==w['quotient']; accepted+=1
        for name,child in v['products'].items():
            left,right=q.req.column_inputs(spec,acc,w)[name]
            arrays=([q.word(x) for x in left],[q.word(x) for x in right])
            expected=lp.ls.source(lp.derive(child,4)['input'],w['columns'][name]['left'],w['columns'][name]['right'])
            assert q.operand_root(child,*arrays)==lp.ls.source_root(lp.derive(child,4)['input'],expected)
        digest.update(v['raw']+acc.to_bytes(4,'little',signed=True)+output.to_bytes(spec.bits//8,'little',signed=True))
    assert accepted==4688 and digest.hexdigest()=='11ae98c900c076ed8c2fddc047a1fbb4da8c5a72576730f406e7e746e8ef5acf'
    edge=q.Spec(q.req.Spec(65535,62,16),(1<<42)-1,53,59,2); v=q.derive(edge,8)
    spans=[(ss['base'],512) for ss in (q.ss.derive(v['input'],8),q.ss.derive(v['output'],8))]
    spans.append((r.derive(v['remainder'],8)[4],64)); spans.extend((lp.derive(child,8)['base'],4096) for child in v['products'].values())
    assert all(v['base']<=start<start+size<=v['base']+(1<<20)<1<<64 for start,size in spans)
    spans.sort(); assert all(start+size<=following for (start,size),(following,_) in zip(spans,spans[1:]))
    print(json.dumps(dict(seed=2672,cases=10000,accepted=accepted,rejected=10000-accepted,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def honest():
    digest=hashlib.sha256(); total=0
    cases=[(q.req.Spec(1,0,8),-128),(q.req.Spec(1,2,8),-1),(q.req.Spec(1,1,8),3),(q.req.Spec(65535,32,16),-(1<<31))]
    for d in (4,8):
        for repetitions in (1,2):
            for case,(schema,acc) in enumerate(cases):
                p=q.Spec(schema,601+case,53,59,repetitions); v=q.derive(p,d)
                proof,state=q.prove(p,acc,d); expected=q.roots(p,proof)
                out=q.verify(p,expected,proof,d); assert out['state']==state
                bo=(schema.bits//8).bit_length()-1; br=r.derive(v['remainder'],d)[1]
                layouts=[lp.derive(child,d) for child in v['products'].values()]
                dims=[3,3,2,bo+1,bo+1,2,br+1]
                for x in layouts: dims.extend((x['layout']['a']+x['layout']['b']+2,x['g']+3,x['g']+3))
                f=lambda x:3*x*(x-1)//2+2*x
                assert out['account']['identities']==[((1<<m)+255,repetitions) for m in dims]
                assert out['account']['lookup_reduction_numerator']==sum(repetitions*(f(m)+f(8)+3*m) for m in dims)
                assert out['account']['range_reduction_numerator']==216+29*bo+7*br+sum(9*x['layout']['b']+18*x['g'] for x in layouts)
                assert out['account']['product_identity_numerator']==sum(x['k']-1 for x in layouts)
                assert out['account']['product_reduction_numerator']==sum(2*x['layout']['a']+4*x['h'] for x in layouts)
                assert out['account']['denominator']==r.sc.P**d and len(out['account']['identities'])==19
                assert len(out['sign']['claims'])==3 and sum(x['numerator'] for x in out['sign']['sc'])==3*bo
                assert out['draws'].get(r.zc.WEIGHT,0)==out['draws'].get(r.zc.tr.CHALLENGE,0)==bo
                output=q.req.witness(schema,acc)['output']; raw=int.from_bytes(output.to_bytes(schema.bits//8,'little',signed=True),'little')
                assert proof['output']['ranges'][0]['words']==q.word(raw)+[0]*(schema.bits//8-len(q.word(raw)))
                digest.update(state); total+=1; print('proof',d,repetitions,case,flush=True)
    assert total==16
    assert digest.hexdigest()=='6e0a8c395c155a39f8568d6c4c4d22c130bf4ecb6d5c88e940b0a212a5a2a55e'
    print(json.dumps(dict(proofs=total,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def unit_controls(p,pairs,d):
    v=q.derive(p,d)
    for name,left in (('bias',(9,1)),('division',(10,0))):
        for right in ((0,1),(1,0)):
            bad=copy.deepcopy(pairs); child=v['products'][name]
            bad['products'][name]=lp.prove(child,lp.limbs.witness(child.schema,left,right),d)
            forged,_=q.assemble(p,bad,d)
            rejects(name.title()+':Input:CommitmentMismatch',lambda:q.verify(p,q.roots(p,forged),forged,d))


def zero_claims(p,pairs,d):
    good,_=q.assemble(p,pairs,d)
    for index in range(3):
        bad=copy.deepcopy(good); bad['sign']['final'][index][0]=r.sc.scalar(1,d)
        rejects('SignTransfer:ClaimMismatch',lambda:q.verify(p,q.roots(p,good),bad,d))


def source_controls():
    p=q.Spec(q.req.Spec(3,1,8),697,53,59,1); unit_controls(p,q.prepare(p,-3,4),4)
    p=q.Spec(q.req.Spec(1,62,16),698,53,59,1); zero_claims(p,q.prepare(p,0,4),4)
    print('requant public units and all zero-quotient claims passed',flush=True)


def controls():
    d=4; p=q.Spec(q.req.Spec(3,1,8),697,53,59,1); v=q.derive(p,d)
    pairs=q.prepare(p,-3,d); proof,_=q.assemble(p,pairs,d); expected=q.roots(p,proof)
    for name,child in (('input','Raw'),('output','Raw')):
        bad=copy.deepcopy(proof); bad[name]['ranges'][0]['words'][0]^=1
        rejects(name.title()+':'+child+':CommitmentMismatch',lambda:q.verify(p,expected,bad,d))
    wrong=[('product',(3,),(2,)),('product',(2,),(3,)),('bias',(9,0),(1,1)),('bias',(8,1),(1,1)),
           ('quotient_product',(5,),(1,)),('quotient_product',(4,),(2,)),('division',(9,0),(1,1)),('division',(10,1),(1,1))]
    for name,left,right in wrong:
        bad=copy.deepcopy(pairs); child=v['products'][name]
        bad['products'][name]=lp.prove(child,lp.limbs.witness(child.schema,left,right),d)
        forged,_=q.assemble(p,bad,d)
        rejects(name.title().replace('_','')+':Input:CommitmentMismatch',lambda:q.verify(p,q.roots(p,forged),forged,d))
    unit_controls(p,pairs,d)
    bad=copy.deepcopy(pairs); bad['output']=q.ss.prove(v['output'],[5],d); forged,_=q.assemble(p,bad,d)
    rejects('SignTransfer:FinalEvaluationMismatch',lambda:q.verify(p,q.roots(p,forged),forged,d))
    # q=256 has a nonzero high byte even though the static quotient cap is zero.
    zero=q.Spec(q.req.Spec(1,62,16),698,53,59,1); zv=q.derive(zero,d); ps=q.prepare(zero,0,d)
    zero_claims(zero,ps,d)
    ps['output']=q.ss.prove(zv['output'],[256],d); forged,_=q.assemble(zero,ps,d)
    rejects('QuotientProduct:Input:CommitmentMismatch',lambda:q.verify(zero,q.roots(zero,forged),forged,d))
    # Wrong q with an oversized remainder satisfies every product and the join.
    for shift,acc in ((0,1),(1,-1)):
        spec=q.Spec(q.req.Spec(1,shift,8),699+shift,53,59,1); sv=q.derive(spec,d); ps=q.prepare(spec,0,d)
        ps['input']=q.ss.prove(sv['input'],[acc],d); rem=1+sv['cert']['bias']; cap=sv['cert']['divisor']-1
        ps['remainder']=r.assemble(sv['remainder'],[rem],[rem,(cap-rem)%256],[1],d)
        values={'product':((1,),(1,)),'bias':((1,sv['cert']['bias']),(1,1)),
                'quotient_product':((0,),(sv['cert']['divisor'],)),'division':((0,rem),(1,1))}
        ps['products']={name:lp.prove(child,lp.limbs.witness(child.schema,*values[name]),d) for name,child in sv['products'].items()}
        forged,_=q.assemble(spec,ps,d)
        rejects('Remainder:TerminalCarry:FinalEvaluationMismatch',lambda:q.verify(spec,q.roots(spec,forged),forged,d))
    # All subproofs can be valid while the two integer expressions disagree.
    join=q.Spec(q.req.Spec(1,0,8),701,53,59,1); jv=q.derive(join,d); ps=q.prepare(join,1,d)
    ps['output']=q.ss.prove(jv['output'],[2],d)
    for name,values in (('quotient_product',((2,),(1,))),('division',((2,0),(1,1)))):
        child=jv['products'][name]; ps['products'][name]=lp.prove(child,lp.limbs.witness(child.schema,*values),d)
    forged,_=q.assemble(join,ps,d)
    rejects('ResultJoin',lambda:q.verify(join,q.roots(join,forged),forged,d))
    for mutate,reason in ((lambda x:x['products'].pop('division'),'ProofShape'),
                          (lambda x:x['sign']['final'].pop(),'ProofShape'),
                          (lambda x:x['sign']['final'][0].__setitem__(0,(False,0,0,0)),'SignTransfer:NoncanonicalField')):
        bad=copy.deepcopy(proof); mutate(bad); rejects(reason,lambda:q.verify(p,expected,bad,d))
    for bad in (replace(p,identity=1<<42),replace(p,source=v['base']),replace(p,output=p.source),replace(p,repetitions=True)):
        rejects('Spec',lambda:q.derive(bad,d))
    child=v['products']['product']; width=lp.derive(child,d)['layout']['planes']
    rejects('SourceWidth',lambda:q.operand_root(child,[[0]*width+[1]],[q.word(3)]))
    print('requant-consumer controls passed',flush=True)


if __name__=='__main__':
    modes={'--corpus':corpus,'--honest':honest,'--controls':controls,'--sources':source_controls}
    if sys.argv[1:]:
        assert all(x in modes for x in sys.argv[1:])
        for mode in sys.argv[1:]: modes[mode]()
    else:
        for test in (corpus,honest,controls): test()
