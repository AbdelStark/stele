"""Q26 / Draft RFC-0004 A10: explicit numerical dependencies, not Tensor IR."""
from collections import Counter
from dataclasses import replace
import hashlib
import json
from alignment import round_i16
import model_config as c
import model_functions as functions

TAG=b'stele/research/q26/model-flow/v1\0'
CAPACITY=1<<24
WEIGHTS=('q','k','v','o','up','gate','down')


def derive(p):
    c.require(type(p) is c.Config,'Config'); nodes=[]; seen=set(); t=p.length; d=p.final_norm.d
    refs={name:[name,c.fn.function_id(r.function).hex(),c.fn.representation_id(r).hex()]
          for name,r in functions.selection(p)[0]}
    def add(role,kind,layer,shape,inputs=(),source=b'',function=None,bounds=()):
        c.require(role not in seen and all(v in seen for v in inputs),'Flow')
        node=dict(role=role,kind=kind,layer=layer,shape=list(shape),inputs=list(inputs),
                  source=source.hex(),function=None if function is None else refs[function],bounds=[list(v) for v in bounds])
        nodes.append(node); seen.add(role)
    def physical(role,s,i=-1): add('physical.'+role,'physical',i,s.shape,source=c.r.config(s))
    add('tokens','tokens',-1,(t,)); add('positions','positions',-1,(t,),('tokens',))
    physical('embedding',p.embedding)
    if p.head is not None: physical('head',p.head)
    physical('final_norm',p.gain)
    add('cut.0','embedding',-1,(t,d),('tokens','physical.embedding'),bounds=((1,'embedding'),))
    for i,b in enumerate(p.blocks):
        prefix='layer.'+str(i)+'.'; q=b.projection; hidden=b.weights[4].shape[0]
        for name,s in [('norm1',b.gain1),('norm2',b.gain2),*zip(WEIGHTS,b.weights)]: physical(prefix+name,s,i)
        rotation='rotation.'+str(i)
        add(rotation,'rotation',i,(t,),
            source=b'' if q.rotation is None else c.rope.encode(q.rotation))
        def op(name,kind,shape,inputs,bindings=(),function=None):
            add(prefix+name,kind,i,(t,shape),inputs,function=None if function is None else prefix+function,
                bounds=tuple((family,prefix+role) for family,role in bindings))
        op('norm1','norm1',d,('cut.'+str(i),'physical.'+prefix+'norm1'),((12,'norm1'),),'norm1')
        op('first','first',d,(prefix+'norm1',),((2,'first'),))
        for name,width in [('q',q.heads*q.width),('k',q.groups*q.width),('v',q.groups*q.width)]:
            op(name,name,width,(prefix+'first','physical.'+prefix+name),((1,name),))
        bindings=[(2,v) for v in ('query','key','value','attention')]+[(3,'query'),(3,'key'),
            (6,'attention_sum'),(7,'attention_normalization'),(9,'attention_score'),(10,'attention_max')]
        if q.attention.accumulation=='block1024': bindings.append((8,'attention_block'))
        op('attention','attention',q.heads*q.width,
            tuple(prefix+v for v in ('q','k','v'))+('positions',rotation),bindings,'attention_exp')
        op('o','o',d,(prefix+'attention','physical.'+prefix+'o'),((1,'o'),))
        op('mid','mid',d,('cut.'+str(i),prefix+'o'),((4,'attention_residual'),))
        op('norm2','norm2',d,(prefix+'mid','physical.'+prefix+'norm2'),((12,'norm2'),),'norm2')
        op('second','second',d,(prefix+'norm2',),((2,'second'),))
        for name in ('up','gate'): op(name,name,hidden,(prefix+'second','physical.'+prefix+name),((1,name),))
        op('silu','silu',hidden,(prefix+'gate',),function='silu')
        op('product','product',hidden,(prefix+'up',prefix+'silu'),((11,'gated_product'),))
        op('gated','gated',hidden,(prefix+'product',),((2,'gated'),))
        op('down','down',d,(prefix+'gated','physical.'+prefix+'down'),((1,'down'),))
        add('cut.'+str(i+1),'output',i,(t,d),(prefix+'mid',prefix+'down'),bounds=((4,prefix+'ffn_residual'),))
    add('final_norm','final_norm',-1,(t,d),('cut.'+str(len(p.blocks)),'physical.final_norm'),
        function='final_norm',bounds=((12,'final_norm'),))
    add('final','final',-1,(t,d),('final_norm',),bounds=((2,'final'),))
    add('head','head',-1,(t,p.embedding.shape[0]),('final','physical.embedding' if p.head is None else 'physical.head'),bounds=((1,'head'),))
    add('decoding.greedy','greedy',-1,(t,),('head',),bounds=((5,'decoding.greedy'),))
    bindings=[tuple(v) for n in nodes for v in n['bounds']]
    c.require(len(nodes)==27*len(p.blocks)+9+int(p.head is not None)<=3466,'Flow')
    c.require(len(set(bindings))==len(bindings)==25*len(p.blocks)+5+
              sum(b.projection.attention.accumulation=='block1024' for b in p.blocks),'Flow')
    c.require([n['function'][0] for n in nodes if n['function'] is not None]==list(refs),'Flow')
    return nodes


def _derive(expected_config,config_bytes):
    c.hash32(expected_config); p=c.decode(config_bytes); c.require(c.identity(p)==expected_config,'Identity')
    nodes=derive(p)
    raw=TAG+expected_config+json.dumps(nodes,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    c.require(len(raw)<=CAPACITY,'Capacity'); return p,nodes,raw


def encode(expected_config,config_bytes): return _derive(expected_config,config_bytes)[-1]


def validate(expected_config,config_bytes,supplied):
    c.require(type(supplied) is bytes,'Flow'); c.require(len(supplied)<=CAPACITY,'Capacity')
    c.require(supplied==encode(expected_config,config_bytes),'Flow')


def execute(expected_config,config_bytes,expected_artifact,artifact_bytes,sequence,*,supplied=None):
    """Full public replay from expected data; no supplied evaluator or proof receipt."""
    if supplied is not None: validate(expected_config,config_bytes,supplied)
    _,nodes,_=_derive(expected_config,config_bytes)
    model=c.load(expected_config,config_bytes,expected_artifact,artifact_bytes); m=c.m; b=m.b
    m.tokens(model,sequence)
    # Match the existing full-block numerical workspace guard before evaluation.
    for block in model.blocks:
        q=block.attention
        cells=16*block.norm1.d+16*q.heads*q.width+8*q.groups*q.width+8*len(block.weights[4].codes)+8*q.heads
        c.require(len(sequence)*cells<=1<<22,'Capacity')
    sources={'physical.embedding':model.embedding,'physical.final_norm':model.gains}
    if model.head is not None: sources['physical.head']=model.head
    for i,block in enumerate(model.blocks):
        prefix='physical.layer.'+str(i)+'.'
        sources.update({prefix+'norm1':block.gains1,prefix+'norm2':block.gains2})
        sources.update((prefix+name,w) for name,w in zip(WEIGHTS,block.weights))
    retained={'cut.'+str(i) for i in range(len(model.blocks)+1)}|{'final_norm','final','head','decoding.greedy'}
    uses=Counter(v for n in nodes for v in n['inputs']); values={}
    def run(node,args):
        kind=node['kind']
        layer=None if node['layer']==-1 else model.blocks[node['layer']]
        if kind=='tokens': result=sequence.copy()
        elif kind=='positions': result=list(range(len(args[0])))
        elif kind=='physical': result=sources.pop(node['role'])
        elif kind=='rotation': result=layer.attention.rotations
        elif kind=='embedding':
            tokens,w=args; fraction=model.blocks[0].norm1.F
            result=[[round_i16(x*w.mantissas[t],-w.exponent-fraction) for x in w.codes[t]] for t in tokens]
        elif kind in ('norm1','norm2','final_norm'):
            p=model.final_norm if kind=='final_norm' else getattr(layer,kind)
            result=[b.norm.evaluate(p,row,list(args[1]))['output'] for row in args[0]]
        elif kind in ('first','second','gated','final'):
            if kind=='first': fraction,policy=layer.norm1.E,layer.first
            elif kind=='second': fraction,policy=layer.norm2.E,layer.second
            elif kind=='gated': fraction,policy=layer.fu+layer.silu.params[1],layer.gated
            else: fraction,policy=model.final_norm.E,model.policy
            result=[b.quantize(row,fraction,policy,product=kind=='gated') for row in args[0]]
        elif kind in WEIGHTS+('head',):
            if kind=='head': fraction=model.logits_fraction
            else:
                fraction=dict(q=layer.attention.fq,k=layer.attention.fk,v=layer.attention.attention.fv,
                              o=layer.fo,up=layer.fu,gate=layer.silu.params[0],down=layer.fd)[kind]
            result=[b.linear(args[1],row,fraction) for row in args[0]]
        elif kind=='attention':
            queries,keys,vals,positions,rotations=args; p=replace(layer.attention,rotations=rotations)
            cache=b.pa.prepare(p,positions,keys,vals); result=[]
            for pos,q in zip(positions,queries):
                row=b.pa.query(p,pos,q,cache,[j<=pos for j in positions])
                result.append(b.Row(tuple(row['codes']),row['scale'],p.attention.fo))
        elif kind in ('mid','output'):
            fx,fy,fo=(layer.norm1.F,layer.fo,layer.norm2.F) if kind=='mid' else (layer.norm2.F,layer.fd,layer.fout)
            result=[[b.residual(x,fx,y,fy,fo) for x,y in zip(xs,ys)] for xs,ys in zip(*args)]
        elif kind=='silu': result=[[b.silu(layer.silu,x) for x in row] for row in args[0]]
        elif kind=='product': result=[[x*y for x,y in zip(xs,ys)] for xs,ys in zip(*args)]
        elif kind=='greedy': result=[m.choose(row) for row in args[0]]
        else: raise ValueError('Flow')
        return result

    for node in nodes:
        result=run(node,[values[v] for v in node['inputs']])
        values[node['role']]=result
        for key in node['inputs']:
            uses[key]-=1
            if uses[key]==0 and key not in retained: del values[key]
    c.require(set(values)==retained and not sources,'Flow')
    heads=[dict(normalized=n,input=x,logits=y) for n,x,y in zip(values['final_norm'],values['final'],values['head'])]
    return dict(cuts=[values['cut.'+str(i)] for i in range(len(model.blocks)+1)],heads=heads,selected=values['decoding.greedy'])


def evidence(expected_config,config_bytes):
    _,nodes,raw=_derive(expected_config,config_bytes)
    return dict(model_flow_nodes=len(nodes),model_flow_bytes=len(raw),model_flow_sha256=hashlib.sha256(raw).hexdigest())
