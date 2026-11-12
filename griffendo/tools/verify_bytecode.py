# Usage: python3.12 tools/verify_bytecode.py SOURCE.py ORIGINAL.pyc  (used to prove the reconstructed sources match Griffendo.exe)
"""Compare a .py source (compiled with this interpreter) against a .pyc's code object, recursively.
Ignores filename / line numbers / exception table positions; reports first differing code object."""
import marshal, sys, types, dis
def norm_instrs(co):
    out=[]
    for i in dis.get_instructions(co):
        arg = i.argval
        if isinstance(arg, types.CodeType): arg = ("<code>", arg.co_name)
        if isinstance(arg, frozenset): arg = ("frozenset", tuple(sorted(map(repr,arg))))
        if i.opname in ('RESUME','CACHE','NOP'): continue
        # jump targets are offsets: normalize away
        if 'JUMP' in i.opname or i.opname in ('FOR_ITER','SEND','SETUP_FINALLY'): arg=None
        out.append((i.opname, repr(arg)))
    return out
def walk(a,b,path,diffs):
    na,nb=norm_instrs(a),norm_instrs(b)
    if na!=nb:
        for k,(x,y) in enumerate(zip(na,nb)):
            if x!=y:
                diffs.append((path+'/'+a.co_name, k, x, y)); break
        else:
            diffs.append((path+'/'+a.co_name,'len',len(na),len(nb)))
    ca=[c for c in a.co_consts if isinstance(c,types.CodeType)]
    cb=[c for c in b.co_consts if isinstance(c,types.CodeType)]
    if [c.co_name for c in ca]!=[c.co_name for c in cb]:
        diffs.append((path+'/'+a.co_name,'children',[c.co_name for c in ca],[c.co_name for c in cb]))
    for x,y in zip(ca,cb): walk(x,y,path+'/'+a.co_name,diffs)
src,pyc=sys.argv[1],sys.argv[2]
a=compile(open(src).read(),sys.argv[3] if len(sys.argv)>3 else src,'exec')
b=marshal.loads(open(pyc,'rb').read()[16:])
d=[];walk(a,b,'',d)
print('IDENTICAL (modulo line numbers/jump offsets)' if not d else '\n'.join(map(str,d[:40])))
