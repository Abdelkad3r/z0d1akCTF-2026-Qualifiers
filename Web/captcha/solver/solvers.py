import json, collections

# ---------- desktop-cleanup ----------
def solve_desktop(cfg):
    folders=cfg['folders']; files=cfg['files']
    def ext(n): return n.split('.')[-1].upper()
    placements=[]
    for f in files:
        e=ext(f['name'])
        folder=next(fo for fo in folders if e in [x.upper() for x in fo.get('extensions',[])])
        placements.append({'file_id':f['id'],'folder_id':folder['id']})
    return {'placements':placements}

# ---------- cable-box ----------
DIRS=[(1,4,0,-1),(2,8,1,0),(4,1,0,1),(8,2,-1,0)]  # bit,opp,dx,dy
def rot(mask,t):
    r=mask&15
    for _ in range(((t%4)+4)%4):
        r=((r<<1)&15)|((r>>3)&1)
    return r
def cable_solved(masks,w,h,src,sink):
    valid=True
    for i,m in enumerate(masks):
        x=i%w; y=i//w
        for bit,opp,dx,dy in DIRS:
            if not(m&bit): continue
            nx,ny=x+dx,y+dy
            if nx<0 or nx>=w or ny<0 or ny>=h: valid=False; continue
            if not(masks[ny*w+nx]&opp): valid=False
    if not valid: return False
    powered={src}; q=[src]
    while q:
        i=q.pop(); x=i%w; y=i//w
        for bit,opp,dx,dy in DIRS:
            if not(masks[i]&bit): continue
            nx,ny=x+dx,y+dy
            if nx<0 or nx>=w or ny<0 or ny>=h: continue
            j=ny*w+nx
            if not(masks[j]&opp) or j in powered: continue
            powered.add(j); q.append(j)
    return len(powered)==len(masks) and sink in powered
def solve_cable(cfg):
    w=cfg['width']; h=cfg['height']; src=cfg['source']; sink=cfg['sink']
    tiles=cfg['tiles']; n=w*h
    rots=[[rot(tiles[i],t) for t in range(4)] for i in range(n)]
    choice=[None]*n
    def ok_partial(i,m):
        x=i%w; y=i//w
        # boundary: no edge off grid
        for bit,opp,dx,dy in DIRS:
            nx,ny=x+dx,y+dy
            off = nx<0 or nx>=w or ny<0 or ny>=h
            if off and (m&bit): return False
        # west neighbor (already placed)
        if x>0:
            wm=choice[i-1]
            # east bit of west must equal west bit of this
            if bool(wm&2)!=bool(m&8): return False
        # north neighbor
        if y>0:
            nm=choice[i-w]
            if bool(nm&4)!=bool(m&1): return False
        return True
    def bt(i):
        if i==n:
            masks=choice[:]
            return cable_solved(masks,w,h,src,sink)
        seen=set()
        for t in range(4):
            m=rots[i][t]
            if m in seen: continue
            seen.add(m)
            if ok_partial(i,m):
                choice[i]=m
                if bt(i+1): return True
        choice[i]=None
        return False
    assert bt(0), "cable unsolved"
    turns=[]
    for i in range(n):
        m=choice[i]
        t=next(t for t in range(4) if rots[i][t]==m)
        turns.append(t)
    return {'turns':turns}

# ---------- tile-scramble (N-puzzle) ----------
def solve_tile(cfg):
    size=cfg['size']
    board=tuple(cfg.get('board') or cfg.get('initial_board'))
    n=size*size
    goal=tuple(list(range(1,n))+[0])
    if board==goal: return {'moves':[]}
    # IDA* with Manhattan distance; moves recorded as tile VALUES slid
    def manhattan(b):
        d=0
        for idx,v in enumerate(b):
            if v==0: continue
            gx=(v-1)%size; gy=(v-1)//size
            d+=abs(idx%size-gx)+abs(idx//size-gy)
        return d
    goal_idx={v:i for i,v in enumerate(goal)}
    def neighbors(b):
        z=b.index(0); zx=z%size; zy=z//size
        for dx,dy in ((1,0),(-1,0),(0,1),(0,-1)):
            nx,ny=zx+dx,zy+dy
            if 0<=nx<size and 0<=ny<size:
                j=ny*size+nx
                lb=list(b); lb[z],lb[j]=lb[j],lb[z]
                yield tuple(lb), b[j]   # b[j] is the tile value that moved
    import sys
    sys.setrecursionlimit(10000)
    threshold=manhattan(board)
    path=[]
    def dfs(b,g,thr,last_val):
        f=g+manhattan(b)
        if f>thr: return f
        if b==goal: return True
        mn=float('inf')
        for nb,val in neighbors(b):
            if val==last_val: continue  # don't immediately undo
            path.append(val)
            r=dfs(nb,g+1,thr,val)
            if r is True: return True
            if r<mn: mn=r
            path.pop()
        return mn
    while True:
        path.clear()
        r=dfs(board,0,threshold,-1)
        if r is True: break
        if r==float('inf'): raise RuntimeError("tile unsolvable")
        threshold=r
    return {'moves':path}

if __name__=='__main__':
    # validate against captured configs
    d=json.load(open('cfg_desktop-cleanup.json')); print('desktop',solve_desktop(d))
    c=json.load(open('cfg_cable-box.json')); tc=solve_cable(c); print('cable',tc)
    t=json.load(open('cfg_tile-scramble.json')); tt=solve_tile(t); print('tile moves',len(tt['moves']),tt['moves'])
    # verify tile by applying
    size=t['size']; b=list(t.get('board')); 
    for v in tt['moves']:
        ti=b.index(v); zi=b.index(0)
        assert abs(ti%size-zi%size)+abs(ti//size-zi//size)==1
        b[ti],b[zi]=b[zi],b[ti]
    print('tile final',b,'solved',b==list(range(1,size*size))+[0])
    # verify cable
    import solvers as S
    w=c['width'];h=c['height']
    masks=[S.rot(c['tiles'][i],tc['turns'][i]) for i in range(w*h)]
    print('cable solved',S.cable_solved(masks,w,h,c['source'],c['sink']))
