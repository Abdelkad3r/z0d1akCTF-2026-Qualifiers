import math, heapq, json, collections

W,H=800,541
import os
_HERE=os.path.dirname(os.path.abspath(__file__))
def _find(name):
    for c in (name, os.path.join(_HERE,name), os.path.join(_HERE,'..','artifacts',name)):
        if os.path.exists(c): return c
    raise FileNotFoundError(name)
MASK=open(_find('track-mask.bin'),'rb').read()
def grass(x,y):
    xi=int(round(x)); yi=int(round(y))
    if xi<0 or yi<0 or xi>=W or yi>=H: return True
    i=yi*W+xi
    return (MASK[i>>3]>>(i&7))&1

# ---- exact physics port of race-core.js ----
P=1_000_000
def q(v): return round(v*P)/P
def clamp(v,a,b): return max(a,min(b,v))
INPUT={'T':1,'B':2,'L':4,'R':8}
def swept_grass(x0,y0,x1,y1):
    dist=max(abs(x1-x0),abs(y1-y0))
    n=max(1,math.ceil(dist/2))
    for i in range(1,n+1):
        a=i/n
        if grass(x0+(x1-x0)*a, y0+(y1-y0)*a): return True
    return False
def orient(ax,ay,bx,by,cx,cy): return (bx-ax)*(cy-ay)-(by-ay)*(cx-ax)
def seg_int(ax,ay,bx,by,cx,cy,dx,dy):
    f=orient(ax,ay,bx,by,cx,cy); s=orient(ax,ay,bx,by,dx,dy)
    t=orient(cx,cy,dx,dy,ax,ay); u=orient(cx,cy,dx,dy,bx,by)
    return ((f<=0 and s>=0) or (f>=0 and s<=0)) and ((t<=0 and u>=0) or (t>=0 and u<=0))
def crosses(fx,fy,tx,ty,gate):
    mx,my=tx-fx,ty-fy
    prog=mx*gate['normal'][0]+my*gate['normal'][1]
    if prog<=0.05: return False
    return seg_int(fx,fy,tx,ty,gate['a'][0],gate['a'][1],gate['b'][0],gate['b'][1])

class Sim:
    def __init__(s,cfg):
        s.cfg=cfg; st=cfg['start']
        s.x=float(st['x']); s.y=float(st['y']); s.angle=float(st['angle'])
        s.speed=0.0; s.av=0.0; s.gi=0; s.ticks=0; s.crashed=False; s.finished=False; s.fat=None
    def step(s,inp):
        cfg=s.cfg; ph=cfg['physics']; dt=1/cfg['hz']
        speed=s.speed; av=s.av
        if inp&1: speed+=ph['acceleration']*dt
        elif inp&2: speed-=ph['braking']*dt
        elif speed>0: speed=max(0,speed-ph['friction']*dt)
        elif speed<0: speed=min(0,speed+ph['friction']*dt)
        speed=clamp(speed,-ph['maximum_reverse_speed'],ph['maximum_speed'])
        asp=abs(speed)
        if asp>ph['minimum_steer_speed']:
            sf=ph['steer_rate']*clamp(1-asp/(ph['maximum_speed']*1.5),0.3,1)
            if inp&4: av=-sf
            elif inp&8: av=sf
            else: av*=0.85
        else: av*=0.7
        angle=q(s.angle+av*dt*(1 if speed>=0 else -1))
        x=q(s.x+math.cos(angle)*speed*dt); y=q(s.y+math.sin(angle)*speed*dt)
        ticks=s.ticks+1
        if swept_grass(s.x,s.y,x,y):
            s.x,s.y,s.angle,s.speed,s.av,s.ticks,s.crashed=x,y,angle,0,q(av),ticks,True
            return
        gi=s.gi
        if gi<len(cfg['gates']) and crosses(s.x,s.y,x,y,cfg['gates'][gi]): gi+=1
        fin = gi==len(cfg['gates']) and crosses(s.x,s.y,x,y,cfg['finish'])
        s.x,s.y,s.angle,s.speed,s.av,s.gi,s.ticks=x,y,angle,q(speed),q(av),gi,ticks
        if fin: s.finished=True; s.fat=ticks

# ---- clearance field (BFS distance to grass) ----
def clearance_field():
    INF=10**9
    dist=[INF]*(W*H)
    dq=collections.deque()
    for y in range(H):
        row=y*W
        for x in range(W):
            i=row+x
            if (MASK[i>>3]>>(i&7))&1:
                dist[i]=0; dq.append(i)
    while dq:
        i=dq.popleft(); x=i%W; y=i//W; dcur=dist[i]
        for dx,dy in ((1,0),(-1,0),(0,1),(0,-1)):
            nx,ny=x+dx,y+dy
            if 0<=nx<W and 0<=ny<H:
                j=ny*W+nx
                if dist[j]>dcur+1:
                    dist[j]=dcur+1; dq.append(j)
    return dist
CLR=clearance_field()
def clr(x,y):
    xi=int(round(x)); yi=int(round(y))
    if xi<0 or yi<0 or xi>=W or yi>=H: return 0
    return CLR[yi*W+xi]

# ---- Dijkstra centerline between waypoints, hugging center ----
_MAXC=max(c for c in CLR if c<10**9)
def path_between(a,b,cw=10.0):
    (ax,ay),(bx,by)=a,b
    start=ay*W+ax; goal=by*W+bx
    INF=float('inf'); dist={start:0.0}; prev={}; pq=[(0.0,start)]
    while pq:
        d,i=heapq.heappop(pq)
        if i==goal: break
        if d>dist.get(i,INF): continue
        x=i%W; y=i//W
        for dx,dy in ((1,0),(-1,0),(0,1),(0,-1),(1,1),(1,-1),(-1,1),(-1,-1)):
            nx,ny=x+dx,y+dy
            if not(0<=nx<W and 0<=ny<H): continue
            j=ny*W+nx
            if CLR[j]==0: continue
            step=math.hypot(dx,dy)
            cost=step*(1+cw*((_MAXC-CLR[j])/_MAXC)**2)   # strongly prefer center
            nd=d+cost
            if nd<dist.get(j,INF):
                dist[j]=nd; prev[j]=i; heapq.heappush(pq,(nd,j))
    if goal not in prev and goal!=start: return None
    path=[goal]; cur=goal
    while cur!=start: cur=prev[cur]; path.append(cur)
    path.reverse()
    return [(p%W,p//W) for p in path]

WAYPTS=[(572,429),(250,365),(245,213),(714,100),(501,210),(670,491),(572,429)]
def build_centerline():
    full=[]
    for k in range(len(WAYPTS)-1):
        seg=path_between(WAYPTS[k],WAYPTS[k+1])
        if seg is None: raise RuntimeError(f'no path {k}')
        if k>0: seg=seg[1:]
        full+=seg
    return full

def build_and_save():
    cl=build_centerline()
    json.dump(cl,open(os.path.join(_HERE,'..','artifacts','centerline.json'),'w'))
    return cl

if __name__=='__main__':
    cl=build_centerline()
    print('centerline pts',len(cl))
    # sample clearance stats
    cs=[clr(x,y) for x,y in cl]
    print('min clr on path',min(cs),'avg',sum(cs)/len(cs))
    json.dump(cl,open(os.path.join(_HERE,'..','artifacts','centerline.json'),'w'))
