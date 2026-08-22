import math, json
from race import Sim, grass, clr, W, H

import os
_HERE=os.path.dirname(os.path.abspath(__file__))
_CL=os.path.join(_HERE,'..','artifacts','centerline.json')
if not os.path.exists(_CL):
    import race as _r; _r.build_and_save() if hasattr(_r,'build_and_save') else None
CENTER=[tuple(p) for p in json.load(open(_CL))]
N=len(CENTER)

def norm(a):
    while a> math.pi: a-=2*math.pi
    while a<-math.pi: a+=2*math.pi
    return a

# cumulative arc length and tangent
SEGLEN=[0.0]*N
for i in range(1,N):
    SEGLEN[i]=SEGLEN[i-1]+math.hypot(CENTER[i][0]-CENTER[i-1][0],CENTER[i][1]-CENTER[i-1][1])
TOTAL=SEGLEN[-1]

def idx_ahead_dist(i, d):
    target=SEGLEN[i]+d
    j=i
    while j<N-1 and SEGLEN[j]<target: j+=1
    return j

# curvature-limited speed profile along path
def build_speed_profile(cfg):
    ph=cfg['physics']; vmax=ph['maximum_speed']
    # local heading change over ~ look window -> radius estimate
    prof=[vmax]*N
    for i in range(N):
        j=idx_ahead_dist(i,26)
        k=idx_ahead_dist(i,52)
        if k<=i: continue
        ax=CENTER[j][0]-CENTER[i][0]; ay=CENTER[j][1]-CENTER[i][1]
        bx=CENTER[k][0]-CENTER[j][0]; by=CENTER[k][1]-CENTER[j][1]
        if (ax==0 and ay==0) or (bx==0 and by==0): continue
        turn=abs(norm(math.atan2(by,bx)-math.atan2(ay,ax)))
        arc=SEGLEN[k]-SEGLEN[i]
        curv=turn/max(1e-6,arc)   # rad per px
        if curv<1e-4:
            v=vmax
        else:
            r=1.0/curv
            # allow yaw = v/r <= steerFactor(v)*0.75 ; steerFactor ~ sr*clamp(1-v/(vmax*1.5),.3,1)
            # solve iteratively
            v=vmax
            for _ in range(30):
                sf=ph['steer_rate']*max(0.3,min(1,1-v/(vmax*1.5)))
                vmax_corner=sf*0.72*r
                if v<=vmax_corner: break
                v=max(30, v*0.9)
            v=min(v,vmax)
        c=clr(*CENTER[i])
        if c<7: v=min(v,80)
        if c<5: v=min(v,55)
        prof[i]=v
    # backward pass: ensure we can brake in time
    brake=ph['braking']
    for i in range(N-2,-1,-1):
        ds=SEGLEN[i+1]-SEGLEN[i]
        if ds<=0: continue
        # v_i^2 <= v_{i+1}^2 + 2*brake*ds
        allowed=math.sqrt(prof[i+1]**2 + 2*brake*ds)
        prof[i]=min(prof[i],allowed)
    return prof

def nearest_ahead(x,y,lo):
    best=lo; bd=1e18
    hi=min(N, lo+160)
    for i in range(lo,hi):
        dx=CENTER[i][0]-x; dy=CENTER[i][1]-y
        d=dx*dx+dy*dy
        if d<bd: bd=d; best=i
    return best

def plan(cfg, vscale=1.0, look_k=0.16, look_min=9, look_max=30, steer_thresh=0.045):
    prof=build_speed_profile(cfg)
    s=Sim(cfg); inputs=[]; lo=0
    for tick in range(cfg['max_ticks']):
        if s.finished: break
        lo=nearest_ahead(s.x,s.y,lo)
        ld=max(look_min,min(look_max, look_k*s.speed+9))
        ti=idx_ahead_dist(lo,ld)
        tx,ty=CENTER[ti]
        err=norm(math.atan2(ty-s.y,tx-s.x)-s.angle)
        vtar=prof[lo]*vscale
        inp=0
        if err<-steer_thresh: inp|=4
        elif err>steer_thresh: inp|=8
        # throttle logic
        if s.speed> vtar+2:
            inp|=2
        elif s.speed< vtar-2 and abs(err)<0.8:
            inp|=1
        # hard brake if very off heading and moving fast
        if abs(err)>0.9 and s.speed>60: inp=(inp&~1)|2
        if tick==0: inp|=1
        s.step(inp); inputs.append(inp)
        if s.crashed:
            return None, s, inputs
    return (inputs if s.finished else None), s, inputs

def to_runs(inputs):
    runs=[]
    for v in inputs:
        if runs and runs[-1][0]==v: runs[-1][1]+=1
        else: runs.append([v,1])
    return runs

def solve(cfg, verbose=False):
    for vs in [1.0,0.95,0.9,0.85,0.8,0.75,0.7,0.65,0.6]:
        for st in [0.045,0.03,0.06,0.08]:
            res,s,inp=plan(cfg,vs,steer_thresh=st)
            if res:
                runs=to_runs(res)
                if len(runs)<=cfg['max_runs'] and s.ticks<=cfg['max_ticks']:
                    if verbose: print(f'  solved vs={vs} st={st} ticks={s.ticks} runs={len(runs)}')
                    return runs,s
            elif verbose:
                pass
    return None,s

if __name__=='__main__':
    cfg={'width':W,'height':H,'hz':60,'max_ticks':2400,'max_runs':512,
         'start':{'x':572,'y':429,'angle':3.9269908169872414},
         'physics':{'acceleration':99,'braking':320,'friction':60,'maximum_speed':278,'maximum_reverse_speed':90,'steer_rate':4.97,'minimum_steer_speed':10},
         'gates':[{'a':[250,344],'b':[250,386],'normal':[-1,0]},{'a':[245,189],'b':[245,237],'normal':[1,0]},{'a':[689,100],'b':[740,100],'normal':[0,1]},{'a':[481,210],'b':[522,210],'normal':[0,1]},{'a':[670,471],'b':[670,512],'normal':[-1,0]}],
         'finish':{'a':[572,400],'b':[572,459],'normal':[-1,0]}}
    runs,s=solve(cfg,verbose=True)
    if runs:
        print('SOLVED ticks',s.ticks,'runs',len(runs),'gi',s.gi)
        json.dump(runs,open('race_runs.json','w'))
    else:
        res,s2,inp=plan(cfg,0.7)
        print('FAIL gi',s2.gi,'pos',(round(s2.x),round(s2.y)),'crashed',s2.crashed,'ticks',s2.ticks)
