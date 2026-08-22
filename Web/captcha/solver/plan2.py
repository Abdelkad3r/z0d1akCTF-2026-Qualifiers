import math, json
from race import Sim, clr, W, H
import plan as P  # reuse profile helpers & CENTER

def plan_hys(cfg, vscale=1.0, look_k=0.12, look_min=8, look_max=26,
             steer_on=0.09, steer_off=0.03, spd_db=6.0):
    prof=P.build_speed_profile(cfg)
    CENTER=P.CENTER
    s=Sim(cfg); inputs=[]; lo=0
    steer=0   # -1 left(4), +1 right(8), 0 straight
    thr=0     # 1 throttle,-1 brake,0 coast
    for tick in range(cfg['max_ticks']):
        if s.finished: break
        lo=P.nearest_ahead(s.x,s.y,lo)
        ld=max(look_min,min(look_max, look_k*s.speed+8))
        ti=P.idx_ahead_dist(lo,ld); tx,ty=CENTER[ti]
        err=P.norm(math.atan2(ty-s.y,tx-s.x)-s.angle)
        vtar=prof[lo]*vscale
        # steering hysteresis
        if steer<=0 and err>steer_on: steer=1
        elif steer>=0 and err<-steer_on: steer=-1
        elif steer==1 and err<steer_off: steer=0
        elif steer==-1 and err>-steer_off: steer=0
        # throttle hysteresis
        if s.speed> vtar+spd_db: thr=-1
        elif s.speed< vtar-spd_db: thr=1
        elif thr==1 and s.speed>=vtar: thr=0
        elif thr==-1 and s.speed<=vtar: thr=0
        inp=0
        if steer<0: inp|=4
        elif steer>0: inp|=8
        # emergency brake if badly off heading & fast
        if abs(err)>0.9 and s.speed>55: thr=-1
        if thr>0: inp|=1
        elif thr<0: inp|=2
        if tick==0: inp|=1; thr=1
        s.step(inp); inputs.append(inp)
        if s.crashed: return None,s,inputs
    return (inputs if s.finished else None),s,inputs

def to_runs(inputs):
    runs=[]
    for v in inputs:
        if runs and runs[-1][0]==v: runs[-1][1]+=1
        else: runs.append([v,1])
    return runs

def best_solution(cfg, verbose=False):
    cands=[]
    for vs in [0.85,0.8,0.75,0.9,0.7,0.65,0.6]:
        for son in [0.10,0.13,0.16]:
            for soff in [0.03,0.05]:
                for lk in [0.10,0.14,0.18]:
                    res,s,_=plan_hys(cfg,vscale=vs,look_k=lk,steer_on=son,steer_off=soff)
                    if res:
                        r=to_runs(res)
                        if len(r)<=cfg['max_runs'] and s.ticks<=cfg['max_ticks']:
                            cands.append((len(r),s.ticks,vs,son,soff,lk,r))
        if cands and min(c[0] for c in cands)<300:
            break
    if not cands: return None
    cands.sort()
    if verbose:
        for c in cands[:5]: print('  runs',c[0],'ticks',c[1],'vs',c[2],'son',c[3],'soff',c[4],'lk',c[5])
    return cands[0]

if __name__=='__main__':
    cfg=json.load(open('nominal_cfg.json')) if False else {
     'width':W,'height':H,'hz':60,'max_ticks':2400,'max_runs':512,
     'start':{'x':572,'y':429,'angle':3.9269908169872414},
     'physics':{'acceleration':99,'braking':320,'friction':60,'maximum_speed':278,'maximum_reverse_speed':90,'steer_rate':4.97,'minimum_steer_speed':10},
     'gates':[{'a':[250,344],'b':[250,386],'normal':[-1,0]},{'a':[245,189],'b':[245,237],'normal':[1,0]},{'a':[689,100],'b':[740,100],'normal':[0,1]},{'a':[481,210],'b':[522,210],'normal':[0,1]},{'a':[670,471],'b':[670,512],'normal':[-1,0]}],
     'finish':{'a':[572,400],'b':[572,459],'normal':[-1,0]}}
    b=best_solution(cfg,verbose=True)
    if b:
        print('BEST runs',b[0],'ticks',b[1],'params vs',b[2],'son',b[3],'soff',b[4],'lk',b[5])
        json.dump(b[6],open('race_runs.json','w'))
    else:
        print('NO SOLUTION')
