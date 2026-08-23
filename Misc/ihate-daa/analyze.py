#!/usr/bin/env python3
"""Offline structural analysis of a captured ihateDAA graph.

Usage: python3 analyze.py [graph.json] [flag-token]
"""
import collections, json, sys

FLAG_NODE = "uxhqkhii"

def main(path="graph.json", flag_node=FLAG_NODE):
    d = json.load(open(path))
    g, roots = d["graph"], d["roots"]

    nodes = set(g) | {m for v in g.values() for m in v}
    edges = sum(len(v) for v in g.values())
    sinks = [n for n, v in g.items() if not v]

    print(f"roots                : {len(roots)}  {roots}")
    print(f"nodes (crawled)      : {len(g)}")
    print(f"nodes (incl. unseen) : {len(nodes)}")
    print(f"edges                : {edges}")
    print(f"mean out-degree      : {edges/len(g):.3f}")
    print(f"sinks (dead ends)    : {len(sinks)}  ({100*len(sinks)/len(g):.1f}%)")

    outd = collections.Counter(len(v) for v in g.values())
    print("out-degree histogram :", dict(sorted(outd.items())))

    ind = collections.Counter()
    for v in g.values():
        for m in v: ind[m] += 1
    indh = collections.Counter(ind.get(n, 0) for n in g)
    print("in-degree histogram  :", dict(sorted(indh.items())[:10]), "...")
    print(f"max in-degree        : {max(ind.values())}")

    tl = collections.Counter(len(n) for n in g)
    print("token length hist    :", dict(sorted(tl.items())))

    # BFS levels from the six roots
    prev, level = {}, {}
    dq = collections.deque()
    for r in roots:
        prev[r] = None; level[r] = 0; dq.append(r)
    while dq:
        n = dq.popleft()
        for m in g.get(n, []):
            if m not in level:
                level[m] = level[n] + 1; prev[m] = n; dq.append(m)
    lv = collections.Counter(level.values())
    print(f"reachable from roots : {len(level)} / {len(g)}")
    print("BFS level sizes      :", dict(sorted(lv.items())))
    print(f"eccentricity (max)   : {max(level.values())}")

    # cycle / DAG test via iterative colouring
    WHITE, GREY, BLACK = 0, 1, 2
    colour = collections.defaultdict(int)
    back_edges = 0
    for s in g:
        if colour[s] != WHITE: continue
        st = [(s, iter(g.get(s, [])))]; colour[s] = GREY
        while st:
            n, it = st[-1]
            adv = next(it, None)
            if adv is None:
                colour[n] = BLACK; st.pop(); continue
            if colour[adv] == WHITE:
                colour[adv] = GREY; st.append((adv, iter(g.get(adv, []))))
            elif colour[adv] == GREY:
                back_edges += 1
    print(f"back edges (cycles)  : {back_edges}  -> {'DAG' if back_edges==0 else 'has cycles'}")

    if flag_node in level:
        p, n = [], flag_node
        while n is not None: p.append(n); n = prev[n]
        p.reverse()
        print(f"\nflag node            : {flag_node}")
        print(f"shortest depth       : {level[flag_node]} hops from a root")
        print(f"in-degree of flag    : {ind.get(flag_node, 0)}")
        print("shortest path        : " + " -> ".join(p))

if __name__ == "__main__":
    main(*sys.argv[1:])
