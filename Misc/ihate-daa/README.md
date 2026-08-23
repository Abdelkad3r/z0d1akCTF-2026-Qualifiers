# ihateDAA

| Field | Value |
| --- | --- |
| CTF | z0d1akCTF 2026 Qualifiers |
| Category | Miscellaneous |
| Author | TitanCode |
| Points | 149 |
| Solves at time of solving | 62 |
| Flag | `zdk{i_l0Ve_GRaPH_7RAvER5AL_4nd_dyN4mIc_inSTanc35}` |

> The way through my heart is very twisted.
>
> Midnight Sun <3

Instancer handout:

```console
$ curl https://ihate-daa-<instance-id>.chals.z0d1ak.org/
```

The instance solved here was `ihate-daa-aa6e271ba001.chals.z0d1ak.org`.

## Executive Summary

The service exposes a directed graph over HTTP. Each node is addressed by
`/?path=<token>`, and its page renders that node's out-edges as further
`?path=` links. There is no session state, no cookie, and no other route — the
only verb available is "follow an edge".

Four page kinds exist, cleanly separable by `<title>`:

| `<title>` | Meaning | HTTP |
| --- | --- | --- |
| `Which way did the flag go?` | Interior node, 2–5 out-edges | 200 |
| `Dead End` | Sink, renders `nope :(` | 200 |
| `Flag Found` | The single goal node | 200 |
| `Missing Path` | Token not in the graph | 404 |

The title is "ihateDAA" — Design and Analysis of Algorithms — and the challenge
is exactly a first-week DAA exercise weaponised into a service: the graph is
far too large to walk by hand and, critically, **it is cyclic**. Measured on the
captured instance, the graph contains 63,236 back edges and every one of the six
entry points is itself the target of 2–6 incoming edges. A naive recursive
descent without a visited set therefore never terminates — that is the "very
twisted" in the description, and the trap the challenge is built around.

The solution is an ordinary breadth-first search with a global visited set,
parallelised over keep-alive connections. The captured instance turned out to be
**92,358 nodes and 258,532 edges**, with exactly one `Flag Found` node —
`uxhqkhii` — sitting **9 hops** from a root with an **in-degree of 1**. One edge
out of a quarter of a million leads to the flag.

Full traversal took roughly 15 minutes at 32 concurrent workers and returned:

```text
zdk{i_l0Ve_GRaPH_7RAvER5AL_4nd_dyN4mIc_inSTanc35}
```

## Repository Contents

| Path | Purpose | SHA-256 |
| --- | --- | --- |
| [`solve.py`](solve.py) | Threaded BFS solver, stdlib only, takes the instance URL | `866e44e890d40164c4cb11061ca2ce282c729feab2f2dca5992b80f700b9af2b` |
| [`analyze.py`](analyze.py) | Offline structural analysis of a captured graph dump | `10b230218167670acce8ddced6547bc33e991133f3ffb4a033482c419fe3e326` |
| [`mock_instance.py`](mock_instance.py) | Local reimplementation of the service, for verifying `solve.py` after the instance expired | `e263d916f41912c02ce65cb15eb0cdb35895d69924d1ae8fdebb503d4e965a38` |
| [`artifacts/graph.json.gz`](artifacts/graph.json.gz) | Complete captured adjacency list (92,358 nodes) | `9e2b17df57efedab6b3e1be283e4b40a0520877f89bfeccca0342b3f26067026` |
| [`artifacts/graph-analysis.txt`](artifacts/graph-analysis.txt) | `analyze.py` output for the captured instance | `5b5c94e0c3abbc413086de0c4a5dfce5510885fa432df16bab2a9b7b209ddd7c` |
| [`artifacts/solution-path.txt`](artifacts/solution-path.txt) | Annotated shortest root-to-flag path | `32353e5474546d5f9242a70b0cc9a96499c41c4380c9dc40f8ede7f97890595a` |
| [`artifacts/crawl-log.txt`](artifacts/crawl-log.txt) | Live progress log of the traversal | `c879e909840ba20e5af35aae4870a4220174323c04c4aad4d51421a85c4ac687` |
| [`artifacts/pages/flag-node.html`](artifacts/pages/flag-node.html) | Byte-exact capture of the `Flag Found` page | `7da56f586791335f736669d2b7e856ac83200809adb160f6b6f4ca384a28d816` |
| [`artifacts/pages/dead-end-node.html`](artifacts/pages/dead-end-node.html) | Byte-exact capture of a `Dead End` page | `8d4e49215a2f8ce6b7851e54008dfd69125210c685679f765ba9914b56085c36` |

Both Python scripts use only the standard library. There is no downloadable
handout for this challenge — the instancer is the entire attack surface.

## 1. Triage

The landing page is a static list of six entry tokens:

```console
$ curl -s https://ihate-daa-aa6e271ba001.chals.z0d1ak.org/
```

```html
<title>Which way did the flag go?</title>
...
  <div class="card">
    <h1>Which way did the flag go?</h1>
       <p>Choose a path:</p>
       <ul><li><a href="/?path=cvhgfhyvkvq">cvhgfhyvkvq</a></li>
<li><a href="/?path=0ij436dr">0ij436dr</a></li>
<li><a href="/?path=j4vnri8vkp">j4vnri8vkp</a></li>
<li><a href="/?path=zoc67o2n1glo">zoc67o2n1glo</a></li>
<li><a href="/?path=r5nbjixy">r5nbjixy</a></li>
<li><a href="/?path=sbp892mmn8n4gnd">sbp892mmn8n4gnd</a></li></ul>
  </div>
```

Following one of them returns the same shape with a different token set:

```console
$ curl -s 'https://ihate-daa-aa6e271ba001.chals.z0d1ak.org/?path=cvhgfhyvkvq'
```

```html
    <h1>Which way did the flag go?</h1>
       <p>Choose a path:</p>
       <ul><li><a href="/?path=8dcb61q1y">8dcb61q1y</a></li>
<li><a href="/?path=kedvd2uxufq3n7">kedvd2uxufq3n7</a></li>
<li><a href="/?path=jrq70z4u1fdy26j">jrq70z4u1fdy26j</a></li>
<li><a href="/?path=db5b1pw8h4">db5b1pw8h4</a></li>
<li><a href="/?path=30xr18ew">30xr18ew</a></li></ul>
```

Three properties are immediately visible and they determine the whole solve:

1. **`path` names a node, not a route.** It is a single opaque token, not an
   accumulating breadcrumb like `a/b/c`. The server is therefore stateless with
   respect to how you arrived — `/?path=X` always renders the same page.
   Re-visiting a token is idempotent, which is exactly what makes a visited set
   valid.
2. **Tokens are stable within an instance.** The same token returns the same
   children on every request, so the graph can be memoised.
3. **There is no session.** No `Set-Cookie`, no `Authorization`, nothing in the
   response headers beyond stock Express:

```console
$ curl -si https://ihate-daa-aa6e271ba001.chals.z0d1ak.org/ | head -6
HTTP/2 200
content-type: text/html; charset=utf-8
date: Sat, 22 Aug 2026 22:35:00 GMT
etag: W/"392-AAXcJDDTuVAq6IqN3LtFGy0ZNjY"
x-powered-by: Express
content-length: 914
```

With no cookie to carry, the server cannot be tracking traversal state, so the
graph is a pure function of the token. Memoisation is safe.

### 1.1 Ruling out a shortcut

Before committing to a large traversal it is worth confirming there is no side
door. An unknown token produces a distinctive 578-byte page:

```console
$ curl -s 'https://.../?path=nonexistent123'
```

```html
    <h1>Unknown path</h1><p class="muted">This token is not part of the graph.</p>
```

Every other route returns stock Express 404s of 142–148 bytes — clearly a
different handler, so these routes simply do not exist:

```console
$ for r in /flag /api /graph /nodes /source /app.js /index.js /.git/HEAD /debug; do
>   printf "%-14s " "$r"
>   curl -s -o /dev/null -w "%{http_code} %{size_download}\n" "https://.../$r"
> done
/flag          404 143
/api           404 142
/graph         404 144
/nodes         404 144
/source        404 145
/app.js        404 145
/index.js      404 147
/.git/HEAD     404 148
/debug         404 144
```

No source disclosure, no graph dump endpoint, no `.git`. Tokens are base36,
8–15 characters, uniformly distributed across those lengths — roughly 2^41 to
2^77 of keyspace, so guessing the flag token is not viable either. Traversal is
the only way through, which is the point of the challenge.

## 2. Mapping the page kinds

Walking a handful of edges by hand surfaces a second page kind. Some nodes have
no links at all:

```console
$ curl -s 'https://.../?path=q03o42uy'
```

```html
    <h1>Which way did the flag go?</h1><p>nope :(</p><p class="muted">Try a different route.</p>
```

The `<h1>` here is unchanged, so **matching on the body text is fragile**. The
`<title>` element, however, is a clean discriminator — it reads `Dead End` for
sinks and `Which way did the flag go?` for interior nodes. This matters more
than it looks: the string `flag` appears in the `<h1>` of *every* interior page,
so an obvious `if "flag" in body` detector matches all 92,358 nodes and tells
you nothing. (My first crawl did precisely this and reported 100 % "interesting"
nodes.) The solver keys on `<title>` instead:

```python
INTERIOR_TITLE = "Which way did the flag go?"

title_match = TITLE_RE.search(body)
title = title_match.group(1) if title_match else ""
if title not in (INTERIOR_TITLE, "Dead End"):
    flag_match = FLAG_RE.search(body)
    ...
```

Anything that is neither an interior node nor a dead end is, by construction,
the goal.

## 3. Why DFS is the trap

The description — *"The way through my heart is very twisted"* — is a
structural hint, not flavour text. Running a cycle check over the captured
adjacency list settles it:

```text
back edges (cycles)  : 63236  -> has cycles
nodes with in-degree 0: 0
root in-degrees: {'cvhgfhyvkvq': 4, '0ij436dr': 2, 'j4vnri8vkp': 6,
                  'zoc67o2n1glo': 5, 'r5nbjixy': 2, 'sbp892mmn8n4gnd': 5}
self loops: 3
```

This is **not a DAG**. Not a single node has in-degree zero — even the six entry
tokens are reachable from deeper in the graph, and three nodes link directly to
themselves. The consequences:

- A recursive `follow_links()` with no visited set recurses forever (or until
  the interpreter's stack limit) the first time it enters a cycle.
- Iterative deepening, "always take the first link", and random-walk strategies
  all revisit the same subgraphs indefinitely.
- Because there is no session state, there is also no server-side notion of
  "where you have been" to lean on. The visited set has to be yours.

BFS with a global visited set is immune to all of this, and as a bonus its
predecessor map yields the shortest path for free.

## 4. The solver

[`solve.py`](solve.py) is a standard parallel BFS. Three implementation details
carry all the performance:

**Keep-alive connections, one per thread.** 92k nodes over 92k fresh TLS
handshakes is dominated by handshake cost. A `threading.local()` holding a
persistent `HTTPSConnection` per worker amortises this to a single handshake per
thread:

```python
def _conn(self):
    conn = getattr(self._local, "conn", None)
    if conn is None:
        conn = http.client.HTTPSConnection(self.host, context=self.ctx,
                                           timeout=self.timeout)
        self._local.conn = conn
    return conn
```

**Mark-on-enqueue, not mark-on-dequeue.** The visited set is updated at the
moment a token is pushed, inside the same lock that mutates the graph. Marking
on dequeue instead would let several workers enqueue the same token
concurrently, inflating the queue by the branching factor:

```python
with self.lock:
    self.graph[token] = out
    fresh = [t for t in out if t not in self.seen]
    self.seen.update(fresh)
for t in fresh:
    self.queue.put(t)
```

**Retry with reconnect.** A dropped keep-alive connection is a normal event over
a 15-minute crawl. Each request retries up to five times with linear backoff,
discarding the socket first, so a transient failure costs one node's latency
rather than a hole in the graph.

Run it:

```console
$ python3 solve.py https://ihate-daa-<id>.chals.z0d1ak.org -t 32 -o graph.json
```

By default the crawl stops as soon as the flag node is seen. Pass `--full` to
keep going and map the entire graph, which is what produced the artifacts here.

## 5. Traversal results

The frontier behaviour is worth reading, since it shows the search is genuinely
exhaustive and not just lucky. From [`artifacts/crawl-log.txt`](artifacts/crawl-log.txt):

```text
nodes=646    queue=1138      <- frontier growing faster than the visited set
nodes=4109   queue=6691
nodes=19579  queue=22828
nodes=33169  queue=27411     <- queue plateaus: edges start landing on seen nodes
nodes=49584  queue=25401     <- frontier now shrinking
nodes=77432  queue=10997
nodes=92079  queue=188
DONE nodes 92358 special 18497
```

The inflection at roughly 33k nodes is the signature of a finite graph with high
edge reuse: past that point most discovered edges point at already-visited
nodes, the queue drains, and termination is guaranteed.

Final structure, from [`artifacts/graph-analysis.txt`](artifacts/graph-analysis.txt):

| Property | Value |
| --- | --- |
| Entry points (roots) | 6 |
| Nodes | 92,358 |
| Edges | 258,532 |
| Mean out-degree | 2.799 |
| Dead ends (sinks) | 18,497 (20.0 %) |
| Out-degree histogram | `{0: 18497, 2: 18494, 3: 18427, 4: 18493, 5: 18391, 6: 56}` |
| Max in-degree | 12 |
| Token lengths | 8–15, base36, ~11.5k nodes each |
| Back edges | 63,236 (cyclic) |
| BFS eccentricity | 16 |
| Reachable from roots | 92,358 / 92,358 (100 %) |

The out-degree histogram is a giveaway for how the generator works: node degree
is drawn uniformly from `{0, 2, 3, 4, 5}` — roughly 18.4k nodes in each bucket,
and not a single degree-1 node anywhere. Only 56 nodes have out-degree 6, an
outlier of 0.06 % whose origin I did not chase. Every node is reachable from the
roots, so there are no orphaned regions and BFS from the six entry points is
provably complete.

BFS level sizes show the graph is wide rather than deep:

```text
level:   0   1   2    3    4     5     6      7      8      9     10    11   12  13 14 15 16
nodes:   6  24  80  214  613  1682  4429  10989  21817  27376  17399  5948 1389 311 68 11  2
```

Half the graph sits at depth 8–9. The difficulty is branching factor, not
distance — which is why "just click around" fails and why a systematic sweep
succeeds quickly.

## 6. The flag node

Exactly one node out of 92,358 rendered a different title:

```text
special total 18497
18496 'Dead End'
    1 'Flag Found'
```

```console
$ curl -s 'https://.../?path=uxhqkhii'
```

```html
<title>Flag Found</title>
...
  <div class="card">
    <h1>flag:</h1><p><strong>zdk{i_l0Ve_GRaPH_7RAvER5AL_4nd_dyN4mIc_inSTanc35}</strong></p>
  </div>
```

Reconstructing the shortest path from the BFS predecessor map
([`artifacts/solution-path.txt`](artifacts/solution-path.txt)):

```text
   0  /?path=zoc67o2n1glo      root
   1  /?path=g2t4csju91        interior, out-deg 5
   2  /?path=a2yz00tco         interior, out-deg 3
   3  /?path=3hy83x43jgmju     interior, out-deg 4
   4  /?path=yjkyi0w0zmj       interior, out-deg 4
   5  /?path=evxp8rol44        interior, out-deg 3
   6  /?path=hfnuz9lxkcg       interior, out-deg 3
   7  /?path=qu8b4u753mqi56    interior, out-deg 5
   8  /?path=bdv5h1snuatozrr   interior, out-deg 6
   9  /?path=uxhqkhii          FLAG (sink)
```

Nine hops from an entry point — and yet the flag node has **in-degree 1**. Only
`bdv5h1snuatozrr` links to it, one edge out of 258,532. The expected cost of
finding it by uniform random guessing is ~92,358 requests with no memory of
where you have been; the expected cost of finding it by depth-first descent
without a visited set is unbounded, because the walk falls into a cycle first.
Exhaustive BFS finds it in one pass.

```text
zdk{i_l0Ve_GRaPH_7RAvER5AL_4nd_dyN4mIc_inSTanc35}
```

## 7. Reproduction

Against a live instance:

```console
$ python3 solve.py https://ihate-daa-<id>.chals.z0d1ak.org -t 32
[*] roots: ['...', ...]
[*]    10.0s  nodes=  1821  queue=  3129
...
[+] flag node : <token>
[+] depth     : <n> hops from a root
[+] path      : <root> -> ... -> <token>

[+] zdk{i_l0Ve_GRaPH_7RAvER5AL_4nd_dyN4mIc_inSTanc35}
```

Offline, against the captured dump:

```console
$ gunzip -c artifacts/graph.json.gz > graph.json
$ python3 analyze.py graph.json | diff - artifacts/graph-analysis.txt && echo OK
OK
```

`analyze.py` also takes the flag token as an optional second argument, so it
works on any dump: `python3 analyze.py graph.json <flag-token>`.

### 7.1 Verifying the solver without a live instance

The real instance was torn down before this writeup was finished, so
[`mock_instance.py`](mock_instance.py) reimplements the service locally with the
properties that matter — base36 tokens of length 8–15, out-degrees drawn from
`{0, 2, 3, 4, 5}`, edges that point backwards into the root set (so the graph is
genuinely cyclic), one `Flag Found` sink with in-degree 1, and the same four
page kinds:

```console
$ python3 mock_instance.py --port 8731 --nodes 6000 --seed 7 &
[mock] 6000 nodes, 16744 edges, flag at zzpbi781ku

$ python3 solve.py http://127.0.0.1:8731 -t 16 --full
[*] roots: ['001634ed', '0022obxtl', '0022zx8ktyeon', '003aoc5aar', '008jqgtvh', '00gvacu8jrd9p0']
[*] finished in 3.0s, 5536 nodes

[+] flag node : zzpbi781ku
[+] depth     : 9 hops from a root
[+] path      : 00gvacu8jrd9p0 -> mfjb40h0mj5nt8c -> kpcvf5f4mzfe03 -> rxabx1xfk3uwa7f
                -> r75wqena4jzudwu -> 9lyd5mpt2il5hbs -> 0jxtnno1hs -> tyz3szm3
                -> 22jiaud7ir -> zzpbi781ku

[+] zdk{i_l0Ve_GRaPH_7RAvER5AL_4nd_dyN4mIc_inSTanc35}
```

Running `analyze.py` on that dump confirms the mock is cyclic too (3,743 back
edges), so the run genuinely exercises the visited-set logic rather than
accidentally traversing a tree. Note the mock reports 5,536 of 6,000 nodes
reached: with edges sampled uniformly, a few hundred nodes end up unreachable
from the roots. The real service had no such gap — all 92,358 nodes were
reachable.

**Instance caveat.** The instancer regenerates the graph per deployment: the
node tokens, the graph size, the flag node's identity and its depth are all
specific to `ihate-daa-aa6e271ba001`, and that instance was torn down shortly
after the solve (every path on it now returns 404). The tokens and path above
are therefore a record of this solve, not a shortcut for a fresh instance — run
`solve.py` against your own. The flag string itself is constant, and the flag
text `dyN4mIc_inSTanc35` is the author confirming exactly this design.

## 8. Notes and dead ends

- **`"flag" in body` matches everything.** The phrase "Which way did the flag
  go?" is in the `<h1>` of every interior page. The first crawl I ran used that
  as its detector and flagged all 92,358 nodes as interesting. Match on
  `<title>`, or on the literal `zdk{` prefix.
- **Sinks are not the goal.** 20 % of nodes are dead ends rendering `nope :(`.
  A detector of "node with no out-links" produces 18,497 false positives; the
  goal node is also a sink, so out-degree alone cannot separate them. Title does.
- **The 404 handler is a useful oracle.** The 578-byte "Unknown path" page is
  distinguishable from Express's 142-byte "Cannot GET" page, which is how the
  absence of other routes was confirmed without guessing.
- **"Midnight Sun <3"** appears to be a greeting to the Midnight Sun CTF crew
  rather than a technical hint. Nothing in the graph, the tokens, or the
  responses keys off it, and the flag rewards graph traversal only.
- **Politeness.** 32 workers on persistent connections completed the sweep in
  ~15 minutes at roughly 100 requests/second. That is enough to map the graph
  comfortably within a CTF window without hammering a shared instancer; going
  much higher buys little, since the crawl is latency-bound rather than
  throughput-bound.
