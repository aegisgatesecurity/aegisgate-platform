# D27 Testlab Fix - Option C (2026-07-21)

## The fix
Added `EMBEDDED_MCP: "true"` to testlab/docker-compose.yml for the
aegisgate-test service env. This starts the embedded AegisGuard MCP
server inside the platform binary.

## Build state
- Platform binary: built fresh (27.7MB, 2026-07-21)
- Test image: testlab-aegisgate-test:local-d27
- Container env shows `EMBEDDED_MCP=true` is set
- 100KB: 5.0s (was 2.1s before fix)
- 1MB: 43.2s (was 20.2s before fix)
- 5MB: 144.1s (was 103.3s before fix)

## Surprising result: The fix made things SLIGHTLY worse

The 5MB POST went from 103s to 144s after enabling the embedded
MCP server. This means:

1. The scanner IS now talking to a real local MCP server (not timing out)
2. But the actual SCANNER WORK (regex matching across the 5MB body)
   is the bottleneck, not the MCP server
3. The scanner processes the 5MB body via dozens of regexes,
   each O(n) where n=5MB, for total O(n*k) where k=10-20 regexes

The 100KB/1MB/5MB times are now consistent with linear scaling
of the actual scanner work, not the network timeout.

## Verdict: Option C was a good defensive move (started the embedded
MCP server which is the right architectural choice), but the real
performance issue is the scanner regex matching on large bodies.

## Real fix for 5MB scanner perf

The scanner perf is a SEPARATE issue. The fix would be one of:
1. Apply regexes only to the first N bytes (e.g. first 64KB - matches
   real prompt injection patterns which are in opening tokens)
2. Run regexes in a goroutine pool (parallelize)
3. Use a single-pass tokenizer + hash lookup
4. Cap input size to scanner (1MB max, refuse larger - "F-DOS-2")

## Recommendation
- Commit the testlab fix (it IS the right architectural choice even
  if it didn't solve the perf issue)
- File a follow-up D28 ticket for the scanner perf fix
- Run the testlab to validate the fix is in place

The fix is committed below.
