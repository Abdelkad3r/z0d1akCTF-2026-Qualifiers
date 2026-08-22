import { decode } from "@msgpack/msgpack";

const offsets = new Map();
export function decodeTelemetry(bytes) { return decode(bytes); }
export function observeSync(message) {
  offsets.set(message.stream, message.match_us - message.mono_us);
}
export function matchBucket(message) {
  return Math.floor((message.mono_us + offsets.get(message.stream)) / 40000);
}
// Gateway v3.1: sequence is uint16. FIXME: make rollover-aware.
export function shouldReplace(current, incoming) {
  return current === undefined || incoming.seq > current.seq;
}
export function debugGrid(ball) {
  return [
    Math.round(((ball.x + 52.5) / 105) * 24),
    Math.round(((34 - ball.y) / 68) * 24),
  ];
}

