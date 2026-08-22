export const RACE_TICK_RATE = 60;
export const RACE_INPUT = Object.freeze({
  THROTTLE: 1,
  BRAKE: 2,
  LEFT: 4,
  RIGHT: 8,
});

const POSITION_PRECISION = 1_000_000;
const MAX_SWEEP_STEP = 2;
const DIRECTION_EPSILON = 0.05;

function quantize(value) {
  return Math.round(value * POSITION_PRECISION) / POSITION_PRECISION;
}

function clamp(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, value));
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value, expectedKeys) {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  return (
    keys.length === expectedKeys.length &&
    expectedKeys.every((key) => Object.hasOwn(value, key))
  );
}

export function raceInputIsValid(input) {
  return (
    Number.isInteger(input) &&
    input >= 0 &&
    input <= 15 &&
    (input & (RACE_INPUT.THROTTLE | RACE_INPUT.BRAKE)) !==
      (RACE_INPUT.THROTTLE | RACE_INPUT.BRAKE) &&
    (input & (RACE_INPUT.LEFT | RACE_INPUT.RIGHT)) !==
      (RACE_INPUT.LEFT | RACE_INPUT.RIGHT)
  );
}

export function inspectRaceTranscript(transcript, config) {
  if (!hasExactKeys(transcript, ["runs"]) || !Array.isArray(transcript.runs)) {
    return null;
  }
  if (transcript.runs.length === 0 || transcript.runs.length > config.max_runs) {
    return null;
  }

  let ticks = 0;
  let previousInput = null;
  for (const run of transcript.runs) {
    if (!Array.isArray(run) || run.length !== 2) return null;
    const [input, runTicks] = run;
    if (
      !raceInputIsValid(input) ||
      !Number.isInteger(runTicks) ||
      runTicks < 1 ||
      runTicks > config.max_ticks ||
      input === previousInput
    ) {
      return null;
    }
    ticks += runTicks;
    if (!Number.isSafeInteger(ticks) || ticks > config.max_ticks) return null;
    previousInput = input;
  }

  if (transcript.runs[0][0] === 0) return null;
  return { ticks };
}

export function raceTranscriptTicks(transcript, config) {
  return inspectRaceTranscript(transcript, config)?.ticks ?? null;
}

export function appendRaceInput(runs, input) {
  if (!raceInputIsValid(input)) {
    throw new TypeError("Invalid race input mask");
  }
  const previous = runs.at(-1);
  if (previous?.[0] === input) {
    previous[1] += 1;
  } else {
    runs.push([input, 1]);
  }
  return runs;
}

export function collisionMaskHasGrass(mask, width, height, x, y) {
  const pixelX = Math.round(x);
  const pixelY = Math.round(y);
  if (
    pixelX < 0 ||
    pixelY < 0 ||
    pixelX >= width ||
    pixelY >= height
  ) {
    return true;
  }
  const index = pixelY * width + pixelX;
  return (mask[index >> 3] & (1 << (index & 7))) !== 0;
}

function sweptPathHitsGrass(mask, width, height, fromX, fromY, toX, toY) {
  const distance = Math.max(Math.abs(toX - fromX), Math.abs(toY - fromY));
  const samples = Math.max(1, Math.ceil(distance / MAX_SWEEP_STEP));
  for (let index = 1; index <= samples; index += 1) {
    const amount = index / samples;
    const x = fromX + (toX - fromX) * amount;
    const y = fromY + (toY - fromY) * amount;
    if (collisionMaskHasGrass(mask, width, height, x, y)) return true;
  }
  return false;
}

function orientation(ax, ay, bx, by, cx, cy) {
  return (bx - ax) * (cy - ay) - (by - ay) * (cx - ax);
}

function segmentsIntersect(ax, ay, bx, by, cx, cy, dx, dy) {
  const first = orientation(ax, ay, bx, by, cx, cy);
  const second = orientation(ax, ay, bx, by, dx, dy);
  const third = orientation(cx, cy, dx, dy, ax, ay);
  const fourth = orientation(cx, cy, dx, dy, bx, by);
  return (
    ((first <= 0 && second >= 0) || (first >= 0 && second <= 0)) &&
    ((third <= 0 && fourth >= 0) || (third >= 0 && fourth <= 0))
  );
}

function crossesGate(fromX, fromY, toX, toY, gate) {
  const movementX = toX - fromX;
  const movementY = toY - fromY;
  const progress = movementX * gate.normal[0] + movementY * gate.normal[1];
  if (progress <= DIRECTION_EPSILON) return false;
  return segmentsIntersect(
    fromX,
    fromY,
    toX,
    toY,
    gate.a[0],
    gate.a[1],
    gate.b[0],
    gate.b[1],
  );
}

export function createRaceState(config) {
  return {
    x: Number(config.start.x),
    y: Number(config.start.y),
    angle: Number(config.start.angle),
    speed: 0,
    angular_velocity: 0,
    gate_index: 0,
    ticks: 0,
    crashed: false,
    finished: false,
    finished_at_tick: null,
  };
}

export function stepRace(state, input, config, collisionMask) {
  if (state.crashed || state.finished) return state;
  if (!raceInputIsValid(input)) {
    return { ...state, crashed: true };
  }

  const dt = 1 / config.hz;
  const physics = config.physics;
  let speed = state.speed;
  let angularVelocity = state.angular_velocity;

  if (input & RACE_INPUT.THROTTLE) {
    speed += physics.acceleration * dt;
  } else if (input & RACE_INPUT.BRAKE) {
    speed -= physics.braking * dt;
  } else if (speed > 0) {
    speed = Math.max(0, speed - physics.friction * dt);
  } else if (speed < 0) {
    speed = Math.min(0, speed + physics.friction * dt);
  }
  speed = clamp(speed, -physics.maximum_reverse_speed, physics.maximum_speed);

  const absoluteSpeed = Math.abs(speed);
  if (absoluteSpeed > physics.minimum_steer_speed) {
    const steerFactor =
      physics.steer_rate *
      clamp(
        1 - absoluteSpeed / (physics.maximum_speed * 1.5),
        0.3,
        1,
      );
    if (input & RACE_INPUT.LEFT) angularVelocity = -steerFactor;
    else if (input & RACE_INPUT.RIGHT) angularVelocity = steerFactor;
    else angularVelocity *= 0.85;
  } else {
    angularVelocity *= 0.7;
  }

  const angle = quantize(
    state.angle + angularVelocity * dt * (speed >= 0 ? 1 : -1),
  );
  const x = quantize(state.x + Math.cos(angle) * speed * dt);
  const y = quantize(state.y + Math.sin(angle) * speed * dt);
  const ticks = state.ticks + 1;
  const crashed = sweptPathHitsGrass(
    collisionMask,
    config.width,
    config.height,
    state.x,
    state.y,
    x,
    y,
  );
  if (crashed) {
    return {
      ...state,
      x,
      y,
      angle,
      speed: 0,
      angular_velocity: quantize(angularVelocity),
      ticks,
      crashed: true,
    };
  }

  let gateIndex = state.gate_index;
  if (
    gateIndex < config.gates.length &&
    crossesGate(state.x, state.y, x, y, config.gates[gateIndex])
  ) {
    gateIndex += 1;
  }

  const finished =
    gateIndex === config.gates.length &&
    crossesGate(state.x, state.y, x, y, config.finish);
  return {
    x,
    y,
    angle,
    speed: quantize(speed),
    angular_velocity: quantize(angularVelocity),
    gate_index: gateIndex,
    ticks,
    crashed: false,
    finished,
    finished_at_tick: finished ? ticks : null,
  };
}

export function replayRace(config, transcript, collisionMask) {
  const inspected = inspectRaceTranscript(transcript, config);
  if (!inspected) return { valid: false, reason: "shape", state: null };
  if (!(collisionMask instanceof Uint8Array)) {
    return { valid: false, reason: "mask", state: null };
  }
  const expectedMaskLength = Math.ceil((config.width * config.height) / 8);
  if (collisionMask.byteLength !== expectedMaskLength) {
    return { valid: false, reason: "mask", state: null };
  }

  let state = createRaceState(config);
  if (
    collisionMaskHasGrass(
      collisionMask,
      config.width,
      config.height,
      state.x,
      state.y,
    )
  ) {
    return { valid: false, reason: "start", state };
  }

  for (const [input, runTicks] of transcript.runs) {
    for (let tick = 0; tick < runTicks; tick += 1) {
      state = stepRace(state, input, config, collisionMask);
      if (state.crashed) return { valid: false, reason: "collision", state };
      if (state.finished && state.ticks !== inspected.ticks) {
        return { valid: false, reason: "padding", state };
      }
    }
  }

  return {
    valid: state.finished && state.finished_at_tick === inspected.ticks,
    reason: state.finished ? null : "incomplete",
    state,
  };
}
