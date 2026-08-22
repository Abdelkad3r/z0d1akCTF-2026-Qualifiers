const DEFAULT_REQUIRED_CHECKS = 4;

function createClientId() {
  const cryptoApi = globalThis.crypto;
  if (typeof cryptoApi?.randomUUID === "function") return cryptoApi.randomUUID();
  if (typeof cryptoApi?.getRandomValues === "function") {
    const bytes = cryptoApi.getRandomValues(new Uint8Array(16));
    return [...bytes]
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

const elements = {
  connection: document.querySelector("#connection-status"),
  connectionLabel: document.querySelector("#connection-label"),
  completedCount: document.querySelector("#completed-count"),
  requiredCount: document.querySelector("#required-count"),
  timer: document.querySelector("#timer"),
  timerBox: document.querySelector(".timer-box"),
  progress: document.querySelector("#progress"),
  progressBar: document.querySelector("#progress-bar"),
  notice: document.querySelector("#system-notice"),
  noticeTitle: document.querySelector("#system-notice-title"),
  noticeCopy: document.querySelector("#system-notice-copy"),
  challengeTitle: document.querySelector("#challenge-title"),
  instructions: document.querySelector("#challenge-instructions"),
  checkStatus: document.querySelector("#check-status"),
  challengeMount: document.querySelector("#challenge-mount"),
  feedback: document.querySelector("#challenge-feedback"),
  verifyButton: document.querySelector("#verify-button"),
  continueButton: document.querySelector("#continue-button"),
  expiredPanel: document.querySelector("#expired-panel"),
  restartButton: document.querySelector("#restart-button"),
  flagResult: document.querySelector("#flag-result"),
  flagValue: document.querySelector("#flag-value"),
};

const runtime = {
  instanceId: createClientId(),
  clientId: null,
  clientIds: [],
  syncChannel: null,
  registration: null,
  connections: new Map(),
  state: null,
  serverClockDelta: 0,
  transcript: null,
  transcriptReady: false,
  ownCompleted: false,
  submitting: false,
  registering: false,
  advancing: false,
  restarting: false,
  registrationEpoch: 0,
  pendingRetry: null,
  pendingRetryTranscript: null,
  registrationTimer: null,
  advanceTimer: null,
  transitionAttemptId: null,
  challengeCleanup: null,
  challengeComplete: null,
};

class ApiError extends Error {
  constructor(response, data) {
    super(data?.error || `Request failed with status ${response.status}`);
    this.name = "ApiError";
    this.status = response.status;
    this.data = data;
  }
}

function element(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(options)) {
    if (key === "className") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key === "attributes") {
      for (const [name, attributeValue] of Object.entries(value)) {
        node.setAttribute(name, String(attributeValue));
      }
    } else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else {
      node[key] = value;
    }
  }
  for (const child of Array.isArray(children) ? children : [children]) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function delay(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function serverNow() {
  return Date.now() + runtime.serverClockDelta;
}

function setConnection(label, tone = "muted") {
  elements.connection.dataset.tone = tone;
  elements.connectionLabel.textContent = label;
}

function showNotice(title, copy, tone = "info") {
  elements.noticeTitle.textContent = title;
  elements.noticeCopy.textContent = copy;
  elements.notice.dataset.tone = tone;
  elements.notice.hidden = false;
}

function hideNotice() {
  elements.notice.hidden = true;
}

function setFeedback(copy, tone = "muted") {
  elements.feedback.textContent = copy;
  elements.feedback.dataset.tone = tone;
}

function setCheckStatus(label, tone = "wait") {
  elements.checkStatus.textContent = label;
  elements.checkStatus.dataset.tone = tone;
}

function clearStoredFlag() {
  try {
    sessionStorage.removeItem("captcha.result");
  } catch {
    // Storage is an optional reload convenience, not part of verification.
  }
  elements.flagResult.hidden = true;
  elements.flagValue.textContent = "";
  updateActionAvailability();
}

function showFlagResult(flag, scroll = true) {
  elements.flagValue.textContent = flag;
  elements.flagResult.hidden = false;
  try {
    sessionStorage.setItem("captcha.result", flag);
  } catch {
    // The unlocked result still remains visible for this page lifetime.
  }
  setConnection("Complete", "success");
  updateActionAvailability();
  if (scroll) {
    elements.flagResult.scrollIntoView({ behavior: "auto", block: "nearest" });
  }
}

function restoreStoredFlag() {
  let flag = null;
  try {
    flag = sessionStorage.getItem("captcha.result");
  } catch {
    flag = null;
  }
  if (flag) {
    runtime.challengeCleanup?.();
    runtime.challengeCleanup = null;
    runtime.transcript = null;
    runtime.transcriptReady = false;
    runtime.ownCompleted = true;
    elements.challengeTitle.textContent = "Verification complete";
    elements.instructions.textContent = "All checks have been accepted.";
    elements.challengeMount.replaceChildren(
      element("p", { text: "No further action is required." }),
    );
    elements.challengeMount.inert = true;
    elements.challengeMount.dataset.complete = "true";
    elements.challengeMount.setAttribute("aria-busy", "false");
    setCheckStatus("DONE", "success");
    setFeedback("Access granted.", "success");
    showFlagResult(flag, false);
  }
  return Boolean(flag);
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers);
  let body = options.body;
  if (body !== undefined && typeof body !== "string") {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(body);
  }
  const response = await fetch(path, {
    ...options,
    headers,
    body,
    credentials: "same-origin",
    cache: "no-store",
  });
  const raw = await response.text();
  let data = null;
  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch {
      data = { error: raw };
    }
  }
  if (!response.ok) throw new ApiError(response, data);
  return data;
}

async function establishClientIdentity() {
  let candidates = [];
  try {
    const stored = JSON.parse(sessionStorage.getItem("captcha.clients") ?? "[]");
    if (Array.isArray(stored)) {
      candidates = stored.filter(
        (value) => typeof value === "string" && value.length >= 8,
      );
    }
  } catch {
    candidates = [];
  }
  const legacyCandidate = sessionStorage.getItem("captcha.client");
  if (candidates.length === 0 && legacyCandidate) candidates = [legacyCandidate];
  if (candidates.length === 0) candidates = [createClientId()];

  function useCandidates(values) {
    runtime.clientIds = [...values];
    runtime.clientId = runtime.clientIds.at(-1);
    sessionStorage.setItem("captcha.clients", JSON.stringify(runtime.clientIds));
    sessionStorage.setItem("captcha.client", runtime.clientId);
  }

  useCandidates(candidates);

  if (!("BroadcastChannel" in window)) {
    return;
  }

  const syncChannel = new BroadcastChannel("captcha-client-sync");
  runtime.syncChannel = syncChannel;
  let duplicated = false;

  syncChannel.addEventListener("message", (event) => {
    const message = event.data;
    if (!message || message.instance_id === runtime.instanceId) return;
    if (message.type === "reset" && message.state) {
      moveToNewAttempt(message.state);
      return;
    }
    if (message.type === "probe" && message.client_id === runtime.clientId) {
      syncChannel.postMessage({
        type: "occupied",
        target_instance_id: message.instance_id,
        client_id: runtime.clientId,
        instance_id: runtime.instanceId,
      });
    }
    if (
      message.type === "occupied" &&
      message.target_instance_id === runtime.instanceId &&
      message.client_id === runtime.clientId
    ) {
      duplicated = true;
    }
  });

  syncChannel.postMessage({
    type: "probe",
    client_id: runtime.clientId,
    instance_id: runtime.instanceId,
  });
  await delay(120);
  if (duplicated) {
    useCandidates([createClientId()]);
  }
}

function persistClientIds() {
  sessionStorage.setItem("captcha.clients", JSON.stringify(runtime.clientIds));
  if (runtime.clientId) {
    sessionStorage.setItem("captcha.client", runtime.clientId);
  }
}

function resetClientChain() {
  const clientId = createClientId();
  runtime.clientIds = [clientId];
  runtime.clientId = clientId;
  persistClientIds();
}

function appendClientId() {
  const clientId = createClientId();
  runtime.clientIds.push(clientId);
  runtime.clientId = clientId;
  persistClientIds();
  return clientId;
}

function removeClientId(clientId) {
  runtime.clientIds = runtime.clientIds.filter((value) => value !== clientId);
  runtime.clientId = runtime.clientIds.at(-1) ?? null;
  persistClientIds();
}

function updateClock(state) {
  if (Number.isFinite(state?.server_now)) {
    runtime.serverClockDelta = state.server_now - Date.now();
  }
}

function remainingMilliseconds() {
  if (!runtime.state?.deadline_at) return 10_000;
  return Math.max(0, runtime.state.deadline_at - serverNow());
}

function attemptIsRunning() {
  return runtime.state?.status === "running" && remainingMilliseconds() > 0;
}

function updateActionAvailability() {
  elements.verifyButton.disabled =
    !runtime.transcriptReady ||
    runtime.submitting ||
    Boolean(runtime.pendingRetry) ||
    runtime.ownCompleted ||
    !attemptIsRunning();

  const canContinue =
    runtime.state?.ready_to_continue &&
    (attemptIsRunning() || runtime.state?.status === "unlocked");
  elements.continueButton.disabled =
    runtime.submitting || !canContinue || !elements.flagResult.hidden;

}

function renderTimer() {
  const remaining = remainingMilliseconds();
  const seconds = Math.ceil(remaining / 1_000);
  const minutesPart = String(Math.floor(seconds / 60)).padStart(2, "0");
  const secondsPart = String(seconds % 60).padStart(2, "0");
  elements.timer.textContent = `${minutesPart}:${secondsPart}`;
  elements.timerBox.dataset.urgent = String(seconds <= 10 && seconds > 0);

  if (
    runtime.state?.deadline_at &&
    remaining <= 0 &&
    runtime.state.status !== "unlocked"
  ) {
    elements.expiredPanel.hidden = false;
    elements.verifyButton.disabled = true;
    elements.continueButton.disabled = true;
    elements.challengeMount.inert = true;
    runtime.challengeCleanup?.();
    runtime.challengeCleanup = null;
    setConnection("Expired", "danger");
    setCheckStatus("EXPIRED", "wait");
  } else if (runtime.state?.status === "unlocked") {
    elements.expiredPanel.hidden = true;
  }
}

function renderState(state) {
  if (!state) return;
  const previousAttemptId = runtime.state?.attempt_id;
  runtime.state = state;
  updateClock(state);

  const completed = state.completed_checks ?? 0;
  const required = state.required_checks ?? DEFAULT_REQUIRED_CHECKS;
  elements.completedCount.textContent = String(completed);
  elements.requiredCount.textContent = String(required);
  elements.progress.setAttribute("aria-valuemax", String(required));
  elements.progress.setAttribute("aria-valuenow", String(completed));
  elements.progressBar.style.width = `${required > 0 ? (completed / required) * 100 : 0}%`;

  if (state.status === "expired") {
    elements.expiredPanel.hidden = false;
  } else if (state.status !== "unlocked") {
    elements.expiredPanel.hidden = true;
  }

  renderTimer();
  updateActionAvailability();

  if (
    runtime.registration &&
    previousAttemptId &&
    state.attempt_id &&
    state.attempt_id !== runtime.registration.attempt_id
  ) {
    moveToNewAttempt(state);
  }
}

function resetChallengeSurface() {
  runtime.challengeCleanup?.();
  runtime.challengeCleanup = null;
  runtime.transcript = null;
  runtime.transcriptReady = false;
  runtime.ownCompleted = false;
  elements.challengeTitle.textContent = "Loading check...";
  elements.instructions.textContent = "Please wait while your check is loaded.";
  elements.challengeMount.replaceChildren(
    element("p", { className: "loading", text: "Loading..." }),
  );
  elements.challengeMount.inert = false;
  elements.challengeMount.dataset.complete = "false";
  elements.challengeMount.setAttribute("aria-busy", "true");
  setFeedback("Connecting to server...");
  setCheckStatus("WAIT");
  updateActionAvailability();
}

function setTranscript(transcript, ready = true) {
  runtime.transcript = transcript;
  runtime.transcriptReady = ready;
  setCheckStatus(ready ? "READY" : "OPEN", ready ? "ready" : "wait");
  updateActionAvailability();
}

function markOwnCheckComplete() {
  runtime.ownCompleted = true;
  runtime.challengeComplete?.();
  elements.challengeMount.inert = true;
  elements.challengeMount.dataset.complete = "true";
  setCheckStatus("DONE", "success");
  setFeedback("Check complete.", "success");
  updateActionAvailability();
}

function renderDesktopCleanup(config) {
  const root = element("div", { className: "cleanup-game" });
  const files = Array.isArray(config.files) ? config.files : [];
  const folders = Array.isArray(config.folders) ? config.folders : [];
  const placements = new Map();
  const fileButtons = new Map();
  const contentNodes = new Map();
  let selectedFileId = null;

  const fileArea = element("div", {
    className: "cleanup-files",
    attributes: { "aria-label": "Files to sort" },
  });
  const folderArea = element("div", {
    className: "cleanup-folders",
    attributes: { "aria-label": "Destination folders" },
  });

  function extensionOf(name) {
    return String(name).split(".").at(-1).toUpperCase();
  }

  function refreshSelection() {
    for (const [fileId, button] of fileButtons) {
      button.setAttribute("aria-pressed", String(fileId === selectedFileId));
    }
  }

  function placeFile(fileId, folderId) {
    if (!fileId || placements.has(fileId)) return;
    const file = files.find(({ id }) => id === fileId);
    const folder = folders.find(({ id }) => id === folderId);
    if (!file || !folder) return;
    const accepted = (folder.extensions ?? []).map((value) => String(value).toUpperCase());
    if (!accepted.includes(extensionOf(file.name))) {
      setFeedback(`${file.name} does not belong there.`, "danger");
      return;
    }

    placements.set(file.id, folder.id);
    selectedFileId = null;
    const button = fileButtons.get(file.id);
    if (button) button.disabled = true;
    const names = files
      .filter((candidate) => placements.get(candidate.id) === folder.id)
      .map(({ name }) => name);
    const content = contentNodes.get(folder.id);
    if (content) content.textContent = names.join(", ") || "Empty";
    refreshSelection();

    const transcript = {
      placements: [...placements].map(([placedFileId, placedFolderId]) => ({
        file_id: placedFileId,
        folder_id: placedFolderId,
      })),
    };
    const complete = placements.size === files.length && files.length > 0;
    setTranscript(transcript, complete);
    setFeedback(
      complete
        ? "All files are sorted. Click Check answer."
        : `${file.name} moved to ${folder.label}.`,
      complete ? "success" : "muted",
    );
  }

  for (const file of files) {
    const button = element(
      "button",
      {
        className: "file-button",
        attributes: {
          type: "button",
          "aria-pressed": "false",
          draggable: "true",
        },
        onclick: () => {
          if (button.disabled) return;
          selectedFileId = selectedFileId === file.id ? null : file.id;
          refreshSelection();
          setFeedback(selectedFileId ? `${file.name} selected. Choose a folder.` : "Selection cleared.");
        },
      },
      [
        element("span", { className: "file-icon", attributes: { "aria-hidden": "true" } }),
        element("span", { className: "file-name", text: file.name }),
      ],
    );
    button.addEventListener("dragstart", (event) => {
      event.dataTransfer?.setData("text/plain", file.id);
    });
    fileButtons.set(file.id, button);
    fileArea.append(button);
  }

  for (const folder of folders) {
    const contents = element("p", { className: "folder-contents", text: "Empty" });
    contentNodes.set(folder.id, contents);
    const button = element(
      "button",
      {
        className: "folder-button",
        attributes: { type: "button" },
        onclick: () => placeFile(selectedFileId, folder.id),
      },
      [
        element("span", { className: "folder-icon", attributes: { "aria-hidden": "true" } }),
        element("span", { className: "folder-label" }, [
          element("strong", { text: folder.label }),
          element("small", { text: (folder.extensions ?? []).join(" / ") }),
        ]),
        contents,
      ],
    );
    button.addEventListener("dragover", (event) => event.preventDefault());
    button.addEventListener("drop", (event) => {
      event.preventDefault();
      placeFile(event.dataTransfer?.getData("text/plain"), folder.id);
    });
    folderArea.append(button);
  }

  root.append(fileArea, folderArea);
  setTranscript({ placements: [] }, false);
  setFeedback("Choose a file, then choose a folder.");
  return root;
}

const CABLE_DIRECTIONS = Object.freeze([
  Object.freeze({ bit: 1, opposite: 4, dx: 0, dy: -1, name: "north" }),
  Object.freeze({ bit: 2, opposite: 8, dx: 1, dy: 0, name: "east" }),
  Object.freeze({ bit: 4, opposite: 1, dx: 0, dy: 1, name: "south" }),
  Object.freeze({ bit: 8, opposite: 2, dx: -1, dy: 0, name: "west" }),
]);

function rotateCableMask(mask, turns) {
  let result = mask & 15;
  const normalized = ((turns % 4) + 4) % 4;
  for (let index = 0; index < normalized; index += 1) {
    result = ((result << 1) & 15) | ((result >> 3) & 1);
  }
  return result;
}

function inspectCable(masks, width, height, source) {
  let valid = true;
  for (let index = 0; index < masks.length; index += 1) {
    const x = index % width;
    const y = Math.floor(index / width);
    for (const direction of CABLE_DIRECTIONS) {
      if ((masks[index] & direction.bit) === 0) continue;
      const nextX = x + direction.dx;
      const nextY = y + direction.dy;
      if (nextX < 0 || nextX >= width || nextY < 0 || nextY >= height) {
        valid = false;
        continue;
      }
      const nextIndex = nextY * width + nextX;
      if ((masks[nextIndex] & direction.opposite) === 0) valid = false;
    }
  }

  const powered = new Set([source]);
  const queue = [source];
  while (queue.length > 0) {
    const index = queue.shift();
    const x = index % width;
    const y = Math.floor(index / width);
    for (const direction of CABLE_DIRECTIONS) {
      if ((masks[index] & direction.bit) === 0) continue;
      const nextX = x + direction.dx;
      const nextY = y + direction.dy;
      if (nextX < 0 || nextX >= width || nextY < 0 || nextY >= height) continue;
      const nextIndex = nextY * width + nextX;
      if ((masks[nextIndex] & direction.opposite) === 0 || powered.has(nextIndex)) continue;
      powered.add(nextIndex);
      queue.push(nextIndex);
    }
  }
  return { valid, powered };
}

function cableDescription(mask) {
  const exits = CABLE_DIRECTIONS
    .filter(({ bit }) => (mask & bit) !== 0)
    .map(({ name }) => name);
  return exits.length > 0 ? exits.join(" and ") : "no exits";
}

function renderCableBox(config) {
  const width = Number(config.width) || 4;
  const height = Number(config.height) || 4;
  const source = Number.isInteger(config.source) ? config.source : 0;
  const sink = Number.isInteger(config.sink) ? config.sink : width * height - 1;
  const initialTiles = Array.isArray(config.tiles) ? [...config.tiles] : [];
  const turns = Array.from({ length: initialTiles.length }, () => 0);
  const root = element("div", { className: "cable-game" });
  const grid = element("div", {
    className: "cable-grid",
    attributes: { role: "group", "aria-label": "Cable box" },
  });
  grid.style.gridTemplateColumns = `repeat(${width}, 54px)`;
  const buttons = [];

  const resetButton = element("button", {
    className: "btn btn-default",
    text: "Reset",
    attributes: { type: "button" },
  });
  const toolbar = element("div", { className: "cable-toolbar" }, [
    element("p", { className: "game-note", text: "Click to rotate. Shift-click rotates the other way." }),
    resetButton,
  ]);

  function render() {
    const masks = initialTiles.map((mask, index) => rotateCableMask(mask, turns[index]));
    const { valid, powered } = inspectCable(masks, width, height, source);
    const solved = valid && powered.size === masks.length && powered.has(sink);
    masks.forEach((mask, index) => {
      const button = buttons[index];
      if (!button) return;
      button.dataset.maskN = String((mask & 1) !== 0);
      button.dataset.maskE = String((mask & 2) !== 0);
      button.dataset.maskS = String((mask & 4) !== 0);
      button.dataset.maskW = String((mask & 8) !== 0);
      button.dataset.powered = String(powered.has(index));
      const endpoint =
        index === source ? ", modem" : index === sink ? ", server" : "";
      button.setAttribute(
        "aria-label",
        `row ${Math.floor(index / width) + 1}, column ${(index % width) + 1}, exits ${cableDescription(mask)}${endpoint}, ${powered.has(index) ? "connected" : "disconnected"}`,
      );
    });
    setTranscript({ turns: [...turns] }, solved);
    setFeedback(
      solved
        ? "The network is connected. Click Check answer."
        : `${powered.size} of ${masks.length} boxes connected.`,
      solved ? "success" : "muted",
    );
  }

  function turn(index, amount) {
    turns[index] = (turns[index] + amount + 4) % 4;
    render();
  }

  for (let index = 0; index < initialTiles.length; index += 1) {
    const button = element(
      "button",
      {
        className: "cable-tile",
        attributes: {
          type: "button",
          tabindex: index === 0 ? "0" : "-1",
        },
      },
      [
        element("span", { className: "wire n", attributes: { "aria-hidden": "true" } }),
        element("span", { className: "wire e", attributes: { "aria-hidden": "true" } }),
        element("span", { className: "wire s", attributes: { "aria-hidden": "true" } }),
        element("span", { className: "wire w", attributes: { "aria-hidden": "true" } }),
        element("span", { className: "wire-core", attributes: { "aria-hidden": "true" } }),
        index === source || index === sink
          ? element("span", {
              className: "endpoint-mark",
              text: index === source ? "IN" : "OUT",
              attributes: { "aria-hidden": "true" },
            })
          : null,
      ],
    );
    button.addEventListener("click", (event) => turn(index, event.shiftKey ? -1 : 1));
    button.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        turn(index, event.shiftKey ? -1 : 1);
        return;
      }
      const x = index % width;
      const y = Math.floor(index / width);
      const target =
        event.key === "ArrowLeft" && x > 0
          ? index - 1
          : event.key === "ArrowRight" && x < width - 1
            ? index + 1
            : event.key === "ArrowUp" && y > 0
              ? index - width
              : event.key === "ArrowDown" && y < height - 1
                ? index + width
                : null;
      if (target === null) return;
      event.preventDefault();
      button.setAttribute("tabindex", "-1");
      buttons[target].setAttribute("tabindex", "0");
      buttons[target].focus();
    });
    buttons.push(button);
    grid.append(button);
  }

  resetButton.addEventListener("click", () => {
    turns.fill(0);
    render();
  });
  root.append(toolbar, element("div", { className: "board-scroll" }, grid));
  render();
  return root;
}

function renderTileScramble(config) {
  const size = Number(config.size) || 4;
  const initialBoard = Array.isArray(config.board)
    ? [...config.board]
    : Array.isArray(config.initial_board)
      ? [...config.initial_board]
      : [];
  let board = [...initialBoard];
  let moves = [];
  const root = element("div", { className: "sliding-game" });
  const counter = element("p", { className: "game-note", text: "Moves: 0" });
  const grid = element("div", {
    className: "sliding-grid",
    attributes: { role: "group", "aria-label": "Number tile puzzle" },
  });
  grid.style.gridTemplateColumns = `repeat(${size}, 62px)`;
  const resetButton = element("button", {
    className: "btn btn-default",
    text: "Reset",
    attributes: { type: "button" },
  });

  function isSolved() {
    return board.every((value, index) =>
      index === board.length - 1 ? value === 0 : value === index + 1,
    );
  }

  function moveTile(value) {
    if (moves.length >= 80) {
      setFeedback("Move limit reached. Reset the puzzle and try again.", "danger");
      return;
    }
    const tileIndex = board.indexOf(value);
    const blankIndex = board.indexOf(0);
    if (tileIndex < 0 || blankIndex < 0) return;
    const tileX = tileIndex % size;
    const tileY = Math.floor(tileIndex / size);
    const blankX = blankIndex % size;
    const blankY = Math.floor(blankIndex / size);
    if (Math.abs(tileX - blankX) + Math.abs(tileY - blankY) !== 1) {
      setFeedback("That tile cannot move.", "danger");
      return;
    }
    [board[tileIndex], board[blankIndex]] = [board[blankIndex], board[tileIndex]];
    moves.push(value);
    render(value);
  }

  function render(focusValue = null) {
    grid.replaceChildren();
    let focusTarget = null;
    board.forEach((value, index) => {
      if (value === 0) {
        grid.append(
          element("span", {
            className: "sliding-blank",
            attributes: {
              role: "img",
              "aria-label": `blank, row ${Math.floor(index / size) + 1}, column ${(index % size) + 1}`,
            },
          }),
        );
        return;
      }
      const button = element("button", {
          className: "sliding-tile",
          text: String(value),
          attributes: {
            type: "button",
            "aria-label": `tile ${value}, row ${Math.floor(index / size) + 1}, column ${(index % size) + 1}`,
          },
          onclick: () => moveTile(value),
        });
      if (value === focusValue) focusTarget = button;
      grid.append(button);
    });
    const solved = board.length > 0 && isSolved();
    counter.textContent = `Moves: ${moves.length}`;
    setTranscript({ moves: [...moves] }, solved);
    setFeedback(
      solved
        ? "Picture restored. Click Check answer."
        : `Arrange the numbers from 1 to ${Math.max(1, board.length - 1)}.`,
      solved ? "success" : "muted",
    );
    focusTarget?.focus();
  }

  resetButton.addEventListener("click", () => {
    board = [...initialBoard];
    moves = [];
    render();
  });
  root.append(
    element("div", { className: "puzzle-toolbar" }, [counter, resetButton]),
    element("div", { className: "board-scroll" }, grid),
  );
  render();
  return root;
}

function renderRaceLap(config, registration) {
  const root = element("div", {
    className: "race-game",
    dataset: { ready: "false", phase: "loading" },
    attributes: {
      tabindex: "0",
      role: "group",
      "aria-label": "Race lap. Focus here and use the arrow keys or W A S D to drive.",
    },
  });
  const canvas = element("canvas", {
    className: "race-canvas",
    attributes: {
      width: "800",
      height: "541",
      role: "img",
      "aria-label": "Top-down race track with one player car",
    },
  });
  canvas.textContent = "A browser with canvas support is required for this check.";
  const stageMessage = element(
    "div",
    {
      className: "race-stage-message",
      attributes: { role: "status", "aria-live": "polite" },
    },
    [
      element("strong", { text: "Loading track..." }),
      element("span", { text: "Please wait." }),
    ],
  );
  const stage = element("div", { className: "race-stage" }, [canvas, stageMessage]);

  const lapValue = element("span", { className: "race-hud-value", text: "0 / 1" });
  const checkpointValue = element("span", { className: "race-hud-value", text: "0 / 0" });
  const timeValue = element("span", { className: "race-hud-value", text: "00:00.00" });
  const speedValue = element("span", { className: "race-hud-value", text: "0 km/h" });
  const hud = element("div", { className: "race-hud", attributes: { "aria-label": "Race status" } });
  for (const [label, value] of [
    ["Lap", lapValue],
    ["Checkpoint", checkpointValue],
    ["Time", timeValue],
    ["Speed", speedValue],
  ]) {
    hud.append(
      element("div", { className: "race-hud-cell" }, [
        element("span", { className: "race-hud-label", text: label }),
        value,
      ]),
    );
  }

  const startButton = element("button", {
    className: "btn btn-primary",
    text: "Start race",
    attributes: { type: "button", disabled: "" },
  });
  const help = element("p", {
    className: "race-help",
    text: "Complete one lap without leaving the track. Use the buttons, arrow keys, or W A S D.",
  });
  const actionCopy = element("div", { className: "race-action-copy" }, [startButton, help]);
  const driveControls = element("div", {
    className: "race-drive-controls",
    attributes: { "aria-label": "Drive controls" },
  });
  const controlButtons = new Map();
  for (const [name, label, copy] of [
    ["up", "Accelerate", "↑ Gas"],
    ["left", "Steer left", "← Left"],
    ["down", "Brake", "↓ Brake"],
    ["right", "Steer right", "→ Right"],
  ]) {
    const button = element("button", {
      className: "btn btn-default race-control",
      text: copy,
      dataset: { control: name },
      attributes: {
        type: "button",
        "aria-label": label,
        "aria-pressed": "false",
        disabled: "",
      },
    });
    controlButtons.set(name, button);
    driveControls.append(button);
  }
  const toolbar = element("div", { className: "race-toolbar" }, [actionCopy, driveControls]);
  root.append(hud, stage, toolbar);

  let disposed = false;
  let core = null;
  let state = null;
  let collisionMask = null;
  let trackImage = null;
  let grassImage = null;
  let carImage = null;
  let phase = "loading";
  let runs = [];
  let frameId = 0;
  let previousFrameAt = null;
  let accumulatedMilliseconds = 0;
  let inputOrder = 0;
  const inputSources = new Map();
  const abortController = new AbortController();
  const expectedCheckId = registration.check_id;
  const expectedAttemptId = registration.attempt_id;
  const context = canvas.getContext("2d");

  function formatRaceTime(ticks) {
    const totalCentiseconds = Math.floor((ticks * 100) / Math.max(1, Number(config.hz)));
    const minutes = Math.floor(totalCentiseconds / 6_000);
    const seconds = Math.floor(totalCentiseconds / 100) % 60;
    const centiseconds = totalCentiseconds % 100;
    return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}.${String(centiseconds).padStart(2, "0")}`;
  }

  function setStageMessage(title, copy) {
    stageMessage.replaceChildren(
      element("strong", { text: title }),
      element("span", { text: copy }),
    );
    stageMessage.hidden = false;
  }

  function updateHud() {
    const gates = Array.isArray(config.gates) ? config.gates.length : 0;
    lapValue.textContent = `${state?.finished ? 1 : 0} / 1`;
    checkpointValue.textContent = `${Math.min(state?.gate_index ?? 0, gates)} / ${gates}`;
    timeValue.textContent = formatRaceTime(state?.ticks ?? 0);
    speedValue.textContent = `${Math.abs(Math.round(state?.speed ?? 0))} km/h`;
  }

  function renderCanvas() {
    if (!context) return;
    const width = Number(config.width) || 800;
    const height = Number(config.height) || 541;
    context.clearRect(0, 0, width, height);
    context.fillStyle = "#d7cdd6";
    context.fillRect(0, 0, width, height);
    if (grassImage) context.drawImage(grassImage, 0, 0, width, height);
    if (trackImage) context.drawImage(trackImage, 0, 0, width, height);
    if (state && carImage) {
      context.save();
      context.translate(state.x, state.y);
      context.rotate(state.angle + Math.PI / 2);
      context.drawImage(carImage, -8, -15, 16, 30);
      context.restore();
    }
    updateHud();
  }

  function selectedInputMask() {
    let longitudinal = null;
    let lateral = null;
    for (const source of inputSources.values()) {
      if (source.bit === core.RACE_INPUT.THROTTLE || source.bit === core.RACE_INPUT.BRAKE) {
        if (!longitudinal || source.order > longitudinal.order) longitudinal = source;
      } else if (source.bit === core.RACE_INPUT.LEFT || source.bit === core.RACE_INPUT.RIGHT) {
        if (!lateral || source.order > lateral.order) lateral = source;
      }
    }
    return (longitudinal?.bit ?? 0) | (lateral?.bit ?? 0);
  }

  function refreshControlButtons() {
    const mask = core ? selectedInputMask() : 0;
    const inputByName = core
      ? {
          up: core.RACE_INPUT.THROTTLE,
          down: core.RACE_INPUT.BRAKE,
          left: core.RACE_INPUT.LEFT,
          right: core.RACE_INPUT.RIGHT,
        }
      : {};
    for (const [name, button] of controlButtons) {
      button.setAttribute("aria-pressed", String(Boolean(mask & (inputByName[name] ?? 0))));
    }
  }

  function clearInputs() {
    inputSources.clear();
    refreshControlButtons();
  }

  function setInputSource(sourceId, bit, down) {
    if (down && phase === "playing") {
      inputSources.set(sourceId, { bit, order: ++inputOrder });
    } else {
      inputSources.delete(sourceId);
    }
    refreshControlButtons();
  }

  function resetRun(nextPhase = "ready") {
    clearInputs();
    runs = [];
    state = core.createRaceState(config);
    previousFrameAt = null;
    accumulatedMilliseconds = 0;
    phase = nextPhase;
    root.dataset.phase = phase;
    setTranscript(null, false);
    renderCanvas();
  }

  function stopFrame() {
    if (frameId) window.cancelAnimationFrame(frameId);
    frameId = 0;
    previousFrameAt = null;
    accumulatedMilliseconds = 0;
  }

  function showAcceptedRace() {
    if (disposed) return;
    stopFrame();
    phase = "finished";
    root.dataset.phase = phase;
    clearInputs();
    setStageMessage("Check complete", "This lap has already been accepted.");
    startButton.disabled = true;
    for (const button of controlButtons.values()) button.disabled = true;
    renderCanvas();
  }

  function finishRace() {
    if (phase !== "playing" || disposed) return;
    phase = "finished";
    root.dataset.phase = phase;
    clearInputs();
    setStageMessage("Lap complete", "Checking your run...");
    startButton.disabled = true;
    for (const button of controlButtons.values()) button.disabled = true;
    const transcript = {
      runs: runs.map(([input, ticks]) => [input, ticks]),
    };
    setTranscript(transcript, true);
    setFeedback("Lap complete. Checking run...", "success");
    window.queueMicrotask(() => {
      if (
        disposed ||
        runtime.registration?.check_id !== expectedCheckId ||
        runtime.registration?.attempt_id !== expectedAttemptId
      ) {
        return;
      }
      submitCheck(transcript);
    });
  }

  function collisionReset(copy = "The car left the track. Start again when ready.") {
    stopFrame();
    resetRun("crashed");
    root.dataset.phase = phase;
    setStageMessage("Off track", copy);
    startButton.textContent = "Retry";
    startButton.disabled = false;
    for (const button of controlButtons.values()) button.disabled = true;
    setFeedback("Off track. Try the lap again.", "danger");
  }

  function frame(timestamp) {
    frameId = 0;
    if (disposed || phase !== "playing") return;
    if (previousFrameAt === null) previousFrameAt = timestamp;
    const elapsed = Math.min(250, Math.max(0, timestamp - previousFrameAt));
    previousFrameAt = timestamp;
    accumulatedMilliseconds += elapsed;
    const stepMilliseconds = 1_000 / config.hz;
    let steps = 0;
    while (
      accumulatedMilliseconds >= stepMilliseconds &&
      phase === "playing" &&
      steps < 15
    ) {
      const input = selectedInputMask();
      if (runs.length === 0 && input === 0) {
        accumulatedMilliseconds -= stepMilliseconds;
        steps += 1;
        continue;
      }
      core.appendRaceInput(runs, input);
      if (runs.length > config.max_runs) {
        collisionReset("Too many control changes were recorded. Start again when ready.");
        break;
      }
      state = core.stepRace(state, input, config, collisionMask);
      accumulatedMilliseconds -= stepMilliseconds;
      steps += 1;
      if (state.crashed) {
        collisionReset();
      } else if (state.finished) {
        renderCanvas();
        finishRace();
      } else if (state.ticks >= config.max_ticks) {
        collisionReset("The lap took too long. Start again when ready.");
      }
    }
    renderCanvas();
    if (phase === "playing") frameId = window.requestAnimationFrame(frame);
  }

  function startRace() {
    if (disposed || !core || !collisionMask || phase === "playing" || phase === "finished") return;
    stopFrame();
    resetRun("playing");
    root.dataset.phase = phase;
    stageMessage.hidden = true;
    startButton.textContent = "Racing...";
    startButton.disabled = true;
    for (const button of controlButtons.values()) button.disabled = false;
    setFeedback("Race in progress. Stay on the track.");
    root.focus({ preventScroll: true });
    frameId = window.requestAnimationFrame(frame);
  }

  const keyInputs = new Map([
    ["ArrowUp", "up"],
    ["KeyW", "up"],
    ["ArrowDown", "down"],
    ["KeyS", "down"],
    ["ArrowLeft", "left"],
    ["KeyA", "left"],
    ["ArrowRight", "right"],
    ["KeyD", "right"],
  ]);

  function bitForName(name) {
    if (!core) return 0;
    return {
      up: core.RACE_INPUT.THROTTLE,
      down: core.RACE_INPUT.BRAKE,
      left: core.RACE_INPUT.LEFT,
      right: core.RACE_INPUT.RIGHT,
    }[name] ?? 0;
  }

  function onKeyDown(event) {
    if (event.ctrlKey || event.altKey || event.metaKey) return;
    const name = keyInputs.get(event.code);
    if (!name || phase !== "playing") return;
    event.preventDefault();
    if (!event.repeat) setInputSource(`key:${event.code}`, bitForName(name), true);
  }

  function onKeyUp(event) {
    const name = keyInputs.get(event.code);
    if (!name) return;
    if (root.contains(document.activeElement) && phase === "playing") event.preventDefault();
    setInputSource(`key:${event.code}`, bitForName(name), false);
  }

  root.addEventListener("keydown", onKeyDown);
  window.addEventListener("keyup", onKeyUp);
  const releaseHeldInputs = () => {
    clearInputs();
    previousFrameAt = null;
  };
  window.addEventListener("blur", releaseHeldInputs);
  document.addEventListener("visibilitychange", releaseHeldInputs);
  startButton.addEventListener("click", startRace);

  for (const [name, button] of controlButtons) {
    const pointers = new Set();
    const releasePointer = (event) => {
      if (!pointers.delete(event.pointerId)) return;
      setInputSource(`pointer:${event.pointerId}`, bitForName(name), false);
    };
    button.addEventListener("pointerdown", (event) => {
      if (phase !== "playing") return;
      event.preventDefault();
      pointers.add(event.pointerId);
      button.setPointerCapture(event.pointerId);
      setInputSource(`pointer:${event.pointerId}`, bitForName(name), true);
    });
    button.addEventListener("pointerup", releasePointer);
    button.addEventListener("pointercancel", releasePointer);
    button.addEventListener("lostpointercapture", releasePointer);
  }

  runtime.challengeCleanup = () => {
    if (disposed) return;
    disposed = true;
    abortController.abort();
    stopFrame();
    clearInputs();
    window.removeEventListener("keyup", onKeyUp);
    window.removeEventListener("blur", releaseHeldInputs);
    document.removeEventListener("visibilitychange", releaseHeldInputs);
    if (runtime.challengeComplete === showAcceptedRace) runtime.challengeComplete = null;
  };
  runtime.challengeComplete = showAcceptedRace;
  setFeedback("Loading race...");

  function loadImage(url) {
    return new Promise((resolve, reject) => {
      const image = new Image();
      image.addEventListener("load", () => resolve(image), { once: true });
      image.addEventListener("error", () => reject(new Error("A race image could not be loaded")), {
        once: true,
      });
      image.src = url;
    });
  }

  Promise.all([
    import("/race/race-core.js"),
    fetch(config.mask_url, { signal: abortController.signal }).then((response) => {
      if (!response.ok) throw new Error("The race course could not be loaded");
      return response.arrayBuffer();
    }),
    loadImage(config.track_url),
    loadImage(config.grass_url),
    loadImage(config.car_url),
  ])
    .then(([raceCore, maskBuffer, loadedTrack, loadedGrass, loadedCar]) => {
      if (disposed) return;
      if (
        Number(config.width) !== 800 ||
        Number(config.height) !== 541 ||
        Number(config.hz) !== 60
      ) {
        throw new Error("The race configuration is not supported");
      }
      core = raceCore;
      collisionMask = new Uint8Array(maskBuffer);
      const expectedMaskBytes = Math.ceil((config.width * config.height) / 8);
      if (collisionMask.byteLength !== expectedMaskBytes) {
        throw new Error("The race course data is incomplete");
      }
      trackImage = loadedTrack;
      grassImage = loadedGrass;
      carImage = loadedCar;
      canvas.width = config.width;
      canvas.height = config.height;
      root.dataset.ready = "true";
      if (
        registration.completed ||
        (runtime.ownCompleted && runtime.registration?.check_id === expectedCheckId)
      ) {
        state = core.createRaceState(config);
        showAcceptedRace();
        return;
      }
      resetRun("ready");
      setStageMessage("Ready to race", "Complete one lap without leaving the track.");
      startButton.disabled = false;
      for (const button of controlButtons.values()) button.disabled = true;
      setFeedback("Start the race when ready.");
    })
    .catch((error) => {
      if (disposed || error?.name === "AbortError") return;
      phase = "error";
      root.dataset.phase = phase;
      setStageMessage("Could not load race", error.message);
      setFeedback(error.message, "danger");
    });

  return root;
}

function renderAssignedChallenge(registration) {
  runtime.challengeCleanup?.();
  runtime.challengeCleanup = null;
  runtime.challengeComplete = null;
  runtime.transcript = null;
  runtime.transcriptReady = false;
  runtime.ownCompleted = Boolean(registration.completed);
  const config =
    registration.challenge_config ?? registration.challenge_public?.config ?? {};
  let challengeNode;
  switch (registration.challenge) {
    case "desktop-cleanup":
      challengeNode = renderDesktopCleanup(config);
      break;
    case "cable-box":
      challengeNode = renderCableBox(config);
      break;
    case "tile-scramble":
      challengeNode = renderTileScramble(config);
      break;
    case "race-lap":
      challengeNode = renderRaceLap(config, registration);
      break;
    default:
      challengeNode = element("p", { text: "This check could not be displayed." });
  }

  elements.challengeMount.replaceChildren(challengeNode);
  elements.challengeMount.setAttribute("aria-busy", "false");
  elements.challengeTitle.textContent =
    registration.title ?? registration.challenge_public?.title ?? "Human check";
  elements.instructions.textContent =
    registration.instructions ??
    registration.challenge_public?.instructions ??
    "Complete the check below.";

  if (runtime.ownCompleted) {
    markOwnCheckComplete();
  }
  updateActionAvailability();
}

function clearPendingTimers() {
  if (runtime.pendingRetry) window.clearTimeout(runtime.pendingRetry);
  if (runtime.registrationTimer) window.clearTimeout(runtime.registrationTimer);
  if (runtime.advanceTimer) window.clearTimeout(runtime.advanceTimer);
  for (const connection of runtime.connections.values()) {
    if (connection.reconnectTimer) window.clearTimeout(connection.reconnectTimer);
    connection.reconnectTimer = null;
  }
  runtime.pendingRetry = null;
  runtime.pendingRetryTranscript = null;
  runtime.registrationTimer = null;
  runtime.advanceTimer = null;
}

function scheduleRegistration(delayMilliseconds = 0) {
  if (runtime.registrationTimer) window.clearTimeout(runtime.registrationTimer);
  runtime.registrationTimer = window.setTimeout(() => {
    runtime.registrationTimer = null;
    restoreAssignments();
  }, delayMilliseconds);
}

function closeAllConnections() {
  const connections = [...runtime.connections.values()];
  runtime.connections.clear();
  for (const connection of connections) {
    if (connection.reconnectTimer) window.clearTimeout(connection.reconnectTimer);
    connection.reconnectTimer = null;
    if (connection.socket && connection.socket.readyState < WebSocket.CLOSING) {
      connection.socket.close();
    }
    connection.socket = null;
  }
}

function requestRegistration(clientId) {
  return api("/api/check/start", {
    method: "POST",
    body: { client_id: clientId },
  });
}

function refreshConnectionLabel() {
  const connections = [...runtime.connections.values()];
  if (connections.length === 0) return;
  const connected = connections.every(
    ({ socket }) => socket?.readyState === WebSocket.OPEN,
  );
  setConnection(
    connected ? "Connected" : "Connecting...",
    connected ? "success" : "warning",
  );
}

function openLiveConnection(clientId, registration) {
  let connection = runtime.connections.get(clientId);
  if (!connection) {
    connection = {
      registration,
      socket: null,
      reconnectAttempts: 0,
      reconnectTimer: null,
    };
    runtime.connections.set(clientId, connection);
  }

  if (connection.reconnectTimer) window.clearTimeout(connection.reconnectTimer);
  connection.reconnectTimer = null;
  const previousSocket = connection.socket;
  connection.registration = registration;
  connection.socket = null;
  if (previousSocket && previousSocket.readyState < WebSocket.CLOSING) {
    previousSocket.close();
  }

  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const url = new URL("/api/check/live", `${protocol}//${location.host}`);
  url.searchParams.set("channel", registration.channel_id);
  const socket = new WebSocket(url);
  connection.socket = socket;
  refreshConnectionLabel();

  socket.addEventListener("open", () => {
    if (
      runtime.connections.get(clientId) !== connection ||
      connection.socket !== socket
    ) {
      return;
    }
    connection.reconnectAttempts = 0;
    refreshConnectionLabel();
  });
  socket.addEventListener("message", (event) => {
    if (
      runtime.connections.get(clientId) !== connection ||
      connection.socket !== socket
    ) {
      return;
    }
    try {
      const message = JSON.parse(event.data);
      if (message.type === "restart") {
        moveToNewAttempt(message.state);
        return;
      } else if (message.state) {
        renderState(message.state);
      }
      if (message.accepted_check_id === registration.check_id) {
        connection.registration.completed = true;
        if (message.accepted_check_id === runtime.registration?.check_id) {
          markOwnCheckComplete();
        }
      }
    } catch {
      showNotice("Connection problem", "A server update could not be read.", "warning");
    }
  });
  socket.addEventListener("close", (event) => {
    if (
      runtime.connections.get(clientId) !== connection ||
      connection.socket !== socket
    ) {
      return;
    }
    connection.socket = null;
    if (!attemptIsRunning()) return;
    setConnection("Reconnecting...", "warning");
    connection.reconnectAttempts += 1;
    if (event.code === 4001 || connection.reconnectAttempts >= 3) {
      connection.reconnectTimer = window.setTimeout(
        () => restoreConnection(clientId),
        event.code === 4001 ? 80 : 300,
      );
      return;
    }
    const retryDelay = 350 * 2 ** (connection.reconnectAttempts - 1);
    connection.reconnectTimer = window.setTimeout(
      () => openLiveConnection(clientId, connection.registration),
      retryDelay,
    );
  });
  socket.addEventListener("error", () => {
    if (
      runtime.connections.get(clientId) === connection &&
      connection.socket === socket
    ) {
      setConnection("Connection lost", "danger");
    }
  });
}

function selectCurrentRegistration(clientId, registration) {
  runtime.clientId = clientId;
  runtime.registration = registration;
  runtime.transitionAttemptId = registration.attempt_id;
  persistClientIds();
  renderState(registration.state);
  renderAssignedChallenge(registration);
  hideNotice();
}

async function restoreConnection(clientId) {
  const connection = runtime.connections.get(clientId);
  if (!connection || !attemptIsRunning()) return;
  const epoch = runtime.registrationEpoch;
  connection.reconnectTimer = null;
  try {
    const registration = await requestRegistration(clientId);
    if (
      epoch !== runtime.registrationEpoch ||
      runtime.connections.get(clientId) !== connection
    ) {
      return;
    }
    if (
      runtime.transitionAttemptId &&
      registration.attempt_id !== runtime.transitionAttemptId
    ) {
      moveToNewAttempt(registration.state);
      return;
    }
    connection.registration = registration;
    if (runtime.clientId === clientId) {
      runtime.registration = registration;
      renderState(registration.state);
    }
    openLiveConnection(clientId, registration);
  } catch (error) {
    if (
      epoch !== runtime.registrationEpoch ||
      runtime.connections.get(clientId) !== connection
    ) {
      return;
    }
    if (error instanceof ApiError && error.data?.state) renderState(error.data.state);
    if (error instanceof ApiError && error.data?.code === "ATTEMPT_EXPIRED") {
      setConnection("Expired", "danger");
      return;
    }
    setConnection("Reconnecting...", "warning");
    connection.reconnectTimer = window.setTimeout(
      () => restoreConnection(clientId),
      1_000,
    );
  }
}

async function restoreAssignments() {
  if (runtime.registering) return;
  const epoch = runtime.registrationEpoch;
  runtime.registering = true;
  closeAllConnections();
  resetChallengeSurface();
  setConnection("Connecting...", "warning");
  const restored = [];
  let capacityReached = false;
  try {
    for (const clientId of [...runtime.clientIds]) {
      try {
        const registration = await requestRegistration(clientId);
        if (epoch !== runtime.registrationEpoch) return;
        if (
          runtime.transitionAttemptId &&
          registration.attempt_id !== runtime.transitionAttemptId
        ) {
          moveToNewAttempt(registration.state);
          return;
        }
        runtime.transitionAttemptId = registration.attempt_id;
        restored.push({ clientId, registration });
        renderState(registration.state);
        openLiveConnection(clientId, registration);
      } catch (error) {
        if (epoch !== runtime.registrationEpoch) return;
        if (error instanceof ApiError && error.data?.state) renderState(error.data.state);
        if (error instanceof ApiError && error.data?.code === "CHECK_CAPACITY") {
          capacityReached = true;
          if (runtime.clientIds.length > 1 || restored.length > 0) removeClientId(clientId);
          continue;
        }
        if (error instanceof ApiError && error.data?.code === "ATTEMPT_EXPIRED") {
          setConnection("Expired", "danger");
          elements.expiredPanel.hidden = false;
          return;
        }
        throw error;
      }
    }

    if (epoch !== runtime.registrationEpoch) return;
    const current =
      [...restored].reverse().find(({ registration }) => !registration.completed) ??
      restored.at(-1);
    if (current) {
      selectCurrentRegistration(current.clientId, current.registration);
      refreshConnectionLabel();
      const allRestoredComplete = restored.every(
        ({ registration }) => registration.completed,
      );
      if (
        allRestoredComplete &&
        attemptIsRunning() &&
        (runtime.state?.completed_checks ?? 0) <
          (runtime.state?.required_checks ?? DEFAULT_REQUIRED_CHECKS)
      ) {
        scheduleAdvance(100, epoch, runtime.transitionAttemptId);
      }
    } else if (capacityReached) {
      setConnection("Unavailable", "danger");
      showNotice(
        "No check available",
        "This request could not be assigned a check.",
        "warning",
      );
    } else {
      throw new Error("No check could be restored");
    }
  } catch (error) {
    if (epoch !== runtime.registrationEpoch) return;
    setConnection("Unavailable", "danger");
    showNotice("Could not start", error.message, "danger");
    scheduleRegistration(1_500);
  } finally {
    if (epoch === runtime.registrationEpoch) runtime.registering = false;
  }
}

function scheduleAdvance(delayMilliseconds, epoch, attemptId) {
  if (runtime.advanceTimer) window.clearTimeout(runtime.advanceTimer);
  runtime.advanceTimer = window.setTimeout(() => {
    runtime.advanceTimer = null;
    advanceToNextCheck(epoch, attemptId);
  }, delayMilliseconds);
}

async function advanceToNextCheck(
  expectedEpoch = runtime.registrationEpoch,
  expectedAttemptId = runtime.transitionAttemptId,
) {
  if (
    expectedEpoch !== runtime.registrationEpoch ||
    expectedAttemptId !== runtime.transitionAttemptId ||
    runtime.advancing ||
    runtime.registering ||
    !attemptIsRunning() ||
    (runtime.state?.completed_checks ?? 0) >=
      (runtime.state?.required_checks ?? DEFAULT_REQUIRED_CHECKS)
  ) {
    return;
  }

  runtime.advancing = true;
  const epoch = runtime.registrationEpoch;
  const previousClientId = runtime.clientId;
  const previousRegistration = runtime.registration;
  const clientId = appendClientId();
  setFeedback("Check complete. Loading next check...", "success");
  setConnection("Connecting...", "warning");
  try {
    const registration = await requestRegistration(clientId);
    if (epoch !== runtime.registrationEpoch) return;
    if (
      runtime.transitionAttemptId &&
      registration.attempt_id !== runtime.transitionAttemptId
    ) {
      moveToNewAttempt(registration.state);
      return;
    }
    openLiveConnection(clientId, registration);
    resetChallengeSurface();
    selectCurrentRegistration(clientId, registration);
    refreshConnectionLabel();
  } catch (error) {
    if (epoch !== runtime.registrationEpoch) return;
    removeClientId(clientId);
    runtime.clientId = previousClientId;
    runtime.registration = previousRegistration;
    persistClientIds();
    if (error instanceof ApiError && error.data?.state) renderState(error.data.state);
    if (error instanceof ApiError && error.data?.code === "ATTEMPT_EXPIRED") {
      setConnection("Expired", "danger");
      elements.expiredPanel.hidden = false;
    } else if (error instanceof ApiError && error.data?.code === "CHECK_CAPACITY") {
      refreshConnectionLabel();
      setFeedback("Check complete.", "success");
    } else {
      refreshConnectionLabel();
      showNotice("Could not load next check", error.message, "danger");
    }
  } finally {
    if (epoch === runtime.registrationEpoch) runtime.advancing = false;
  }
}

async function submitCheck(transcriptOverride = null) {
  const candidateTranscript = transcriptOverride ?? runtime.transcript;
  if (
    runtime.submitting ||
    (runtime.pendingRetry && !transcriptOverride) ||
    !runtime.registration ||
    (!transcriptOverride && !runtime.transcriptReady) ||
    !candidateTranscript
  ) {
    return;
  }
  const registration = runtime.registration;
  const submittedTranscript = structuredClone(candidateTranscript);
  const minimumCompleteAt = Number(registration.minimum_complete_at);
  if (Number.isFinite(minimumCompleteAt) && serverNow() < minimumCompleteAt) {
    const wait = Math.max(25, minimumCompleteAt - serverNow() + 25);
    setCheckStatus("CHECKING", "wait");
    setFeedback("Answer saved. Waiting for the server...", "warning");
    runtime.pendingRetryTranscript = submittedTranscript;
    runtime.pendingRetry = window.setTimeout(() => {
      const retryTranscript = runtime.pendingRetryTranscript;
      runtime.pendingRetry = null;
      runtime.pendingRetryTranscript = null;
      submitCheck(retryTranscript);
    }, wait);
    updateActionAvailability();
    return;
  }
  runtime.submitting = true;
  setCheckStatus("CHECKING", "wait");
  updateActionAvailability();
  setFeedback("Checking answer...");
  try {
    const result = await api(
      `/api/checks/${encodeURIComponent(registration.check_id)}/verify`,
      {
        method: "POST",
        headers: { "X-Check-Channel": registration.channel_id },
        body: { transcript: submittedTranscript },
      },
    );
    if (runtime.registration?.attempt_id !== registration.attempt_id) return;
    if (result.state) renderState(result.state);
    setFeedback("Answer accepted. Finishing check...", "success");
    await acceptReceipt(result.proof);
  } catch (error) {
    if (runtime.registration?.attempt_id !== registration.attempt_id) return;
    const retryAt = error instanceof ApiError ? error.data?.retry_at : null;
    if (
      error instanceof ApiError &&
      (error.data?.code === "PHYSICALLY_IMPLAUSIBLE" ||
        error.data?.code === "PROOF_CADENCE") &&
      Number.isFinite(retryAt)
    ) {
      const wait = Math.max(25, retryAt - serverNow() + 40);
      setFeedback("Answer saved. Waiting for the server...", "warning");
      runtime.pendingRetryTranscript = submittedTranscript;
      runtime.pendingRetry = window.setTimeout(() => {
        const retryTranscript = runtime.pendingRetryTranscript;
        runtime.pendingRetry = null;
        runtime.pendingRetryTranscript = null;
        submitCheck(retryTranscript);
      }, wait);
    } else {
      if (error instanceof ApiError && error.data?.state) renderState(error.data.state);
      setCheckStatus("ERROR", "wait");
      setFeedback(error.message, "danger");
    }
  } finally {
    runtime.submitting = false;
    updateActionAvailability();
  }
}

async function acceptReceipt(proof) {
  const registration = runtime.registration;
  if (!registration) throw new Error("No active check");
  const result = await api(
    `/api/checks/${encodeURIComponent(registration.check_id)}/accept`,
    {
      method: "POST",
      headers: { "X-Check-Channel": registration.channel_id },
      body: { proof },
    },
  );
  if (
    runtime.registration?.attempt_id !== registration.attempt_id ||
    runtime.registration?.check_id !== registration.check_id
  ) {
    return result;
  }
  const connection = runtime.connections.get(runtime.clientId);
  if (connection?.registration.check_id === registration.check_id) {
    connection.registration.completed = true;
  }
  markOwnCheckComplete();
  if (result.state) renderState(result.state);
  if (
    attemptIsRunning() &&
    (result.state?.completed_checks ?? 0) <
      (result.state?.required_checks ?? DEFAULT_REQUIRED_CHECKS)
  ) {
    const completionEpoch = runtime.registrationEpoch;
    const completionAttemptId = registration.attempt_id;
    setFeedback("Check complete. Loading next check...", "success");
    await delay(180);
    if (
      completionEpoch === runtime.registrationEpoch &&
      completionAttemptId === runtime.transitionAttemptId &&
      runtime.registration?.check_id === registration.check_id
    ) {
      await advanceToNextCheck(completionEpoch, completionAttemptId);
    }
  }
  return result;
}

async function continueLogin() {
  if (runtime.submitting) return;
  runtime.submitting = true;
  updateActionAvailability();
  try {
    const result = await api("/api/unlock", { method: "POST" });
    showFlagResult(result.flag);
    elements.expiredPanel.hidden = true;
  } catch (error) {
    if (error instanceof ApiError && error.data?.state) renderState(error.data.state);
    showNotice("Could not continue", error.message, "danger");
  } finally {
    runtime.submitting = false;
    updateActionAvailability();
  }
}

function moveToNewAttempt(state) {
  const targetAttemptId = state?.attempt_id ?? null;
  if (
    targetAttemptId &&
    runtime.transitionAttemptId === targetAttemptId
  ) {
    if (state) renderState(state);
    return;
  }
  runtime.transitionAttemptId = targetAttemptId;
  runtime.registrationEpoch += 1;
  runtime.registering = false;
  runtime.advancing = false;
  clearPendingTimers();
  closeAllConnections();
  runtime.registration = null;
  resetClientChain();
  clearStoredFlag();
  elements.expiredPanel.hidden = true;
  if (state) renderState(state);
  resetChallengeSurface();
  scheduleRegistration(40 + Math.floor(Math.random() * 160));
}

async function restartAttempt() {
  if (runtime.restarting) return;
  runtime.restarting = true;
  elements.restartButton.disabled = true;
  showNotice("Starting over", "Preparing a new attempt.", "info");
  try {
    const result = await api("/api/session/restart", {
      method: "POST",
      body: { expected_attempt_id: runtime.state?.attempt_id },
    });
    runtime.syncChannel?.postMessage({
      type: "reset",
      state: result.state,
      instance_id: runtime.instanceId,
    });
    moveToNewAttempt(result.state);
  } catch (error) {
    if (error instanceof ApiError && error.data?.code === "STALE_RESTART" && error.data.state) {
      moveToNewAttempt(error.data.state);
    } else {
      showNotice("Could not restart", error.message, "danger");
    }
  } finally {
    runtime.restarting = false;
    elements.restartButton.disabled = false;
  }
}

elements.verifyButton.addEventListener("click", () => submitCheck());
elements.continueButton.addEventListener("click", continueLogin);
elements.restartButton.addEventListener("click", restartAttempt);

window.addEventListener("pagehide", () => {
  runtime.registrationEpoch += 1;
  runtime.registering = false;
  runtime.advancing = false;
  clearPendingTimers();
  runtime.syncChannel?.close();
  runtime.syncChannel = null;
  closeAllConnections();
});

window.addEventListener("pageshow", (event) => {
  if (!event.persisted) return;
  establishClientIdentity()
    .then(async () => {
      const state = await api("/api/state");
      renderState(state);
      const resultRestored =
        state.status === "unlocked" && restoreStoredFlag();
      if (state.status !== "unlocked") clearStoredFlag();
      if (resultRestored) return;
      if (state.status === "expired") {
        setConnection("Expired", "danger");
        return;
      }
      await restoreAssignments();
    })
    .catch((error) => {
      setConnection("Unavailable", "danger");
      showNotice("Could not restore", error.message, "danger");
    });
});

window.setInterval(() => {
  renderTimer();
  updateActionAvailability();
}, 200);

async function start() {
  try {
    await establishClientIdentity();
    const state = await api("/api/state");
    renderState(state);
    const resultRestored =
      state.status === "unlocked" && restoreStoredFlag();
    if (state.status !== "unlocked") clearStoredFlag();
    if (resultRestored) return;
    if (state.status === "expired") {
      setConnection("Expired", "danger");
      return;
    }
    await restoreAssignments();
  } catch (error) {
    setConnection("Unavailable", "danger");
    showNotice("Could not start", error.message, "danger");
  }
}

start();
