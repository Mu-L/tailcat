// tailcat web app. Plain JavaScript, no build step. The Go side
// (main_js.go) exposes globals tailcatListen and tailcatDial.

const CHUNK = 64 * 1024;
const KEY_STORAGE = "tailcat-web-key";

const params = new URLSearchParams(location.search);
const derpMapURL = new URL(params.get("derpmap") || "derpmap.json", location.href).toString();
const verbose = params.has("verbose");

// tcTest is the state surface polled by the headless-browser
// integration test (web/wasm_test.go).
window.tcTest = {
  ready: false,
  listenAddr: null,
  recvBytes: 0,
  recvSha256: null,
  recvDone: false,
  sentBytes: 0,
  sentSha256: null,
  sendDone: false,
  errors: [],
};
window.addEventListener("error", (e) => window.tcTest.errors.push(String(e.message)));
window.addEventListener("unhandledrejection", (e) => window.tcTest.errors.push(String(e.reason)));

const $ = (id) => document.getElementById(id);
const setStatus = (msg) => { $("status").textContent = msg; };

async function hex(digest) {
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(bytes) {
  return hex(await crypto.subtle.digest("SHA-256", bytes));
}

// fetchWithProgress fetches the wasm, updating the page's progress
// bar as (decompressed) bytes arrive. The server advertises the
// uncompressed size in a header since Content-Length is the
// compressed size.
async function fetchWithProgress(url) {
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`fetching ${url}: ${resp.status}`);
  }
  // The body stream yields decompressed bytes, so progress is
  // tracked against the uncompressed size, but the size shown to the
  // user is Content-Length: what actually crosses the wire.
  const total = Number(resp.headers.get("X-Uncompressed-Size")) ||
    Number(resp.headers.get("Content-Length")) || 0;
  const wireBytes = Number(resp.headers.get("X-Compressed-Size")) ||
    Number(resp.headers.get("Content-Length")) || 0;
  const ofMB = wireBytes > 0 ? ` of ${(wireBytes / (1 << 20)).toFixed(1)} MB` : "";
  const bar = $("load-progress");
  let loaded = 0;
  const counted = resp.body.pipeThrough(new TransformStream({
    transform(chunk, controller) {
      loaded += chunk.byteLength;
      if (total > 0) {
        bar.value = loaded / total;
        const pct = Math.min(100, Math.floor(100 * loaded / total));
        setStatus(`Loading WebAssembly… ${pct}%${ofMB}`);
      } else {
        setStatus(`Loading WebAssembly…`);
      }
      controller.enqueue(chunk);
    },
  }));
  return new Response(counted, { headers: { "Content-Type": "application/wasm" } });
}

// Boot the wasm module.
const ready = new Promise((resolve) => { globalThis.onTailcatReady = resolve; });
const go = new Go();
WebAssembly.instantiateStreaming(fetchWithProgress("main.wasm"), go.importObject)
  .then(({ instance }) => go.run(instance));
await ready;
window.tcTest.ready = true;
$("load-progress").remove();
setStatus("Ready.");
$("listen-btn").disabled = false;
$("send-btn").disabled = false;

// --- Receive side ---

async function startListener() {
  $("listen-btn").disabled = true;
  setStatus("Starting listener…");
  const persist = $("persist-key").checked;
  const privateKey = persist ? (localStorage.getItem(KEY_STORAGE) || "") : "";
  try {
    const ln = await tailcatListen({ derpMapURL, privateKey, verbose, onConnection });
    if (persist) {
      localStorage.setItem(KEY_STORAGE, ln.privateKeyJSON);
    }
    $("listen-addr").textContent = ln.addr;
    $("listen-info").classList.remove("hidden");
    setStatus("Listening. Share the address with the sender.");
    window.tcTest.listenAddr = ln.addr;
  } catch (err) {
    setStatus("Listen failed: " + err.message);
    window.tcTest.errors.push(String(err));
    $("listen-btn").disabled = false;
  }
}

function onConnection(conn) {
  if (params.get("sink") === "hash") {
    hashSink(conn);
    return;
  }
  const li = document.createElement("li");
  const btn = document.createElement("button");
  btn.textContent = "Save incoming file…";
  const progress = document.createElement("span");
  li.append(btn, " ", progress);
  $("incoming").append(li);
  btn.onclick = async () => {
    btn.disabled = true;
    try {
      // Stream to disk. The pull-based conn.read means the sender
      // stalls on TCP backpressure while the user picks a file, and
      // while the disk keeps up; nothing is buffered in memory.
      const handle = await showSaveFilePicker({ suggestedName: "tailcat-download" });
      const w = await handle.createWritable();
      let n = 0;
      for (let chunk; (chunk = await conn.read()) !== null; ) {
        await w.write(chunk);
        n += chunk.length;
        progress.textContent = `${n} bytes`;
      }
      await w.close();
      conn.close();
      progress.textContent = `done, ${n} bytes`;
    } catch (err) {
      conn.close();
      progress.textContent = "failed: " + err.message;
      window.tcTest.errors.push(String(err));
    }
  };
}

// hashSink is the test-mode receiver: instead of the file picker
// (which needs a user gesture that headless Chrome can't provide), it
// counts and hashes the received bytes into tcTest.
async function hashSink(conn) {
  const chunks = [];
  let n = 0;
  for (let chunk; (chunk = await conn.read()) !== null; ) {
    chunks.push(chunk);
    n += chunk.length;
    window.tcTest.recvBytes = n;
  }
  const all = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.length;
  }
  window.tcTest.recvSha256 = await sha256Hex(all);
  window.tcTest.recvDone = true;
  conn.close();
}

$("listen-btn").onclick = startListener;
$("copy-addr").onclick = () => navigator.clipboard.writeText($("listen-addr").textContent);

// --- Send side ---

async function sendStream(addr, size, readChunk, progressEl) {
  const conn = await tailcatDial({ addr, derpMapURL, verbose });
  let off = 0;
  while (off < size) {
    const chunk = await readChunk(off, Math.min(CHUNK, size - off));
    await conn.write(chunk);
    off += chunk.length;
    progressEl.textContent = `${off} / ${size} bytes`;
  }
  await conn.closeWrite();
  // Wait for the receiver's close: like the CLI, the peer's EOF is
  // the confirmation that everything we sent was delivered.
  while ((await conn.read()) !== null) {}
  conn.close();
  window.tcTest.sentBytes = off;
  window.tcTest.sendDone = true;
  progressEl.textContent = `sent ${off} bytes`;
}

$("send-btn").onclick = async () => {
  const addr = $("send-addr").value.trim();
  const file = $("send-file").files[0];
  if (!addr || !file) {
    setStatus("Enter an address and pick a file first.");
    return;
  }
  $("send-btn").disabled = true;
  setStatus("Connecting…");
  try {
    await sendStream(addr, file.size,
      async (off, n) => new Uint8Array(await file.slice(off, off + n).arrayBuffer()),
      $("send-progress"));
    setStatus("Done.");
  } catch (err) {
    setStatus("Send failed: " + err.message);
    window.tcTest.errors.push(String(err));
  }
  $("send-btn").disabled = false;
};

// --- Test automation via query parameters ---

if (params.get("mode") === "listen") {
  startListener();
} else if (params.get("mode") === "send") {
  const addr = params.get("addr");
  const size = parseInt(params.get("bytes"), 10);
  const data = new Uint8Array(size);
  // crypto.getRandomValues caps each call at 64 KiB.
  for (let off = 0; off < size; off += CHUNK) {
    crypto.getRandomValues(data.subarray(off, Math.min(off + CHUNK, size)));
  }
  window.tcTest.sentSha256 = await sha256Hex(data);
  try {
    await sendStream(addr, size, async (off, n) => data.subarray(off, off + n), $("send-progress"));
  } catch (err) {
    window.tcTest.errors.push(String(err));
  }
}
