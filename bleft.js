// bleft client: stream data to a bleft-listener over Web Bluetooth, and drive
// its TTY (remote shell) session.
//
// Wire protocol (must match listener/src/protocol.rs).
//
// File transfer: each GATT write to DATA_CHAR_UUID is a packet:
//   0x01 START [utf8 name]            begin a new stream / file on the listener
//   0x02 DATA  [payload]              append payload
//   0x03 END   [u32le length][u32le crc32]
//
// TTY: a login shell on the listener, driven like a remote terminal, gated by
// a password since it's sensitive (plain bytes over an unencrypted GATT
// write - stops casual access, not a determined attacker who can sniff the
// link). Subscribing alone does not start a shell; it opens an auth window.
//   TTY_RX_CHAR_UUID (write, browser -> listener):
//     0x01 DATA   [bytes]                      keystrokes/input
//     0x02 RESIZE [u16le cols][u16le rows]
//     0x03 AUTH   [utf8 password]
//   TTY_TX_CHAR_UUID (notify, listener -> browser):
//     0x01 DATA      [bytes]                   shell output
//     0x02 AUTH_OK                             password accepted, shell starting
//     0x03 EXIT      [i32le code]               shell exited; session is over
//     0x04 AUTH_FAIL                           wrong password; send another AUTH to retry

export const SERVICE_UUID = 'bf1e0001-7c5a-4b8e-9d3f-2a6c1e0b5d70';
export const DATA_CHAR_UUID = 'bf1e0002-7c5a-4b8e-9d3f-2a6c1e0b5d70';
export const TTY_RX_CHAR_UUID = 'bf1e0003-7c5a-4b8e-9d3f-2a6c1e0b5d70';
export const TTY_TX_CHAR_UUID = 'bf1e0004-7c5a-4b8e-9d3f-2a6c1e0b5d70';

const PKT_START = 0x01;
const PKT_DATA = 0x02;
const PKT_END = 0x03;

const TTY_PKT_DATA = 0x01;
const TTY_PKT_RESIZE = 0x02;
const TTY_RX_PKT_AUTH = 0x03; // rx only
const TTY_TX_PKT_AUTH_OK = 0x02; // tx only
const TTY_PKT_EXIT = 0x03; // tx only
const TTY_TX_PKT_AUTH_FAIL = 0x04; // tx only
const TTY_AUTH_TIMEOUT_MS = 8000;

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

/** Incremental CRC-32 (IEEE), same as crc32fast on the listener. */
export class Crc32 {
  #crc = 0xffffffff;
  update(bytes) {
    let c = this.#crc;
    for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    this.#crc = c;
  }
  get value() {
    return (this.#crc ^ 0xffffffff) >>> 0;
  }
}

function packet(type, payload = new Uint8Array(0)) {
  const p = new Uint8Array(1 + payload.length);
  p[0] = type;
  p.set(payload, 1);
  return p;
}

/** Re-slice any async source of Uint8Arrays into pieces of at most `size` bytes. */
async function* rechunk(source, size) {
  let pending = null;
  for await (const part of source) {
    let buf = pending ? concat(pending, part) : part;
    pending = null;
    while (buf.length >= size) {
      yield buf.subarray(0, size);
      buf = buf.subarray(size);
    }
    if (buf.length) pending = buf;
  }
  if (pending) yield pending;
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Dispatched with `detail` a Uint8Array of shell output. */
export class TtyDataEvent extends Event {
  constructor(data) {
    super('tty-data');
    this.data = data;
  }
}

/** Dispatched with `code` the shell's exit status; the session is over. */
export class TtyExitEvent extends Event {
  constructor(code) {
    super('tty-exit');
    this.code = code;
  }
}

export class BleftClient extends EventTarget {
  #device = null;
  #char = null;
  #ttyRx = null;
  #ttyTx = null;
  #ttyActive = false;
  #pendingAuth = null; // { resolve, reject } while an AUTH is in flight

  get connected() {
    return !!this.#device?.gatt?.connected && !!this.#char;
  }

  /** Whether the TTY (remote shell) characteristics were found and notifications started. */
  get ttyConnected() {
    return this.connected && this.#ttyActive;
  }

  get deviceName() {
    return this.#device?.name ?? null;
  }

  /** Must be called from a user gesture (click). Shows the browser's device chooser. */
  async connect() {
    if (!navigator.bluetooth) throw new Error('Web Bluetooth is not available in this browser (use Chrome/Edge over https or localhost).');
    const device = await navigator.bluetooth.requestDevice({ filters: [{ services: [SERVICE_UUID] }] });
    device.addEventListener('gattserverdisconnected', () => {
      this.#char = null;
      this.#ttyRx = null;
      this.#ttyTx = null;
      this.#ttyActive = false;
      this.#pendingAuth?.reject(new Error('disconnected'));
      this.#pendingAuth = null;
      this.dispatchEvent(new Event('disconnected'));
    });
    const server = await device.gatt.connect();
    const service = await server.getPrimaryService(SERVICE_UUID);
    this.#char = await service.getCharacteristic(DATA_CHAR_UUID);
    try {
      this.#ttyRx = await service.getCharacteristic(TTY_RX_CHAR_UUID);
      this.#ttyTx = await service.getCharacteristic(TTY_TX_CHAR_UUID);
    } catch {
      this.#ttyRx = this.#ttyTx = null; // listener without TTY support
    }
    this.#device = device;
    this.dispatchEvent(new Event('connected'));
  }

  disconnect() {
    this.#device?.gatt?.disconnect();
  }

  /**
   * Subscribe to the TTY output characteristic and authenticate; the listener
   * starts its shell once the password is accepted. Resolves once the shell
   * has started; rejects (without ever touching the shell) if the password
   * is wrong, or the listener doesn't answer within a few seconds.
   *
   * @param {string} [password] - must match the listener's `--tty-password`
   *   (or whatever it printed at startup); leave empty if it was started
   *   with `--tty-no-password`.
   */
  async ttyStart(password = '') {
    if (!this.#ttyTx || !this.#ttyRx) throw new Error('listener has no TTY support');
    this.#ttyTx.addEventListener('characteristicvaluechanged', this.#onTtyNotify);
    // The listener opens a fresh auth window on GATT subscribe (see protocol
    // docs); it doesn't start a shell until a correct AUTH follows. If we
    // stayed subscribed after the shell last exited (we only unsubscribe when
    // the user clicks "close"), startNotifications() on an already-active
    // subscription is a no-op in Web Bluetooth - no new "subscribed" event
    // would reach the listener. Force a clean unsubscribe/resubscribe cycle
    // so one always does.
    try {
      await this.#ttyTx.stopNotifications();
    } catch {
      // wasn't subscribed; nothing to undo.
    }
    await this.#ttyTx.startNotifications();

    const authed = new Promise((resolve, reject) => {
      this.#pendingAuth = { resolve, reject };
    });
    const timeout = setTimeout(
      () => this.#pendingAuth?.reject(new Error("listener didn't respond to the password (old listener without TTY auth?)")),
      TTY_AUTH_TIMEOUT_MS,
    );
    try {
      const pwBytes = new TextEncoder().encode(password).subarray(0, 200);
      await (this.#ttyRx.writeValueWithResponse ?? this.#ttyRx.writeValue).call(this.#ttyRx, packet(TTY_RX_PKT_AUTH, pwBytes));
      await authed;
      this.#ttyActive = true;
    } finally {
      clearTimeout(timeout);
      this.#pendingAuth = null;
    }
  }

  /** Unsubscribe; the listener stops the shared shell once nobody is listening. */
  async ttyStop() {
    this.#ttyActive = false;
    this.#pendingAuth?.reject(new Error('closed'));
    this.#pendingAuth = null;
    if (!this.#ttyTx) return;
    this.#ttyTx.removeEventListener('characteristicvaluechanged', this.#onTtyNotify);
    try {
      await this.#ttyTx.stopNotifications();
    } catch {
      // already gone (e.g. device disconnected); nothing to clean up.
    }
  }

  #onTtyNotify = (ev) => {
    const value = ev.target.value; // DataView
    if (value.byteLength === 0) return;
    const kind = value.getUint8(0);
    if (kind === TTY_PKT_DATA) {
      this.dispatchEvent(new TtyDataEvent(new Uint8Array(value.buffer, value.byteOffset + 1, value.byteLength - 1)));
    } else if (kind === TTY_PKT_EXIT && value.byteLength >= 5) {
      this.#ttyActive = false;
      this.dispatchEvent(new TtyExitEvent(value.getInt32(1, true)));
    } else if (kind === TTY_TX_PKT_AUTH_OK) {
      this.#pendingAuth?.resolve();
    } else if (kind === TTY_TX_PKT_AUTH_FAIL) {
      this.#pendingAuth?.reject(new Error('wrong password'));
    }
  };

  /** Send keystrokes/input to the shell. */
  async ttyWrite(bytes) {
    if (!this.#ttyRx) throw new Error('listener has no TTY support');
    const pkt = packet(TTY_PKT_DATA, bytes);
    await (this.#ttyRx.writeValueWithoutResponse ?? this.#ttyRx.writeValue).call(this.#ttyRx, pkt);
  }

  /** Tell the shell the terminal was resized. */
  async ttyResize(cols, rows) {
    if (!this.#ttyRx) throw new Error('listener has no TTY support');
    const body = new Uint8Array(4);
    new DataView(body.buffer).setUint16(0, cols, true);
    new DataView(body.buffer).setUint16(2, rows, true);
    await (this.#ttyRx.writeValueWithoutResponse ?? this.#ttyRx.writeValue).call(this.#ttyRx, packet(TTY_PKT_RESIZE, body));
  }

  /**
   * Send one stream; the listener writes it to a new timestamped file.
   *
   * @param {ReadableStream<Uint8Array> | AsyncIterable<Uint8Array> | Iterable<Uint8Array>} source
   * @param {object} [opts]
   * @param {string} [opts.name]            file name hint for the listener (e.g. "photo.jpg")
   * @param {number} [opts.chunkSize=128]   payload bytes per write; keep <= (ATT MTU - 4).
   * @param {boolean} [opts.withResponse=true]  acknowledged writes (reliable, slower) vs write-without-response (fast)
   * @param {(sent:number)=>void} [opts.onProgress]
   * @param {AbortSignal} [opts.signal]
   * @returns {Promise<{bytes:number, crc32:number}>}
   */
  async sendStream(source, { name = '', chunkSize = 128, withResponse = true, onProgress, signal } = {}) {
    if (!this.connected) throw new Error('not connected');
    const char = this.#char;
    const write = async (pkt, acked) => {
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError');
      if (!this.connected) throw new Error('disconnected during transfer');
      if (acked || !char.writeValueWithoutResponse) {
        await (char.writeValueWithResponse ?? char.writeValue).call(char, pkt);
        return;
      }
      // Write-without-response can fail transiently when the OS queue is full.
      for (let attempt = 0; ; attempt++) {
        try {
          await char.writeValueWithoutResponse(pkt);
          return;
        } catch (e) {
          if (attempt >= 50 || !this.connected) throw e;
          await sleep(10 + attempt * 5);
        }
      }
    };

    // ReadableStream (not async-iterable everywhere), or any sync/async iterable of Uint8Array.
    const iterable = typeof source.getReader === 'function' ? readableToAsyncIterable(source) : source;
    const nameBytes = new TextEncoder().encode(name).subarray(0, 100);
    await write(packet(PKT_START, nameBytes), true);

    const crc = new Crc32();
    let bytes = 0;
    for await (const chunk of rechunk(iterable, chunkSize)) {
      await write(packet(PKT_DATA, chunk), withResponse);
      crc.update(chunk);
      bytes += chunk.length;
      onProgress?.(bytes);
    }

    const end = new Uint8Array(8);
    const dv = new DataView(end.buffer);
    dv.setUint32(0, bytes >>> 0, true);
    dv.setUint32(4, crc.value, true);
    await write(packet(PKT_END, end), true);
    return { bytes, crc32: crc.value };
  }
}

async function* readableToAsyncIterable(stream) {
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      yield value;
    }
  } finally {
    reader.releaseLock();
  }
}
