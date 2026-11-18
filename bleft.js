// bleft client: stream data to a bleft-listener over Web Bluetooth.
//
// Wire protocol (must match listener/src/protocol.rs). Each GATT write is a packet:
//   0x01 START [utf8 name]            begin a new stream / file on the listener
//   0x02 DATA  [payload]              append payload
//   0x03 END   [u32le length][u32le crc32]

export const SERVICE_UUID = 'bf1e0001-7c5a-4b8e-9d3f-2a6c1e0b5d70';
export const DATA_CHAR_UUID = 'bf1e0002-7c5a-4b8e-9d3f-2a6c1e0b5d70';

const PKT_START = 0x01;
const PKT_DATA = 0x02;
const PKT_END = 0x03;

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

export class BleftClient extends EventTarget {
  #device = null;
  #char = null;

  get connected() {
    return !!this.#device?.gatt?.connected && !!this.#char;
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
      this.dispatchEvent(new Event('disconnected'));
    });
    const server = await device.gatt.connect();
    const service = await server.getPrimaryService(SERVICE_UUID);
    this.#char = await service.getCharacteristic(DATA_CHAR_UUID);
    this.#device = device;
    this.dispatchEvent(new Event('connected'));
  }

  disconnect() {
    this.#device?.gatt?.disconnect();
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
