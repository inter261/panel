import { connect } from 'cloudflare:sockets';
import html from './ui.html';
import { sha224Hex } from './sha224.js';

const PORTS_CUSTOM = [443, 2053, 2083, 2087, 2096, 8443]; // port yang didukung Cloudflare untuk domain sendiri
const FINGERPRINTS = ['chrome', 'firefox', 'safari', 'edge'];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      return handleWebSocket(env);
    }
    if (url.pathname === '/admin' && request.method === 'GET') {
      return new Response(html, {
        headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
      });
    }
    if (url.pathname.startsWith('/api/')) {
      return handleApi(request, env, url);
    }
    return new Response('Not found', { status: 404 });
  },
};

// ---------- WebSocket: VLESS + Trojan ----------

function handleWebSocket(env) {
  const vless = uuidToBytes(env.UUID || '');
  const trojanHash = env.TROJAN_PASSWORD ? sha224Hex(env.TROJAN_PASSWORD) : null;
  if (!vless && !trojanHash) {
    return new Response('Belum ada UUID atau TROJAN_PASSWORD', { status: 500 });
  }
  const [client, server] = Object.values(new WebSocketPair());
  server.accept();
  server.binaryType = 'arraybuffer';
  session(server, { vless, trojanHash });
  return new Response(null, { status: 101, webSocket: client });
}

function session(ws, opts) {
  let buf = new Uint8Array(0);
  let headerDone = false;
  let proto = null;     // 'vless' | 'trojan'
  let udp = false;
  let version = 0;
  let respSent = false;
  let socket = null;
  let writer = null;
  let target = '-';

  const sendToClient = (data) => {
    if (ws.readyState !== 1) {
      console.log(`drop: ws state ${ws.readyState}, ${data.byteLength} byte, tujuan ${target}`);
      return;
    }
    if (!respSent) {
      if (proto === 'vless') {
        const out = new Uint8Array(data.byteLength + 2);
        out[0] = version; // versi VLESS, lalu panjang addon 0
        out.set(data, 2);
        ws.send(out);
      } else {
        ws.send(data); // Trojan tidak punya header respons
      }
      respSent = true;
      console.log(`header respons terkirim, ${data.byteLength} byte payload, tujuan ${target}`);
    } else {
      ws.send(data);
    }
  };

  const pipeFromRemote = async () => {
    let total = 0;
    let chunks = 0;
    try {
      await socket.readable.pipeTo(new WritableStream({
        write: (chunk) => {
          total += chunk.byteLength;
          chunks++;
          sendToClient(chunk);
        },
      }));
      console.log(`remote EOF, ${chunks} chunk, ${total} byte, tujuan ${target}`);
    } catch (e) {
      console.error(`remote error setelah ${total} byte, tujuan ${target}:`, String(e));
    }
    console.log(`pipeFromRemote selesai, ${total} byte, header terkirim ${respSent}, tujuan ${target}`);
    try { ws.close(); } catch {}
  };

  // UDP: hanya DNS (port 53) untuk VLESS, diteruskan ke DoH
  const drainDns = async () => {
    while (buf.length >= 2) {
      const len = (buf[0] << 8) | buf[1];
      if (buf.length < 2 + len) return;
      const query = buf.slice(2, 2 + len);
      buf = buf.subarray(2 + len);
      try {
        const res = await fetch('https://dns.google/dns-query', {
          method: 'POST',
          headers: {
            'content-type': 'application/dns-message',
            accept: 'application/dns-message',
          },
          body: query,
        });
        const answer = new Uint8Array(await res.arrayBuffer());
        const frame = new Uint8Array(2 + answer.length);
        frame[0] = answer.length >> 8;
        frame[1] = answer.length & 0xff;
        frame.set(answer, 2);
        sendToClient(frame);
      } catch (e) {
        console.error('doh:', String(e));
      }
    }
  };

  ws.addEventListener('message', async (ev) => {
    try {
      const chunk = ev.data instanceof Blob
        ? new Uint8Array(await ev.data.arrayBuffer())
        : toBytes(ev.data);

      if (!headerDone) {
        buf = concat(buf, chunk);
        if (buf.length === 0) return;

        // Trojan diawali hash hex (0-9a-f); VLESS diawali versi 0x00.
        const isTrojan = /[0-9a-f]/.test(String.fromCharCode(buf[0]));
        let h;
        if (isTrojan) {
          h = opts.trojanHash ? parseTrojan(buf, opts.trojanHash) : { error: 'Trojan belum diatur' };
        } else {
          h = opts.vless ? parseVless(buf, opts.vless) : { error: 'VLESS belum diatur' };
        }
        if (h === null) return; // header belum lengkap
        if (h.error) {
          console.error('ditolak:', h.error);
          ws.close();
          return;
        }

        headerDone = true;
        proto = h.proto;
        version = h.version ?? 0;
        buf = h.rest;
        target = `${h.host}:${h.port}`;
        console.log(`${proto.toUpperCase()} ${h.udp ? 'UDP' : 'TCP'} ${target}, payload awal ${buf.length} byte`);

        if (h.udp) {
          if (h.port !== 53) {
            console.log(`UDP port ${h.port} ditolak, menutup`);
            ws.close();
            return;
          }
          udp = true;
          await drainDns();
          return;
        }

        socket = connect({ hostname: h.host, port: h.port });
        socket.closed
          .then(() => console.log(`socket closed, tujuan ${target}`))
          .catch((e) => console.error(`socket closed error, tujuan ${target}:`, String(e)));
        writer = socket.writable.getWriter();
        pipeFromRemote();
        if (buf.length) {
          writer.write(buf).catch((e) => console.error(`write awal, tujuan ${target}:`, String(e)));
        }
        buf = new Uint8Array(0);
        return;
      }

      if (udp) {
        buf = concat(buf, chunk);
        await drainDns();
        return;
      }

      writer.write(chunk).catch((e) => console.error(`write, tujuan ${target}:`, String(e)));
    } catch (e) {
      console.error('message error:', e?.stack || String(e));
      try { ws.close(); } catch {}
    }
  });

  ws.addEventListener('close', (ev) => {
    console.log(`client close kode ${ev.code}, tujuan ${target}`);
    try { socket?.close(); } catch {}
  });

  ws.addEventListener('error', (ev) => {
    console.error(`ws error, tujuan ${target}:`, String(ev?.message || ev));
  });
}

function parseVless(buf, uuid) {
  if (buf.length < 18) return null;
  for (let i = 0; i < 16; i++) {
    if (buf[1 + i] !== uuid[i]) return { error: 'UUID VLESS tidak cocok' };
  }

  let p = 18 + buf[17]; // lewati addon
  if (buf.length < p + 4) return null;

  const cmd = buf[p];
  if (cmd !== 1 && cmd !== 2) return { error: `command ${cmd} tidak didukung` };
  const port = (buf[p + 1] << 8) | buf[p + 2];
  const atyp = buf[p + 3];
  p += 4;

  const addr = parseAddr(buf, p, atyp, 'vless');
  if (addr === null) return null;
  if (addr.error) return addr;
  p = addr.next;

  return { proto: 'vless', version: buf[0], udp: cmd === 2, host: addr.host, port, rest: buf.subarray(p) };
}

// Format Trojan: hash(56 hex) CRLF cmd(1) atyp addr port(2) CRLF payload
function parseTrojan(buf, hashHex) {
  if (buf.length < 58) return null;
  const pass = new TextDecoder().decode(buf.subarray(0, 56));
  if (buf[56] !== 13 || buf[57] !== 10) return { error: 'format Trojan salah' };
  if (pass !== hashHex) return { error: 'password Trojan tidak cocok' };

  let p = 58;
  if (buf.length < p + 2) return null;
  const cmd = buf[p];
  const atyp = buf[p + 1];
  p += 2;
  if (cmd !== 1) return { error: `command Trojan ${cmd} tidak didukung` };

  const addr = parseAddr(buf, p, atyp, 'trojan');
  if (addr === null) return null;
  if (addr.error) return addr;
  p = addr.next;

  if (buf.length < p + 4) return null;
  const port = (buf[p] << 8) | buf[p + 1];
  if (buf[p + 2] !== 13 || buf[p + 3] !== 10) return { error: 'format Trojan salah (CRLF)' };
  p += 4;

  return { proto: 'trojan', udp: false, host: addr.host, port, rest: buf.subarray(p) };
}

// Kode tipe alamat berbeda: VLESS (domain=2, IPv6=3), Trojan (domain=3, IPv6=4)
function parseAddr(buf, p, atyp, proto) {
  const DOMAIN = proto === 'vless' ? 2 : 3;
  const IPV6 = proto === 'vless' ? 3 : 4;
  if (atyp === 1) {
    if (buf.length < p + 4) return null;
    return { host: Array.from(buf.subarray(p, p + 4)).join('.'), next: p + 4 };
  }
  if (atyp === DOMAIN) {
    if (buf.length < p + 1) return null;
    const len = buf[p];
    if (buf.length < p + 1 + len) return null;
    return { host: new TextDecoder().decode(buf.subarray(p + 1, p + 1 + len)), next: p + 1 + len };
  }
  if (atyp === IPV6) {
    if (buf.length < p + 16) return null;
    const dv = new DataView(buf.buffer, buf.byteOffset + p, 16);
    const parts = [];
    for (let k = 0; k < 16; k += 2) parts.push(dv.getUint16(k).toString(16));
    return { host: parts.join(':'), next: p + 16 };
  }
  return { error: `tipe alamat ${atyp} tidak dikenal` };
}

// ---------- Admin API ----------

async function handleApi(request, env, url) {
  const key = request.headers.get('x-admin-key') || '';
  if (!env.ADMIN_KEY || !safeEqual(key, env.ADMIN_KEY)) {
    return json({ error: 'Kunci salah, atau ADMIN_KEY belum diatur' }, 401);
  }

  if (url.pathname === '/api/info' && request.method === 'GET') {
    return json({
      host: url.host,
      vlessReady: !!uuidToBytes(env.UUID || ''),
      trojanReady: !!env.TROJAN_PASSWORD,
      fingerprints: FINGERPRINTS,
    });
  }

  if (url.pathname === '/api/link' && request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'JSON tidak valid' }, 400); }
    return buildLink(body, env, url.host);
  }

  return json({ error: 'Tidak ditemukan' }, 404);
}

function buildLink(body, env, host) {
  const protocol = body.protocol;
  if (protocol === 'vless' && !env.UUID) return json({ error: 'Secret UUID belum diatur' }, 400);
  if (protocol === 'trojan' && !env.TROJAN_PASSWORD) return json({ error: 'Secret TROJAN_PASSWORD belum diatur' }, 400);
  if (protocol !== 'vless' && protocol !== 'trojan') return json({ error: 'Protokol harus vless atau trojan' }, 400);

  const address = String(body.address || host).trim();
  const sni = String(body.sni || host).trim();
  const port = Number(body.port || 443);
  let path = String(body.path || '/').trim();
  if (!path.startsWith('/')) path = '/' + path;
  const fp = FINGERPRINTS.includes(body.fingerprint) ? body.fingerprint : 'chrome';

  if (!/^[a-zA-Z0-9.-]+$/.test(address) || !/^[a-zA-Z0-9.-]+$/.test(sni)) {
    return json({ error: 'Alamat atau SNI mengandung karakter tidak valid' }, 400);
  }
  const allowedPorts = host.endsWith('workers.dev') ? [443] : PORTS_CUSTOM;
  if (!allowedPorts.includes(port)) {
    return json({ error: `Port ${port} tidak didukung untuk host ini. Pilihan: ${allowedPorts.join(', ')}` }, 400);
  }

  const query = [
    'security=tls',
    `sni=${encodeURIComponent(sni)}`,
    `fp=${fp}`,
    'alpn=http%2F1.1',
    'type=ws',
    `host=${encodeURIComponent(sni)}`,
    `path=${encodeURIComponent(path)}`,
  ];
  const name = encodeURIComponent(`${protocol}-${host}`);

  let link;
  if (protocol === 'vless') {
    link = `vless://${env.UUID}@${address}:${port}?encryption=none&${query.join('&')}#${name}`;
  } else {
    link = `trojan://${encodeURIComponent(env.TROJAN_PASSWORD)}@${address}:${port}?${query.join('&')}#${name}`;
  }
  return json({ link });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------- Helpers ----------

function uuidToBytes(uuid) {
  const hex = uuid.replace(/-/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function toBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new TextEncoder().encode(String(data));
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}
