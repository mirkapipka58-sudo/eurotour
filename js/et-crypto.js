/* End-to-end encryption for the site <-> bot bridge.

   ntfy.sh topics are public, and this repository is public too, so the topic
   name is not a secret. Confidentiality comes from encryption only:
   - visitor -> bot: ECDH P-256 with an ephemeral key + HKDF-SHA256 + AES-256-GCM.
     Only the bot holds the private key (GitHub Actions secret BRIDGE_PRIVATE_KEY).
   - bot -> visitor: AES-256-GCM with a random per-visitor key (rk), which the
     browser generates and sends to the bot inside the encrypted messages.
   Without WebCrypto nothing is sent: there is no plaintext fallback. */
(function () {
  'use strict';
  var CFG = window.__SITE_BRIDGE || {};
  var subtle = window.crypto && window.crypto.subtle;
  var RK_KEY = 'et_chat_rk';
  var INFO = new TextEncoder().encode('eurotour-bridge-v2');

  function b64(buf) {
    var s = '', a = new Uint8Array(buf);
    for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s);
  }
  function unb64(str) {
    var s = atob(str), a = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
    return a;
  }
  function randomBytes(n) { return window.crypto.getRandomValues(new Uint8Array(n)); }

  var memoryRk = null;
  function replyKeyB64() {
    var v = null;
    try { v = localStorage.getItem(RK_KEY); } catch (e) {}
    if (!v) v = memoryRk;
    if (!v) {
      v = b64(randomBytes(32));
      memoryRk = v;
      try { localStorage.setItem(RK_KEY, v); } catch (e) {}
    }
    return v;
  }
  function aesKey(raw, usages) { return subtle.importKey('raw', raw, 'AES-GCM', false, usages); }

  function seal(obj) {
    if (!subtle || !CFG.pub) return Promise.reject(new Error('crypto unavailable'));
    var inner = Object.assign({}, obj, { rk: replyKeyB64() });
    var curve = { name: 'ECDH', namedCurve: 'P-256' };
    return Promise.all([
      subtle.importKey('raw', unb64(CFG.pub), curve, false, []),
      subtle.generateKey(curve, true, ['deriveBits'])
    ]).then(function (r) {
      var pub = r[0], eph = r[1];
      return subtle.deriveBits({ name: 'ECDH', public: pub }, eph.privateKey, 256).then(function (bits) {
        return subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
      }).then(function (ikm) {
        return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: INFO }, ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
      }).then(function (key) {
        var iv = randomBytes(12);
        return Promise.all([
          subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(JSON.stringify(inner))),
          subtle.exportKey('raw', eph.publicKey)
        ]).then(function (x) {
          return JSON.stringify({ v: 2, e: b64(x[1]), i: b64(iv), c: b64(x[0]) });
        });
      });
    });
  }

  /* Encrypt a file with a fresh key; the key travels inside the sealed message. */
  function sealFile(file) {
    if (!subtle) return Promise.reject(new Error('crypto unavailable'));
    var raw = randomBytes(32), iv = randomBytes(12);
    return Promise.all([aesKey(raw, ['encrypt']), file.arrayBuffer()]).then(function (r) {
      return subtle.encrypt({ name: 'AES-GCM', iv: iv }, r[0], r[1]);
    }).then(function (ct) {
      return { blob: new Blob([ct], { type: 'application/octet-stream' }), key: b64(raw), iv: b64(iv) };
    });
  }

  function open(text) {
    return Promise.resolve().then(function () {
      var env = JSON.parse(text);
      if (!env || env.v !== 2 || !env.i || !env.c) throw new Error('bad envelope');
      return aesKey(unb64(replyKeyB64()), ['decrypt']).then(function (key) {
        return subtle.decrypt({ name: 'AES-GCM', iv: unb64(env.i) }, key, unb64(env.c));
      }).then(function (plain) { return JSON.parse(new TextDecoder().decode(plain)); });
    });
  }

  /* Decode one ntfy event. Messages above ntfy's 4 KB limit arrive as an attachment. */
  function openEvent(d) {
    var msg = d.message || '';
    if (msg.charAt(0) === '{') return open(msg);
    if (d.attachment && d.attachment.url) {
      return fetch(d.attachment.url).then(function (r) { return r.text(); }).then(open);
    }
    return Promise.reject(new Error('not encrypted'));
  }

  function openFile(url, ivB64, type) {
    return Promise.all([
      fetch(url).then(function (r) { if (!r.ok) throw new Error('download failed'); return r.arrayBuffer(); }),
      aesKey(unb64(replyKeyB64()), ['decrypt'])
    ]).then(function (x) {
      return subtle.decrypt({ name: 'AES-GCM', iv: unb64(ivB64) }, x[1], x[0]);
    }).then(function (plain) { return new Blob([plain], { type: type || 'application/octet-stream' }); });
  }

  window.EtCrypto = { available: !!(subtle && CFG.pub), seal: seal, sealFile: sealFile, open: open, openEvent: openEvent, openFile: openFile };
})();
