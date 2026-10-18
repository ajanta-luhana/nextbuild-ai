/* NextBuild AI: real 3D pipeline model rendered on <canvas> with a small built-in 3D engine
   (rotation + perspective projection + depth-sorted shaded faces). No libraries, no inline styles.
   Drag to rotate, wheel/pinch not needed; it auto-rotates gently unless the user prefers reduced motion. */
"use strict";
(function () {
  const COL = {
    done: [25, 181, 142], now: [92, 120, 255], gate: [240, 178, 74], fail: [240, 112, 95], pending: [84, 99, 142],
  };
  const LABELS = ["Plan", "Plan approval", "Generate", "Verify", "Export approval", "Package", "Done"];
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // unit cuboid faces: 4 vertex indices (counter-clockwise from outside) and outward normal
  const V = [[-1, -1, -1], [1, -1, -1], [1, 1, -1], [-1, 1, -1], [-1, -1, 1], [1, -1, 1], [1, 1, 1], [-1, 1, 1]];
  const F = [[[4, 5, 6, 7], [0, 0, 1], 1.0], [[1, 0, 3, 2], [0, 0, -1], 0.62], [[5, 1, 2, 6], [1, 0, 0], 0.8], [[0, 4, 7, 3], [-1, 0, 0], 0.7],
    [[7, 6, 2, 3], [0, 1, 0], 1.18], [[0, 1, 5, 4], [0, -1, 0], 0.5]]; // +y is "up" in model space (flipped to screen later)

  function build(canvas, states, opts) {
    const names = (opts && opts.labels) || LABELS, n = states.length;
    const ctx = canvas.getContext("2d");
    let yaw = -0.62, pitch = 0.5, vyaw = reduce ? 0 : 0.004, drag = null, t0 = performance.now(), w = 0, h = 0, dpr = 1;
    const blocks = states.map((s, i) => ({ i, s: s || "pending", x: (i - (n - 1) / 2) * 1.38, hh: 0.55 + i * (1.8 / Math.max(1, n - 1)) }));

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth || 600; h = canvas.clientHeight || 300;
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
    }
    function xf(p) { // model -> camera space
      const cy = Math.cos(yaw), sy = Math.sin(yaw), cp = Math.cos(pitch), sp = Math.sin(pitch);
      const x1 = p[0] * cy + p[2] * sy, z1 = -p[0] * sy + p[2] * cy, y1 = p[1];
      return [x1, y1 * cp - z1 * sp, y1 * sp + z1 * cp];
    }
    function proj(c, scale) { const f = 11 / (11 + c[2]); return [w / 2 + c[0] * scale * f, h * 0.56 - c[1] * scale * f, f]; }

    function frame(now) {
      if (!canvas.isConnected) return;
      if (!drag) yaw += vyaw;
      const t = (now - t0) / 1000, scale = Math.min(w / (n * 1.38 + 0.9), h / 3.9), narrow = w < 720;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, w, h);
      // ground shadow plate
      const gp = [[-5.2, 0, -1.5], [5.2, 0, -1.5], [5.2, 0, 1.5], [-5.2, 0, 1.5]].map((p) => proj(xf([p[0], -0.02, p[2]]), scale));
      ctx.beginPath(); gp.forEach((p, k) => (k ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1]))); ctx.closePath();
      ctx.fillStyle = "rgba(120,140,255,.10)"; ctx.fill(); ctx.strokeStyle = "rgba(160,178,255,.25)"; ctx.stroke();

      const faces = [], labels = [];
      for (const b of blocks) {
        const lift = b.s === "now" || b.s === "gate" ? 0.22 + Math.sin(t * 2.4) * 0.07 : 0;
        const hy = b.hh / 2, base = COL[b.s] || COL.pending;
        const wob = b.s === "fail" ? Math.sin(t * 18) * 0.02 : 0;
        const pts = V.map((v) => xf([b.x + v[0] * 0.5 + wob, lift + hy + v[1] * hy, v[2] * 0.5]));
        for (const [idx, n, shade] of F) {
          const nn = xf([n[0] * 1, n[1] * 1, n[2] * 1]);
          if (nn[2] > 0.02) continue; // back-face cull (camera looks down +z)
          const poly = idx.map((k) => pts[k]), depth = poly.reduce((a, p) => a + p[2], 0) / 4;
          faces.push({ poly, depth, base, shade, glow: b.s === "now" || b.s === "gate", top: n[1] === 1 });
        }
        const topc = proj(xf([b.x, lift + b.hh + 0.35, 0]), scale);
        labels.push({ t: names[b.i], p: [topc[0], topc[1] - (narrow && b.i % 2 ? 24 : 0)], s: b.s, z: xf([b.x, 0, 0])[2] });
      }
      faces.sort((a, b) => b.depth - a.depth);
      for (const f of faces) {
        const pp = f.poly.map((p) => proj(p, scale));
        const m = f.shade, c = f.base.map((v) => Math.min(255, Math.round(v * m)));
        ctx.beginPath(); pp.forEach((p, k) => (k ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1]))); ctx.closePath();
        if (f.glow) { ctx.shadowColor = `rgba(${f.base[0]},${f.base[1]},${f.base[2]},.85)`; ctx.shadowBlur = 22; }
        ctx.fillStyle = `rgb(${c[0]},${c[1]},${c[2]})`; ctx.fill(); ctx.shadowBlur = 0;
        ctx.lineWidth = 1; ctx.strokeStyle = "rgba(255,255,255,.28)"; ctx.stroke();
        if (f.top) { // subtle gloss on the top face
          ctx.fillStyle = "rgba(255,255,255,.10)"; ctx.fill();
        }
      }
      ctx.font = "600 11.5px Segoe UI, system-ui, sans-serif"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
      for (const l of labels) {
        const tw = ctx.measureText(l.t).width + 14, x = l.p[0] - tw / 2, y = l.p[1] - 10;
        ctx.fillStyle = l.s === "pending" ? "rgba(20,28,60,.72)" : "rgba(8,14,36,.85)";
        ctx.beginPath(); ctx.roundRect ? ctx.roundRect(x, y, tw, 20, 10) : ctx.rect(x, y, tw, 20); ctx.fill();
        ctx.strokeStyle = `rgba(${(COL[l.s] || COL.pending).join(",")},.9)`; ctx.stroke();
        ctx.fillStyle = "#fff"; ctx.fillText(l.t, l.p[0], l.p[1]);
      }
      requestAnimationFrame(frame);
    }

    canvas.addEventListener("pointerdown", (e) => { drag = { x: e.clientX, y: e.clientY }; canvas.setPointerCapture(e.pointerId); canvas.classList.add("grabbing"); });
    canvas.addEventListener("pointermove", (e) => { if (!drag) return; yaw += (e.clientX - drag.x) * 0.01; pitch = Math.max(0.12, Math.min(1.25, pitch + (e.clientY - drag.y) * 0.006)); drag = { x: e.clientX, y: e.clientY }; });
    const end = () => { drag = null; canvas.classList.remove("grabbing"); };
    canvas.addEventListener("pointerup", end); canvas.addEventListener("pointercancel", end);
    canvas.addEventListener("keydown", (e) => { if (e.key === "ArrowLeft") yaw -= 0.15; if (e.key === "ArrowRight") yaw += 0.15; if (e.key === "ArrowUp") pitch = Math.min(1.25, pitch + 0.08); if (e.key === "ArrowDown") pitch = Math.max(0.12, pitch - 0.08); });
    if (window.ResizeObserver) new ResizeObserver(resize).observe(canvas); else window.addEventListener("resize", resize);
    resize(); requestAnimationFrame(frame);
  }
  window.NB3D = { mount: build };
})();
