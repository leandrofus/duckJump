// Graphical sessions (VNC, RDP): the display operations of PTP kind 0x04
// and the input events of kind 0x05. Formats: paltad/crates/palta-proto/src/gfx.rs.

export const KIND_DISPLAY = 0x04
export const KIND_INPUT = 0x05

export type DisplayOp =
  | { op: 'size'; w: number; h: number }
  | { op: 'image'; x: number; y: number; w: number; h: number; mime: string; data: Uint8Array }
  | { op: 'copy'; sx: number; sy: number; w: number; h: number; dx: number; dy: number }
  | { op: 'fill'; x: number; y: number; w: number; h: number; r: number; g: number; b: number }
  | { op: 'cursor'; hx: number; hy: number; w: number; h: number; png: Uint8Array }
  | { op: 'sync'; frame: number }

/** Parses one display payload (without the kind byte). */
export function parseDisplay(b: Uint8Array): DisplayOp | null {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength)
  const u16 = (i: number) => v.getUint16(i)
  switch (b[0]) {
    case 0x01: return { op: 'size', w: u16(1), h: u16(3) }
    case 0x02: return { op: 'image', x: u16(1), y: u16(3), w: u16(5), h: u16(7), mime: b[9] === 2 ? 'image/jpeg' : 'image/png', data: b.subarray(10) }
    case 0x03: return { op: 'copy', sx: u16(1), sy: u16(3), w: u16(5), h: u16(7), dx: u16(9), dy: u16(11) }
    case 0x04: return { op: 'fill', x: u16(1), y: u16(3), w: u16(5), h: u16(7), r: b[9], g: b[10], b: b[11] }
    case 0x05: return { op: 'cursor', hx: u16(1), hy: u16(3), w: u16(5), h: u16(7), png: b.subarray(9) }
    case 0x06: return { op: 'sync', frame: v.getUint32(1) }
  }
  return null
}

/**
 * Applies display operations to a canvas strictly in order. Images are
 * decoded as soon as they arrive (in parallel) but drawn in sequence.
 */
export class Painter {
  private chain: Promise<void> = Promise.resolve()
  private ctx: CanvasRenderingContext2D
  private cursorURL = ''
  canvas: HTMLCanvasElement
  onCursor?: (css: string) => void

  constructor(canvas: HTMLCanvasElement) {
    this.canvas = canvas
    this.ctx = canvas.getContext('2d', { alpha: false })!
  }

  /** Queues an op; `after` runs once it (and everything before) is drawn. */
  push(op: DisplayOp, after?: () => void) {
    const decoded = op.op === 'image' ? createImageBitmap(new Blob([op.data as BlobPart], { type: op.mime })) : null
    this.chain = this.chain
      .then(async () => this.apply(op, decoded ? await decoded : null))
      .catch(() => {}) // a broken tile must not stop the session
      .then(() => after?.())
  }

  /** Resolves when everything queued is drawn. */
  idle() {
    return this.chain
  }

  private apply(op: DisplayOp, bmp: ImageBitmap | null) {
    const c = this.ctx
    switch (op.op) {
      case 'size':
        this.canvas.width = op.w
        this.canvas.height = op.h
        c.fillStyle = '#000'
        c.fillRect(0, 0, op.w, op.h)
        break
      case 'image':
        if (bmp) {
          c.drawImage(bmp, op.x, op.y)
          bmp.close()
        }
        break
      case 'copy':
        c.drawImage(this.canvas, op.sx, op.sy, op.w, op.h, op.dx, op.dy, op.w, op.h)
        break
      case 'fill':
        c.fillStyle = `rgb(${op.r},${op.g},${op.b})`
        c.fillRect(op.x, op.y, op.w, op.h)
        break
      case 'cursor': {
        if (this.cursorURL) URL.revokeObjectURL(this.cursorURL)
        this.cursorURL = ''
        if (!op.w || !op.h) {
          this.onCursor?.('default')
          break
        }
        this.cursorURL = URL.createObjectURL(new Blob([op.png as BlobPart], { type: 'image/png' }))
        this.onCursor?.(`url(${this.cursorURL}) ${op.hx} ${op.hy}, default`)
        break
      }
    }
  }

  dispose() {
    if (this.cursorURL) URL.revokeObjectURL(this.cursorURL)
  }
}

// ---- input ----

/** KEY with the physical scancode (RDP uses it; VNC uses the keysym). */
export function keyEvent(keysym: number, down: boolean, scancode = 0) {
  const b = new Uint8Array(9)
  const v = new DataView(b.buffer)
  b[0] = KIND_INPUT
  b[1] = 0x01
  v.setUint32(2, keysym)
  b[6] = down ? 1 : 0
  v.setUint16(7, scancode)
  return b
}

// KeyboardEvent.code -> PC scancode set 1 (0xE0xx = extended). The server
// applies its own keyboard layout to these physical keys.
const SCANCODES: Record<string, number> = {
  Escape: 0x01, Digit1: 0x02, Digit2: 0x03, Digit3: 0x04, Digit4: 0x05, Digit5: 0x06, Digit6: 0x07, Digit7: 0x08,
  Digit8: 0x09, Digit9: 0x0a, Digit0: 0x0b, Minus: 0x0c, Equal: 0x0d, Backspace: 0x0e, Tab: 0x0f,
  KeyQ: 0x10, KeyW: 0x11, KeyE: 0x12, KeyR: 0x13, KeyT: 0x14, KeyY: 0x15, KeyU: 0x16, KeyI: 0x17, KeyO: 0x18, KeyP: 0x19,
  BracketLeft: 0x1a, BracketRight: 0x1b, Enter: 0x1c, ControlLeft: 0x1d,
  KeyA: 0x1e, KeyS: 0x1f, KeyD: 0x20, KeyF: 0x21, KeyG: 0x22, KeyH: 0x23, KeyJ: 0x24, KeyK: 0x25, KeyL: 0x26,
  Semicolon: 0x27, Quote: 0x28, Backquote: 0x29, ShiftLeft: 0x2a, Backslash: 0x2b,
  KeyZ: 0x2c, KeyX: 0x2d, KeyC: 0x2e, KeyV: 0x2f, KeyB: 0x30, KeyN: 0x31, KeyM: 0x32,
  Comma: 0x33, Period: 0x34, Slash: 0x35, ShiftRight: 0x36, NumpadMultiply: 0x37, AltLeft: 0x38, Space: 0x39, CapsLock: 0x3a,
  F1: 0x3b, F2: 0x3c, F3: 0x3d, F4: 0x3e, F5: 0x3f, F6: 0x40, F7: 0x41, F8: 0x42, F9: 0x43, F10: 0x44,
  NumLock: 0x45, ScrollLock: 0x46, Numpad7: 0x47, Numpad8: 0x48, Numpad9: 0x49, NumpadSubtract: 0x4a,
  Numpad4: 0x4b, Numpad5: 0x4c, Numpad6: 0x4d, NumpadAdd: 0x4e, Numpad1: 0x4f, Numpad2: 0x50, Numpad3: 0x51,
  Numpad0: 0x52, NumpadDecimal: 0x53, IntlBackslash: 0x56, F11: 0x57, F12: 0x58, IntlRo: 0x73, IntlYen: 0x7d,
  NumpadEnter: 0xe01c, ControlRight: 0xe01d, NumpadDivide: 0xe035, PrintScreen: 0xe037, AltRight: 0xe038,
  Home: 0xe047, ArrowUp: 0xe048, PageUp: 0xe049, ArrowLeft: 0xe04b, ArrowRight: 0xe04d, End: 0xe04f,
  ArrowDown: 0xe050, PageDown: 0xe051, Insert: 0xe052, Delete: 0xe053, MetaLeft: 0xe05b, MetaRight: 0xe05c,
  ContextMenu: 0xe05d,
}

export function scancodeFor(e: KeyboardEvent) {
  return SCANCODES[e.code] ?? 0
}

export function pointerEvent(x: number, y: number, buttons: number) {
  const b = new Uint8Array(7)
  const v = new DataView(b.buffer)
  b[0] = KIND_INPUT
  b[1] = 0x02
  v.setUint16(2, Math.max(0, Math.round(x)))
  v.setUint16(4, Math.max(0, Math.round(y)))
  b[6] = buttons
  return b
}

export function ackEvent(frame: number) {
  const b = new Uint8Array(6)
  b[0] = KIND_INPUT
  b[1] = 0x03
  new DataView(b.buffer).setUint32(2, frame)
  return b
}

/** Browser mouse buttons (MouseEvent.buttons) -> RFB button mask. */
export function buttonMask(buttons: number) {
  return (buttons & 1 ? 1 : 0) | (buttons & 4 ? 2 : 0) | (buttons & 2 ? 4 : 0)
}

const SPECIAL: Record<string, number> = {
  Backspace: 0xff08, Tab: 0xff09, Enter: 0xff0d, Escape: 0xff1b, Delete: 0xffff, Insert: 0xff63,
  Home: 0xff50, End: 0xff57, PageUp: 0xff55, PageDown: 0xff56,
  ArrowLeft: 0xff51, ArrowUp: 0xff52, ArrowRight: 0xff53, ArrowDown: 0xff54,
  CapsLock: 0xffe5, NumLock: 0xff7f, ScrollLock: 0xff14, Pause: 0xff13, PrintScreen: 0xff61, ContextMenu: 0xff67,
  AltGraph: 0xfe03,
}
const BY_CODE: Record<string, number> = {
  ShiftLeft: 0xffe1, ShiftRight: 0xffe2, ControlLeft: 0xffe3, ControlRight: 0xffe4,
  AltLeft: 0xffe9, AltRight: 0xffea, MetaLeft: 0xffeb, MetaRight: 0xffec, OSLeft: 0xffeb, OSRight: 0xffec,
  NumpadEnter: 0xff8d,
}

/** X11 keysym for a keyboard event, or 0 if it has none (dead keys…). */
export function keysymFor(e: KeyboardEvent): number {
  if (BY_CODE[e.code]) return BY_CODE[e.code]
  if (SPECIAL[e.key]) return SPECIAL[e.key]
  const f = /^F(\d{1,2})$/.exec(e.key)
  if (f && +f[1] >= 1 && +f[1] <= 24) return 0xffbe + +f[1] - 1
  if ([...e.key].length === 1) {
    const cp = e.key.codePointAt(0)!
    // Latin-1 keysyms equal the code point; the rest use the Unicode range.
    return cp >= 0x20 && cp <= 0xff ? cp : 0x01000000 + cp
  }
  return 0
}

export const KEYSYM = { Control_L: 0xffe3, Alt_L: 0xffe9, Delete: 0xffff, Super_L: 0xffeb, Tab: 0xff09, Escape: 0xff1b }
export const SCANCODE = { Control_L: 0x1d, Alt_L: 0x38, Delete: 0xe053 }

// ---- recordings (DJGFX1) ----

export interface GfxRecord {
  t: number
  kind: number // 1 display, 2 input
  payload: Uint8Array
}

/** Parses a DJGFX1 recording; a truncated last record (still being written) is ignored. */
export function parseRecording(buf: ArrayBuffer): { header: { width: number; height: number; timestamp: number }; records: GfxRecord[] } {
  const b = new Uint8Array(buf)
  const magic = new TextDecoder().decode(b.subarray(0, 7))
  if (magic !== 'DJGFX1\n') throw new Error('not a DuckJump graphical recording')
  const nl = b.indexOf(10, 7)
  const header = JSON.parse(new TextDecoder().decode(b.subarray(7, nl)))
  const v = new DataView(buf)
  const records: GfxRecord[] = []
  let i = nl + 1
  while (i + 13 <= b.length) {
    const t = v.getFloat64(i)
    const kind = b[i + 8]
    const len = v.getUint32(i + 9)
    if (i + 13 + len > b.length) break
    records.push({ t, kind, payload: b.subarray(i + 13, i + 13 + len) })
    i += 13 + len
  }
  return { header, records }
}
