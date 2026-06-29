// Canonical encoding shared by every Postcept signature. Produces the same bytes
// the Postcept API signs, so signatures can be verified without calling Postcept.

// Every non-ASCII code unit, to mirror Python's json.dumps(ensure_ascii=True).
const NON_ASCII = new RegExp("[\\u0080-\\uffff]", "g");

/** JSON-encode a primitive the way Python's json.dumps(ensure_ascii=True) does. */
export function asciiJson(value: unknown): string {
  return JSON.stringify(value).replace(
    NON_ASCII,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")
  );
}

/** Deterministic JSON: keys sorted, no whitespace, non-ASCII escaped. */
export function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return (
      "{" +
      Object.keys(obj)
        .sort()
        .map((k) => asciiJson(k) + ":" + canonicalize(obj[k]))
        .join(",") +
      "}"
    );
  }
  return asciiJson(value);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// The API spells UTC timestamps with a trailing "Z". Some serializers re-spell that
// as "+00:00", so try both when verifying.
export const TIMESTAMP_SPELLINGS: Array<(s: string) => string> = [
  (s) => s,
  (s) => s.replace(/Z$/, "+00:00"),
  (s) => s.replace(/\+00:00$/, "Z"),
];

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  return bytesToHex(await sha256(data));
}
