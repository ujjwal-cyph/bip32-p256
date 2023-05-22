import BN from "bn.js";
import * as elliptic from "elliptic";

const secp256r1 = new elliptic.ec("p256");

export const compressedToFullPublicKey = (publicKey: Uint8Array) => {
  const ec = new elliptic.ec("p256");
  const key = ec.keyFromPublic(publicKey);
  const fullPublicKey = key.getPublic(false, "hex");
  return fullPublicKey.slice(2);
};

export function isPoint(p: Uint8Array): boolean {
  try {
    const { result } = secp256r1.keyFromPublic(p).validate();
    return result;
  } catch {
    return false;
  }
}

export function isPrivate(d: Uint8Array): boolean {
  const { result } = secp256r1.keyFromPrivate(d).validate();
  return result;
}

export function pointFromScalar(
  d: Uint8Array,
  compressed?: boolean
): Uint8Array | null {
  if (!isPrivate(d)) return null;
  return new TextEncoder().encode(
    secp256r1.keyFromPrivate(d).getPublic((compressed ??= true), "hex")
  );
}

export function pointAddScalar(
  p: Uint8Array,
  tweak: Uint8Array,
  compressed?: boolean
): Uint8Array | null {
  if (new BN(tweak).isZero()) return p;
  if (!isPrivate(tweak)) return null;
  const point = (secp256r1.keyFromPublic(p) as any).pub;

  const result = secp256r1.g.mul(tweak).add(point);

  return Buffer.from(result.encode('hex', !!compressed), 'hex');
}

export function privateAdd(
  d: Uint8Array,
  tweak: Uint8Array
): Uint8Array | null {
  if (new BN(tweak).isZero()) return d;
  if (!isPrivate(tweak)) return null;

  return new BN(d)
    .add(new BN(tweak))
    .mod(secp256r1.n as any)
    .toBuffer();
}

export function sign(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array {
  const sig = secp256r1.sign(h, Buffer.from(d.buffer));
  return new TextEncoder().encode(sig.toDER("hex"));
}

export function verify(
  h: Uint8Array,
  Q: Uint8Array,
  signature: Uint8Array,
  strict?: boolean
): boolean {
  return secp256r1.verify(h, signature, Buffer.from(Q.buffer));
}
