import { secp256k1 } from "@noble/curves/secp256k1";
import { hmac } from "@noble/hashes/hmac";
import { keccak_256 } from "@noble/hashes/sha3";
import { sha512 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";

const HARDENED_KEY_START = 0x80000000;
const CHAIN_CODE_BYTES = 32;
const COMPRESSED_PUBKEY_BYTES = 33;

/**
 * Derive a compressed child public key from a compressed master public key.
 * Uses BIP-32 non-hardened derivation (public key only, no private key needed).
 *
 * @param masterPubKeyCompressed - 33-byte compressed secp256k1 public key
 * @param chainCodeHex - 32-byte chain code as hex string (64 chars)
 * @param path - derivation path as array of non-hardened indices
 * @returns 33-byte compressed child public key
 * @throws if any index >= 0x80000000 (hardened), or if derivation produces invalid key
 */
export function deriveSecp256k1ChildCompressed(
  masterPubKeyCompressed: Uint8Array,
  chainCodeHex: string,
  path: number[]
): Uint8Array {
  if (masterPubKeyCompressed.length !== COMPRESSED_PUBKEY_BYTES) {
    throw new Error(
      `invalid master pubkey length: ${masterPubKeyCompressed.length}`
    );
  }

  let currentPubKey: Uint8Array;
  try {
    currentPubKey = secp256k1.ProjectivePoint.fromHex(
      masterPubKeyCompressed
    ).toRawBytes(true);
  } catch (error) {
    throw new Error(`decode master pubkey: ${toErrorMessage(error)}`);
  }

  let currentChainCode = parseChainCode(chainCodeHex);

  for (let depth = 0; depth < path.length; depth += 1) {
    const index = path[depth];
    validateChildIndex(index, depth);

    const data = new Uint8Array(COMPRESSED_PUBKEY_BYTES + 4);
    data.set(currentPubKey, 0);
    writeUint32BE(data, index, COMPRESSED_PUBKEY_BYTES);

    const ilr = hmac(sha512, currentChainCode, data);
    const il = ilr.slice(0, CHAIN_CODE_BYTES);
    const ir = ilr.slice(CHAIN_CODE_BYTES);

    const ilNum = bytesToBigInt(il);
    if (ilNum === 0n || ilNum >= secp256k1.CURVE.n) {
      throw new Error(`invalid IL for index ${index}`);
    }

    const deltaPoint = secp256k1.ProjectivePoint.BASE.multiply(ilNum);
    const parentPoint = secp256k1.ProjectivePoint.fromHex(currentPubKey);
    const childPoint = parentPoint.add(deltaPoint);

    if (childPoint.equals(secp256k1.ProjectivePoint.ZERO)) {
      throw new Error(`invalid child point at index ${index}`);
    }

    currentPubKey = childPoint.toRawBytes(true);
    currentChainCode = ir;
  }

  return currentPubKey;
}

/**
 * Derive an Ethereum address from a compressed master public key + derivation path.
 * Combines BIP-32 derivation with Ethereum address computation (keccak256 of uncompressed key).
 *
 * @returns Checksummed Ethereum address string (e.g. "0x742d35Cc...")
 */
export function deriveEthereumAddress(
  masterPubKeyCompressed: Uint8Array,
  chainCodeHex: string,
  path: number[]
): string {
  const childCompressed = deriveSecp256k1ChildCompressed(
    masterPubKeyCompressed,
    chainCodeHex,
    path
  );

  const childPoint = secp256k1.ProjectivePoint.fromHex(childCompressed);
  const childUncompressed = childPoint.toRawBytes(false);
  const hash = keccak_256(childUncompressed.slice(1));
  const addressLowerHex = bytesToHex(hash.slice(-20));

  return toChecksumAddress(addressLowerHex);
}

/**
 * Compress an uncompressed secp256k1 public key.
 * @param uncompressed - 64 bytes (X||Y, no 04 prefix) or 65 bytes (with 04 prefix)
 * @returns 33 bytes compressed (02/03 prefix + X)
 */
export function compressPublicKey(uncompressed: Uint8Array): Uint8Array {
  let uncompressedWithPrefix: Uint8Array;

  if (uncompressed.length === 64) {
    uncompressedWithPrefix = new Uint8Array(65);
    uncompressedWithPrefix[0] = 0x04;
    uncompressedWithPrefix.set(uncompressed, 1);
  } else if (uncompressed.length === 65) {
    if (uncompressed[0] !== 0x04) {
      throw new Error(
        `invalid uncompressed public key prefix: ${uncompressed[0]}`
      );
    }
    uncompressedWithPrefix = uncompressed;
  } else {
    throw new Error(`invalid uncompressed public key length: ${uncompressed.length}`);
  }

  try {
    return secp256k1.ProjectivePoint.fromHex(uncompressedWithPrefix).toRawBytes(
      true
    );
  } catch (error) {
    throw new Error(`invalid secp256k1 public key: ${toErrorMessage(error)}`);
  }
}

function validateChildIndex(index: number, depth: number): void {
  if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) {
    throw new Error(`invalid child index at path[${depth}]: ${index}`);
  }
  if (index >= HARDENED_KEY_START) {
    throw new Error(`hardened derivation not supported: ${index}`);
  }
}

function parseChainCode(chainCodeHex: string): Uint8Array {
  const normalized = chainCodeHex.startsWith("0x")
    ? chainCodeHex.slice(2)
    : chainCodeHex;

  let chainCode: Uint8Array;
  try {
    chainCode = hexToBytes(normalized);
  } catch (error) {
    throw new Error(`decode chain code: ${toErrorMessage(error)}`);
  }

  if (chainCode.length !== CHAIN_CODE_BYTES) {
    throw new Error(`invalid chain code length: ${chainCode.length}`);
  }

  return chainCode;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt(`0x${bytesToHex(bytes)}`);
}

function writeUint32BE(target: Uint8Array, value: number, offset: number): void {
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

function toChecksumAddress(addressLowerHex: string): string {
  const address = addressLowerHex.toLowerCase().replace(/^0x/, "");
  if (address.length !== 40) {
    throw new Error(`invalid Ethereum address length: ${address.length}`);
  }

  const hash = keccak_256(utf8ToBytes(address));
  let checksummed = "0x";

  for (let i = 0; i < address.length; i += 1) {
    const hashByte = hash[Math.floor(i / 2)];
    const nibble = i % 2 === 0 ? hashByte >> 4 : hashByte & 0x0f;
    checksummed += nibble >= 8 ? address[i].toUpperCase() : address[i];
  }

  return checksummed;
}

function toErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
