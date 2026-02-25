import { secp256k1 } from "@noble/curves/secp256k1";
import { hmac } from "@noble/hashes/hmac";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { describe, expect, it, vi } from "vitest";
import {
  compressPublicKey,
  deriveEthereumAddress,
  deriveSecp256k1ChildCompressed,
} from "../src/ckdutil";
import { MpciumClient } from "../src/client";
import { KeyType } from "../src/types";

const CHAIN_CODE_HEX =
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const MASTER_PRIVATE_KEY_HEX =
  "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function writeUint32BE(target: Uint8Array, value: number, offset: number): void {
  const view = new DataView(target.buffer, target.byteOffset, target.byteLength);
  view.setUint32(offset, value, false);
}

function referenceDeriveSecp256k1Child(
  masterPubKeyCompressed: Uint8Array,
  chainCodeHex: string,
  path: number[]
): Uint8Array {
  let currentChainCode = hexToBytes(chainCodeHex);
  let currentPoint = secp256k1.ProjectivePoint.fromHex(masterPubKeyCompressed);

  for (const index of path) {
    if (index >= 0x80000000) {
      throw new Error(`hardened derivation not supported: ${index}`);
    }

    const data = new Uint8Array(37);
    data.set(currentPoint.toRawBytes(true), 0);
    writeUint32BE(data, index, 33);

    const ilr = hmac(sha512, currentChainCode, data);
    const il = ilr.slice(0, 32);
    const ir = ilr.slice(32);

    const ilNum = BigInt(`0x${bytesToHex(il)}`);
    if (ilNum === 0n || ilNum >= secp256k1.CURVE.n) {
      throw new Error(`invalid IL for index ${index}`);
    }

    const delta = secp256k1.ProjectivePoint.BASE.multiply(ilNum);
    const child = currentPoint.add(delta);
    if (child.equals(secp256k1.ProjectivePoint.ZERO)) {
      throw new Error(`invalid child point at index ${index}`);
    }

    currentPoint = child;
    currentChainCode = ir;
  }

  return currentPoint.toRawBytes(true);
}

function toChecksumAddress(addressLowerHex: string): string {
  const lower = addressLowerHex.toLowerCase().replace(/^0x/, "");
  const hash = keccak_256(utf8ToBytes(lower));
  let out = "0x";

  for (let i = 0; i < lower.length; i += 1) {
    const hashByte = hash[Math.floor(i / 2)];
    const nibble = i % 2 === 0 ? hashByte >> 4 : hashByte & 0x0f;
    out += nibble >= 8 ? lower[i].toUpperCase() : lower[i];
  }

  return out;
}

function referenceEthereumAddress(childCompressedPubKey: Uint8Array): string {
  const childPoint = secp256k1.ProjectivePoint.fromHex(childCompressedPubKey);
  const uncompressed = childPoint.toRawBytes(false);
  const hash = keccak_256(uncompressed.slice(1));
  const addressLowerHex = bytesToHex(hash.slice(-20));
  return toChecksumAddress(addressLowerHex);
}

function isChecksummedAddress(address: string): boolean {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    return false;
  }

  const lower = address.slice(2).toLowerCase();
  return toChecksumAddress(lower) === address;
}

function decodeXpub(xpub: string): {
  chainCode: Uint8Array;
  publicKey: Uint8Array;
} {
  const decoded = base58Decode(xpub);
  if (decoded.length !== 82) {
    throw new Error(`invalid xpub length: ${decoded.length}`);
  }

  const payload = decoded.slice(0, 78);
  const checksum = decoded.slice(78);
  const expectedChecksum = sha256(sha256(payload)).slice(0, 4);
  if (bytesToHex(checksum) !== bytesToHex(expectedChecksum)) {
    throw new Error("invalid xpub checksum");
  }

  const chainCode = payload.slice(13, 45);
  const publicKey = payload.slice(45, 78);
  return { chainCode, publicKey };
}

function base58Decode(input: string): Uint8Array {
  let value = 0n;
  for (const char of input) {
    const digit = BASE58_ALPHABET.indexOf(char);
    if (digit === -1) {
      throw new Error(`invalid base58 character: ${char}`);
    }
    value = value * 58n + BigInt(digit);
  }

  const decodedBytes: number[] = [];
  while (value > 0n) {
    decodedBytes.push(Number(value & 0xffn));
    value >>= 8n;
  }
  decodedBytes.reverse();

  let leadingZeros = 0;
  for (const char of input) {
    if (char !== "1") {
      break;
    }
    leadingZeros += 1;
  }

  const out = new Uint8Array(leadingZeros + decodedBytes.length);
  out.set(decodedBytes, leadingZeros);
  return out;
}

function createMockNatsConnection() {
  const jetstreamPublish = vi.fn(async (_subject: string, _data: Uint8Array) => {
    return { seq: 1n };
  });

  const nc = {
    status: async function* status() {
      return;
    },
    jetstream: () => ({
      publish: jetstreamPublish,
    }),
    publish: vi.fn(),
  };

  return { nc, jetstreamPublish };
}

type MockNc = ReturnType<typeof createMockNatsConnection>["nc"];

type SignTransactionClient = Pick<MpciumClient, "signTransaction"> & {
  ensureStreamsExist: () => Promise<void>;
};

function createSignTransactionClient(
  nc: MockNc,
  privateKeyByte: number
): SignTransactionClient {
  const ClientCtor = MpciumClient as unknown as {
    new (
      options: { nc: MockNc; keyPath: string },
      privateKey: Buffer
    ): SignTransactionClient;
  };

  const client = new ClientCtor(
    { nc, keyPath: "unused" },
    Buffer.alloc(32, privateKeyByte)
  );

  client.ensureStreamsExist = async () => {};
  return client;
}

describe("ckdutil", () => {
  const masterPrivateKey = hexToBytes(MASTER_PRIVATE_KEY_HEX);
  const masterPubCompressed = secp256k1.getPublicKey(masterPrivateKey, true);
  const masterPubUncompressed = secp256k1.getPublicKey(masterPrivateKey, false);

  it("A) derives expected child key via independent reference math", () => {
    const path = [44, 60, 0, 0, 0];
    const actual = deriveSecp256k1ChildCompressed(
      masterPubCompressed,
      CHAIN_CODE_HEX,
      path
    );
    const expected = referenceDeriveSecp256k1Child(
      masterPubCompressed,
      CHAIN_CODE_HEX,
      path
    );

    expect(bytesToHex(actual)).toBe(bytesToHex(expected));
  });

  it("B) derives checksummed Ethereum address and matches manual computation", () => {
    const path = [44, 60, 0, 0, 0];
    const derivedAddress = deriveEthereumAddress(
      masterPubCompressed,
      CHAIN_CODE_HEX,
      path
    );

    const childCompressed = referenceDeriveSecp256k1Child(
      masterPubCompressed,
      CHAIN_CODE_HEX,
      path
    );
    const manualAddress = referenceEthereumAddress(childCompressed);

    expect(isChecksummedAddress(derivedAddress)).toBe(true);
    expect(derivedAddress).toBe(manualAddress);
  });

  it("C) is deterministic and changes output with path/chain code changes", () => {
    const path0 = [44, 60, 0, 0, 0];
    const path1 = [44, 60, 0, 0, 1];
    const alternateChainCode =
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    const a1 = deriveEthereumAddress(masterPubCompressed, CHAIN_CODE_HEX, path0);
    const a2 = deriveEthereumAddress(masterPubCompressed, CHAIN_CODE_HEX, path0);
    const b = deriveEthereumAddress(masterPubCompressed, CHAIN_CODE_HEX, path1);
    const c = deriveEthereumAddress(
      masterPubCompressed,
      alternateChainCode,
      path0
    );

    expect(a1).toBe(a2);
    expect(a1).not.toBe(b);
    expect(a1).not.toBe(c);
  });

  it("D) supports empty/single/multi-level paths and distinct final indices", () => {
    const emptyPath = deriveSecp256k1ChildCompressed(
      masterPubCompressed,
      CHAIN_CODE_HEX,
      []
    );
    expect(bytesToHex(emptyPath)).toBe(bytesToHex(masterPubCompressed));

    const singleLevel = deriveSecp256k1ChildCompressed(
      masterPubCompressed,
      CHAIN_CODE_HEX,
      [0]
    );
    expect(singleLevel.length).toBe(33);

    const standard0 = deriveSecp256k1ChildCompressed(
      masterPubCompressed,
      CHAIN_CODE_HEX,
      [44, 60, 0, 0, 0]
    );
    const standard1 = deriveSecp256k1ChildCompressed(
      masterPubCompressed,
      CHAIN_CODE_HEX,
      [44, 60, 0, 0, 1]
    );

    expect(bytesToHex(standard0)).not.toBe(bytesToHex(standard1));

    const from64 = compressPublicKey(masterPubUncompressed.slice(1));
    const from65 = compressPublicKey(masterPubUncompressed);
    expect(bytesToHex(from64)).toBe(bytesToHex(masterPubCompressed));
    expect(bytesToHex(from65)).toBe(bytesToHex(masterPubCompressed));
  });

  it("E) validates hardened index, chain code, and invalid keys while allowing boundary indices", () => {
    expect(() =>
      deriveSecp256k1ChildCompressed(masterPubCompressed, CHAIN_CODE_HEX, [
        0x80000000,
      ])
    ).toThrow(/hardened derivation not supported/i);

    expect(() =>
      deriveSecp256k1ChildCompressed(masterPubCompressed, "abcd", [0])
    ).toThrow(/invalid chain code length/i);

    expect(() =>
      deriveSecp256k1ChildCompressed(new Uint8Array(32), CHAIN_CODE_HEX, [0])
    ).toThrow(/invalid master pubkey length/i);

    const invalidPoint = hexToBytes(
      "020000000000000000000000000000000000000000000000000000000000000007"
    );
    expect(() =>
      deriveSecp256k1ChildCompressed(invalidPoint, CHAIN_CODE_HEX, [0])
    ).toThrow(/decode master pubkey|invalid/i);

    const indexZero = deriveSecp256k1ChildCompressed(
      masterPubCompressed,
      CHAIN_CODE_HEX,
      [0]
    );
    expect(indexZero.length).toBe(33);

    const largeIndex = deriveSecp256k1ChildCompressed(
      masterPubCompressed,
      CHAIN_CODE_HEX,
      [0x7fffffff]
    );
    expect(largeIndex.length).toBe(33);
  });

  it("F) matches BIP-32 vector for non-hardened derivation", () => {
    // BIP-32 Test Vector 2: m -> m/0 (non-hardened)
    const parentXpub =
      "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
    const childXpub =
      "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";

    const parent = decodeXpub(parentXpub);
    const expectedChild = decodeXpub(childXpub);

    const derived = deriveSecp256k1ChildCompressed(
      parent.publicKey,
      bytesToHex(parent.chainCode),
      [0]
    );

    expect(bytesToHex(derived)).toBe(bytesToHex(expectedChild.publicKey));
  });

  it("G) includes derivation_path in SignTxMessage when provided", async () => {
    const { nc, jetstreamPublish } = createMockNatsConnection();
    const client = createSignTransactionClient(nc, 7);

    await client.signTransaction({
      walletId: "wallet-1",
      keyType: KeyType.Secp256k1,
      networkInternalCode: "ethereum-mainnet",
      tx: "AQID",
      derivationPath: [44, 60, 0, 0, 0],
    });

    const publishedPayload = jetstreamPublish.mock.calls[0][1] as Uint8Array;
    const decoded = JSON.parse(new TextDecoder().decode(publishedPayload));

    expect(decoded.derivation_path).toEqual([44, 60, 0, 0, 0]);
  });

  it("G) omits derivation_path in SignTxMessage when not provided", async () => {
    const { nc, jetstreamPublish } = createMockNatsConnection();
    const client = createSignTransactionClient(nc, 9);

    await client.signTransaction({
      walletId: "wallet-2",
      keyType: KeyType.Ed25519,
      networkInternalCode: "solana-devnet",
      tx: "BAUG",
    });

    const publishedPayload = jetstreamPublish.mock.calls[0][1] as Uint8Array;
    const decoded = JSON.parse(new TextDecoder().decode(publishedPayload));

    expect(Object.prototype.hasOwnProperty.call(decoded, "derivation_path")).toBe(
      false
    );
  });
});
