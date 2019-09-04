import {
  createDiffieHellman,
  pbkdf2Sync,
  createHash,
  createDecipheriv
} from "crypto";
import base64safe from "urlsafe-base64";
import { find } from "lodash";
import NodeRSA from "node-rsa";
import hkdf from "futoin-hkdf";
import xor from "buffer-xor";
import { BigInteger } from "jsbn";
import { N, g } from "../config";
import { Key, Auth, Session, Keysets } from "../types";

export class Cipher {
  private session: Session;
  private key: Key;
  private auth: Auth;

  public setSession(session: Session): void {
    this.session = session;
  }

  public setKey(key: Key): void {
    this.key = key;
  }

  public setAuth(auth: Auth): void {
    this.auth = auth;
  }

  public generateSRPKeys(): Record<"bigA" | "littleA", string> {
    const dh = createDiffieHellman(N, "hex", g, "hex");
    const bigA = dh.generateKeys().toString("hex");
    const littleA = dh.getPrivateKey().toString("hex");
    return { bigA, littleA };
  }

  public getSessionKey(sessionID: string): string {
    const srpX = this.srpX();
    const x = new BigInteger(srpX, 16);
    const bLittleA = new BigInteger(this.auth.littleA, 16);
    const bBigB = new BigInteger(this.auth.bigB, 16);
    const bigK = new BigInteger(Buffer.from(sessionID).toString("hex"), 16);
    const AB = this.auth.bigA + this.auth.bigB;
    const hash = new BigInteger(
      createHash("sha256")
        .update(Buffer.from(AB))
        .digest("hex"),
      16
    );
    const bN = new BigInteger(N, 16);
    const bg = new BigInteger(g, 16);

    const f = bLittleA.add(hash.multiply(x));
    const m = bBigB.subtract(bg.modPow(x, bN).multiply(bigK));
    const y = m
      .modPow(f, bN)
      .toString(16)
      .replace(/^(0x)?[0]/, "");
    return createHash("sha256")
      .update(Buffer.from(y))
      .digest("hex");
  }

  public clientVerifyHash(): string {
    const secretKeyIdHashed = createHash("sha256")
      .update(this.key.id)
      .digest();
    const sessionIDHashed = createHash("sha256")
      .update(this.session.id)
      .digest();
    const concat = Buffer.concat([secretKeyIdHashed, sessionIDHashed]);
    const hashConcat = createHash("sha256")
      .update(concat)
      .digest();
    return base64safe.encode(hashConcat);
  }

  public serverVerifyHash(clientHash: string): string {
    const clientHashHashed = createHash("sha256")
      .update(clientHash)
      .digest();
    const sessionIDHashed = createHash("sha256")
      .update(this.session.id)
      .digest();
    const concat = Buffer.concat([sessionIDHashed, clientHashHashed]);
    const hashConcat = createHash("sha256")
      .update(concat)
      .digest();
    return base64safe.encode(hashConcat);
  }

  public getMasterPrivateKey(encKeysets: Keysets): NodeRSA {
    const { encSymKey, encPriKey } = find(encKeysets, ["encryptedBy", "mp"]);
    const masterKey = this.deriveMasterUnlockKey(encSymKey);
    const symKey = this.deriveSymKey(masterKey, encSymKey);
    const priKey = this.derivePrivateKey(symKey, encPriKey);
    return this.getPrivateKey(priKey);
  }

  public decryptItem(key: string, data: string, piv: string): any {
    const keyData = base64safe.decode(data);
    const iv = base64safe.decode(piv);
    const decipher = createDecipheriv(
      "aes-256-gcm",
      base64safe.decode(key),
      iv
    );
    decipher.setAuthTag(keyData.slice(-16));
    let plainText = decipher.update(keyData.slice(0, -16), null, "utf8");
    plainText += decipher.final("utf8");
    return JSON.parse(plainText);
  }

  private srpX(): string {
    const masterPass = Buffer.from(this.auth.password);
    const salt = base64safe.decode(this.auth.salt); //l
    const method = Buffer.from(this.auth.method); //p
    const email = Buffer.from(this.auth.email); //m
    const length = 32;
    const salted = hkdf(salt, length, {
      salt: email,
      info: method,
      hash: "SHA-256"
    });
    const key1 = pbkdf2Sync(
      masterPass,
      salted,
      this.auth.iterations,
      length,
      "sha256"
    );
    const secretKey = Buffer.from(this.key.key);
    const secretFormat = Buffer.from(this.key.format);
    const secretID = Buffer.from(this.key.id);
    const key2 = hkdf(secretKey, 32, {
      salt: secretID,
      info: secretFormat,
      hash: "SHA-256"
    });
    const x = xor(key1, key2);
    return x.toString("hex");
  }

  private deriveMasterUnlockKey(encSymKey: any): string {
    const salt = base64safe.decode(encSymKey.p2s);
    const iterations = encSymKey.p2c;
    const username = Buffer.from(this.auth.email);
    const password = Buffer.from(this.auth.password);
    const key = Buffer.from(this.key.key);
    const keyFormat = Buffer.from(this.key.format);
    const keyID = Buffer.from(this.key.id);
    const method = Buffer.from(encSymKey.alg);
    const key1 = hkdf(salt, 32, {
      salt: username,
      info: method,
      hash: "sha-256"
    });
    const key2 = pbkdf2Sync(password, key1, iterations, 32, "sha256");
    const key3 = hkdf(key, 32, {
      info: keyFormat,
      salt: keyID,
      hash: "sha-256"
    });
    const masterKey = xor(key3, key2);
    return base64safe.encode(masterKey);
  }

  private deriveSymKey(masterEncodedKey: string, encSymKey: any): string {
    const keyData = base64safe.decode(encSymKey.data);
    const iv = base64safe.decode(encSymKey.iv);
    const masterKey = base64safe.decode(masterEncodedKey);
    const decipher = createDecipheriv("aes-256-gcm", masterKey, iv);
    decipher.setAuthTag(keyData.slice(-16));
    let key = decipher.update(keyData.slice(0, -16), null, "utf8");
    key += decipher.final("utf8");
    const { k } = JSON.parse(key);
    return k;
  }

  private derivePrivateKey(symEncodedKey: string, encPriKey: any): any {
    const keyData = base64safe.decode(encPriKey.data);
    const iv = base64safe.decode(encPriKey.iv);
    const symKey = base64safe.decode(symEncodedKey);
    const decipher = createDecipheriv("aes-256-gcm", symKey, iv);
    decipher.setAuthTag(keyData.slice(-16));
    let key = decipher.update(keyData.slice(0, -16), null, "utf8");
    key += decipher.final("utf8");
    return JSON.parse(key);
  }

  private getPrivateKey(key: any): NodeRSA {
    const asymkey = new NodeRSA();
    asymkey.importKey(
      {
        n: base64safe.decode(key.n),
        e: base64safe.decode(key.e),
        d: base64safe.decode(key.d),
        p: base64safe.decode(key.p),
        q: base64safe.decode(key.q),
        dmp1: base64safe.decode(key.dp),
        dmq1: base64safe.decode(key.dq),
        coeff: base64safe.decode(key.qi)
      },
      "components"
    );

    return asymkey;
  }
}
