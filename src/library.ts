import { BigInteger } from "jsbn";
import {
  request,
  random,
  deriveKey,
  N,
  g,
  encrypt,
  bufferToHex,
  hexToBuffer,
  mergeArrayBuffers
} from "./util";
const base64url = require("base64url");
import { JWK } from "./Interfaces";

export default class OnePasswordWeb {
  private email: string;
  private masterPassword: string;
  private secretKey: string;
  private secretVersion: string;
  private accountUUID: string;
  private session: JWK;
  private userAuth: any;
  constructor(email: string, masterPassword: string, secret: string) {
    this.email = email;
    this.masterPassword = masterPassword;
    const formattedSecret = secret.replace(/-/g, "");
    this.secretVersion = formattedSecret.slice(0, 2);
    this.accountUUID = formattedSecret.slice(2, 8);
    this.secretKey = formattedSecret.slice(8);
    this.session = {
      kid: "",
      kty: "oct",
      k: "",
      alg: "A256GCM",
      key_ops: ["encrypt", "decrypt"]
    };
  }

  public init = async () => {
    const { userAuth, sessionID } = await this.startSession();
    this.session.kid = sessionID;
    this.userAuth = userAuth;
    const x = await this.deriveAuthKey();
    const { result, userA, userB, secretA } = await this.SRPExchange();
    result
      ? (this.session.k = await this.sessionEncryptionKey(
          x,
          new BigInteger(
            bufferToHex(new TextEncoder().encode(this.session.kid)), //Checked by node crypto, correct hex.
            16
          ),
          userB,
          userA,
          secretA
        ))
      : null;
    const keyVerified = await this.verifySessionKey();
    await this.getKeySets();
    return keyVerified;
  };

  private startSession = async (randomBytes?: string): Promise<any> => {
    !randomBytes ? (randomBytes = random(26)) : null;
    const endpoint = `v2/auth/${this.email}/${this.secretVersion}/${
      this.accountUUID
    }/${randomBytes}`;
    const { status, sessionID, userAuth } = await request(endpoint, "GET");
    if (status === "ok") {
      return { sessionID, userAuth };
    } else {
      const device = await this.enrollDevice(sessionID, randomBytes);
      if (!device) throw new Error("Device couldn't be registered.");
      return await this.startSession(randomBytes);
    }
  };

  private enrollDevice = async (
    tempSessionID: string,
    randomBytes: string
  ): Promise<boolean> => {
    const endpoint = `v1/device`;
    const payload = {
      clientName: "1Password for Web",
      clientVersion: "636",
      uuid: randomBytes
    };
    const headers = { "X-AgileBits-Session-ID": tempSessionID };
    const { success } = await request(endpoint, "POST", payload, headers);
    return success;
  };

  private deriveAuthKey = async () => {
    const key1 = new Uint8Array(
      await deriveKey(
        this.secretKey,
        new TextEncoder().encode(this.accountUUID),
        1,
        32,
        "HKDF",
        this.secretVersion
      )
    );
    const key2_salt = new Uint8Array(
      await deriveKey(
        this.userAuth.salt,
        new TextEncoder().encode(this.email),
        1,
        32,
        "HKDF",
        this.userAuth.method
      )
    );
    const key2 = new Uint8Array(
      await deriveKey(
        this.masterPassword.normalize("NFKD"),
        key2_salt,
        this.userAuth.iterations,
        32
      )
    );
    //https://tools.ietf.org/html/rfc5054#page-16
    const bi = new BigInteger(bufferToHex(key1), 16).xor(
      new BigInteger(bufferToHex(key2), 16)
    );
    /*const generator = new BigInteger(g);
    const n = new BigInteger(N, 16);
    return generator.modPow(bi, n);*/
    return bi;
  };

  private SRPExchange = async () => {
    const endpoint = "v1/auth";
    const secretA = new BigInteger(random(16), 16);
    const userA = new BigInteger(g).modPow(secretA, new BigInteger(N, 16));
    const payload = {
      sessionID: this.session.kid,
      userA: userA.toString(16)
    };
    const headers = { "X-AgileBits-Session-ID": this.session.kid };
    const { sessionID: rSessionID, userB } = await request(
      endpoint,
      "POST",
      payload,
      headers
    );

    return {
      result: rSessionID === this.session.kid,
      userB: new BigInteger(userB, 16),
      userA,
      secretA
    };
  };

  private sessionEncryptionKey = async (
    x: BigInteger,
    sessionID: BigInteger,
    userB: BigInteger,
    userA: BigInteger,
    secretA: BigInteger
  ) => {
    const hash_a_b = new BigInteger(
      bufferToHex(
        await crypto.subtle.digest(
          "SHA-256",
          mergeArrayBuffers([
            new Uint8Array(hexToBuffer(userA.toString(16))),
            new Uint8Array(hexToBuffer(userB.toString(16)))
          ])
        )
      ),
      16
    ); //Hash verified by crypto - Don't use this anywhere new Uint8Array(Bignumber.toByteArray())!

    const y = userB.subtract(
      new BigInteger(g).modPow(x, new BigInteger(N, 16)).multiply(sessionID)
    );
    const z = y.modPow(
      secretA.add(hash_a_b.multiply(x)),
      new BigInteger(N, 16)
    );
    const key = new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new Uint8Array(hexToBuffer(z.toString(16))) //verified by node crypto
      )
    );
    return base64url(key);
  };

  private verifySessionKey = async () => {
    const iv = random(12);
    const clientVerifyHash = await this.calculateClientHash(); //Verified by node crypto
    const plainText = {
      sessionID: this.session.kid,
      clientVerifyHash,
      client: "1Password for Web/636"
    };
    const data = await encrypt(iv, JSON.stringify(plainText), this.session); //Verified by nodeCrypto
    const payload = {
      kid: this.session.kid,
      enc: "A256GCM",
      cty: "b5+jwk+json",
      iv: base64url(iv),
      data
    };
    const { kid } = await request("v2/auth/verify", "POST", payload, {
      "X-AgileBits-Session-ID": this.session.kid,
      "X-AgileBits-MAC": await this.generateSessionHMAC(
        "POST",
        "my.1password.com/v2/auth/verify",
        "1"
      )
    });
    return kid === this.session.kid;
  };

  private getKeySets = async () => {
    const endpoint = "v1/account/keysets";
    const { data, iv } = await request(endpoint, "GET");
  };

  private calculateClientHash = async () => {
    const a = new TextEncoder().encode(this.accountUUID);
    const b = new TextEncoder().encode(this.session.kid);
    const c = new Uint8Array(await crypto.subtle.digest("SHA-256", a));
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", b));
    const e = mergeArrayBuffers([c, d]);
    return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", e)));
  };

  private generateSessionHMAC = async (
    method: string,
    url: string,
    requestID: string
  ) => {
    const message = `${
      this.session.kid
    }|${method.toUpperCase()}|${url}|v1|${requestID}`;
    const salt = await this.generateSessionHMACSalt();
    const hash = await crypto.subtle.sign(
      "HMAC",
      await crypto.subtle.importKey(
        "raw",
        salt,
        { name: "HMAC", hash: "SHA-256" },
        true,
        ["sign", "verify"]
      ),
      new TextEncoder().encode(message)
    );
    const hash12 = base64url(new Uint8Array(hash.slice(0, 12)));
    return `v1|${requestID}|${hash12}`;
  };

  private generateSessionHMACSalt = async () => {
    const sessionHMACSecret =
      "He never wears a Mac, in the pouring rain. Very strange.";
    return new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        await crypto.subtle.importKey(
          "raw",
          new TextEncoder().encode(base64url.decode(this.session.k)),
          { name: "HMAC", hash: "SHA-256" },
          true,
          ["sign", "verify"]
        ),
        new TextEncoder().encode(sessionHMACSecret)
      )
    );
  };
}

const prom = new OnePasswordWeb(
  "allroundexperts@gmail.com",
  "Sibi1234@@",
  "A3-ARFJYY-P8P2MT-2VS5C-4T3LJ-XMMS2-Z57PR"
);

console.log(prom.init());
