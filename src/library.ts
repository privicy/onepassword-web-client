import {
  randomBytes,
  pbkdf2Sync,
  createHash,
  createHmac,
  createDiffieHellman,
  createCipheriv,
  createDecipheriv
} from "crypto";
import { BigInteger } from "jsbn";
import { find } from "lodash";
import { Device, Key, Auth, Session, Keysets } from "./Interface";
import { N, g, request } from "./util";

const base64safe = require("urlsafe-base64");
const NodeRSA = require("node-rsa");
const hkdf = require("futoin-hkdf");
const xor = require("buffer-xor");

export default class OnePassword {
  private device: Device;
  private key: Key;
  private auth: Auth;
  private session: Session;
  private requestID: number;
  private encKeysets: any;
  private keysets: Keysets;

  constructor(email: string, password: string, secretKey: string) {
    this.device = {
      clientName: "1Password for Web",
      clientVersion: "637",
      model: "73.0.3683.103",
      name: "Chrome",
      osName: "MacOSX",
      osVersion: "10.14.4",
      userAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36",
      uuid: randomBytes(26)
        .toString("hex")
        .slice(0, 26)
    };
    const formattedKey = secretKey.replace(/-/g, "");
    this.key = {
      format: formattedKey.slice(0, 2),
      id: formattedKey.slice(2, 8),
      key: formattedKey.slice(8)
    };
    this.auth = {
      email,
      password
    };
    this.session = { id: "", key: "" };
    this.keysets = { masterKey: "", privateKey: "", vaultKeys: {}, symKey: "" };
    this.requestID = 0;
  }

  public init = async () => {
    await this.startSession();
    this.generateSRPKeys();
    const result = await this.SRPExchange();
    result ? await this.computeSessionKey() : null;
    await this.verifySessionKey();
    await this.getKeySets();
    const vaults = await this.getVaults();
    return vaults;
  };

  private startSession = async (): Promise<any> => {
    const endpoint = `v2/auth/${this.auth.email}/${this.key.format}/${
      this.key.id
    }/${this.device.uuid}`;
    const { status, sessionID, userAuth } = await request(endpoint, "GET");
    this.session.id = sessionID;
    if (status === "ok") {
      this.auth = { ...this.auth, ...userAuth };
    } else {
      const device = await this.enrollDevice();
      if (!device) throw new Error("Device couldn't be registered.");
      return await this.startSession();
    }
  };

  private enrollDevice = async (): Promise<boolean> => {
    const endpoint = `v1/device`;
    const payload = this.device;
    const headers = { "X-AgileBits-Session-ID": this.session.id };
    const { success } = await request(endpoint, "POST", payload, headers);
    return success;
  };

  private SRPExchange = async () => {
    const endpoint = "v1/auth";
    const payload = {
      sessionID: this.session.id,
      userA: this.auth.bigA
    };
    const headers = { "X-AgileBits-Session-ID": this.session.id };
    const { sessionID, userB } = await request(
      endpoint,
      "POST",
      payload,
      headers
    );
    this.auth.bigB = userB;
    return this.session.id === sessionID;
  };

  private verifySessionKey = async () => {
    const clientVerifyHash = this.clientVerifyHash();
    const message = {
      sessionID: this.session.id,
      clientVerifyHash,
      client: "1Password for Web/637",
      device: this.device
    };
    const { serverVerifyHash } = await this.secureRequest(
      "v2/auth/verify",
      "POST",
      message
    );
    if (serverVerifyHash !== this.serverVerifyHash())
      throw new Error("Possible MIM attack.");
    return true;
  };

  private getKeySets = async () => {
    const endpoint = "v1/account/keysets";
    const { keysets } = await this.secureRequest(endpoint, "GET", false);
    this.encKeysets = keysets;
    this.deriveMasterUnlockKey()
      .deriveSymKey()
      .derivePrivateKey();
  };

  private getVaults = async () => {
    const endpoint = "v1/vaults";
    const encVaults = await this.secureRequest(endpoint, "GET", false);
    const vaults: any = {};
    const promises: any = [];
    encVaults.map(async ({ uuid, access }: any) => {
      const { encVaultKey } = access[0];
      const key = this.getPrivateKey();
      const vaultKey = JSON.parse(
        key.decrypt(base64safe.decode(encVaultKey.data)).toString()
      );
      this.keysets.vaultKeys[uuid] = vaultKey.k;
      promises.push(
        new Promise(async resolve => {
          const overview = await this.getItemsOverview(uuid);
          resolve({ vaultID: uuid, overview });
        })
      );
    });
    const results = await Promise.all(promises);
    results.map(({ vaultID, overview }: any) => {
      vaults[vaultID] = overview;
    });
    return vaults;
  };

  private getItemsOverview = async (vaultID: string) => {
    const items: any = {};
    const endpoint = `v1/vault/${vaultID}/items/overviews`;
    const { items: encItems } = await this.secureRequest(
      endpoint,
      "GET",
      false
    );
    encItems.map(({ uuid, encOverview: { data, iv } }: any) => {
      items[uuid] = this.decryptItem(this.keysets.vaultKeys[vaultID], data, iv);
    });
    return items;
  };

  getItemDetail = async (itemID: string, vaultID: string) => {
    const endpoint = `v1/vault/${vaultID}/item/${itemID}`;
    const {
      item: { encDetails }
    } = await this.secureRequest(endpoint, "GET", false);
    return this.decryptItem(
      this.keysets.vaultKeys[vaultID],
      encDetails.data,
      encDetails.iv
    );
  };

  private srpX = () => {
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
  };

  private computeSessionKey = () => {
    const srpX = this.srpX();
    const x = new BigInteger(srpX, 16);
    const bLittleA = new BigInteger(this.auth.littleA, 16);
    const bBigB = new BigInteger(this.auth.bigB, 16);
    const bigK = new BigInteger(
      Buffer.from(this.session.id).toString("hex"),
      16
    );
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
    this.session.key = createHash("sha256")
      .update(Buffer.from(y))
      .digest("hex");
  };

  private clientVerifyHash = () => {
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
  };

  private serverVerifyHash = () => {
    const clientHash = this.clientVerifyHash();
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
  };

  private getMacMessage = (
    requestMethod: string,
    requestURL: string,
    requestCount: number
  ) => {
    const { hostname, pathname, search } = new URL(requestURL);
    return [
      this.session.id,
      requestMethod.toUpperCase(),
      hostname + pathname + "?" + search,
      "v1",
      requestCount
    ].join("|");
  };

  private createSessionHMAC = () => {
    return createHmac("sha256", Buffer.from(this.session.key, "hex"))
      .update(
        Buffer.from("He never wears a Mac, in the pouring rain. Very strange.")
      )
      .digest();
  };

  private createMACHeader = (
    requestMethod: string,
    requestURL: string,
    requestID: number
  ) => {
    const message = this.getMacMessage(requestMethod, requestURL, requestID);
    const sessionHMAC = this.createSessionHMAC();
    const hash = base64safe.encode(
      createHmac("sha256", sessionHMAC)
        .update(message)
        .digest()
        .slice(0, 12)
    );
    return ["v1", requestID, hash].join("|");
  };

  private generateSRPKeys = () => {
    const dh = createDiffieHellman(N, "hex", g, "hex");
    this.auth.bigA = dh.generateKeys().toString("hex");
    this.auth.littleA = dh.getPrivateKey().toString("hex");
  };

  private secureRequest = async (
    endpoint: string,
    method: string,
    message: any
  ) => {
    let payload: any = "";
    if (message) {
      let iv = randomBytes(12);
      const cipher = createCipheriv(
        "aes-256-gcm",
        Buffer.from(this.session.key, "hex"),
        iv
      );
      let data = cipher.update(JSON.stringify(message), "utf8", "hex");
      data += cipher.final("hex");
      data += cipher.getAuthTag().toString("hex");
      payload = {
        kid: this.session.id,
        enc: "A256GCM",
        cty: "b5+jwk+json",
        iv: base64safe.encode(iv),
        data: base64safe.encode(Buffer.from(data, "hex"))
      };
    }
    this.requestID++;
    let { iv, data, kid } = await request(endpoint, method, payload, {
      "X-AgileBits-Session-ID": this.session.id,
      "X-AgileBits-MAC": await this.createMACHeader(
        method,
        `https://my.1password.com/api/${endpoint}`,
        this.requestID
      )
    });
    if (kid !== this.session.id) throw new Error("Session mismatch.");
    data = base64safe.decode(data);
    const decipher = createDecipheriv(
      "aes-256-gcm",
      Buffer.from(this.session.key, "hex"),
      base64safe.decode(iv)
    );
    decipher.setAuthTag(data.slice(-16));
    data = decipher.update(data.slice(0, -16), null, "utf8");
    data += decipher.final("utf8");
    return JSON.parse(data);
  };

  private deriveMasterUnlockKey = () => {
    const { encSymKey } = find(this.encKeysets, ["encryptedBy", "mp"]);
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
    this.keysets.masterKey = base64safe.encode(masterKey);
    return this;
  };

  private deriveSymKey = () => {
    const { encSymKey } = find(this.encKeysets, ["encryptedBy", "mp"]);
    const keyData = base64safe.decode(encSymKey.data);
    const iv = base64safe.decode(encSymKey.iv);
    const masterKey = base64safe.decode(this.keysets.masterKey);
    const decipher = createDecipheriv("aes-256-gcm", masterKey, iv);
    decipher.setAuthTag(keyData.slice(-16));
    let key = decipher.update(keyData.slice(0, -16), null, "utf8");
    key += decipher.final("utf8");
    const { k } = JSON.parse(key);
    this.keysets.symKey = k;
    return this;
  };

  private derivePrivateKey = () => {
    const { encPriKey } = find(this.encKeysets, ["encryptedBy", "mp"]);
    const keyData = base64safe.decode(encPriKey.data);
    const iv = base64safe.decode(encPriKey.iv);
    const symKey = base64safe.decode(this.keysets.symKey);
    const decipher = createDecipheriv("aes-256-gcm", symKey, iv);
    decipher.setAuthTag(keyData.slice(-16));
    let key = decipher.update(keyData.slice(0, -16), null, "utf8");
    key += decipher.final("utf8");
    this.keysets.privateKey = JSON.parse(key);
    return this;
  };

  private decryptItem = (key: string, data: string, piv: string) => {
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
  };

  private getPrivateKey = () => {
    const key = this.keysets.privateKey;
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
  };
}
