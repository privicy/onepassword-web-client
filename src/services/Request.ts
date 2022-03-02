import { createHmac, randomBytes, createCipheriv } from "crypto";
import base64safe from "urlsafe-base64";
import { Cipher } from "./Cipher";
import { baseURL } from "../config";
import {
  Session,
  HttpBody,
  HttpMethod,
  HttpHeaders,
  EncryptedPayload
} from "../types";

export default class {
  private session: Session;
  private requestID: number = 1;
  private cipherService: Cipher = new Cipher();

  public setSession(session: Session) {
    this.session = session;
  }

  public async request(
    endpoint: string,
    method: HttpMethod,
    payload?: HttpBody,
    headers?: HttpHeaders
  ): Promise<any> {
    headers = {
      "x-requested-with": "XMLHttpRequest",
      "x-agilebits-client": "1Password for Web/1198",
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
      ...(method !== "GET" && { "Content-Type": "application/json" }),
      ...(headers && headers)
    };
    const body = { body: JSON.stringify(payload) };
    const path = encodeURI(baseURL + endpoint);
    const response = await fetch(path, {
      headers,
      method,
      ...(method !== "GET" && body)
    });
    return await response.json();
  }

  public async secureRequest(
    endpoint: string,
    method: HttpMethod,
    message?: HttpBody
  ) {
    this.requestID++;
    const payload = message
      ? this.cipherService.cipher(JSON.stringify(message), {
          key: Buffer.from(this.session.key, "hex"),
          id: this.session.id
        })
      : {};
    const encData = (await this.request(endpoint, method, payload, {
      "X-AgileBits-Session-ID": this.session.id,
      "X-AgileBits-MAC": await this.createMACHeader(
        method,
        `https://my.1password.com/api/${endpoint}`
      )
    })) as EncryptedPayload;
    if (encData.kid !== this.session.id)
      throw new Error("Wrong master password / secret key.");
    return this.cipherService.decipher(
      encData,
      Buffer.from(this.session.key, "hex")
    );
  }

  private createMACHeader(requestMethod: string, requestURL: string) {
    const message = this.getMacMessage(requestMethod, requestURL);
    const sessionHMAC = this.createSessionHMAC();
    const hash = base64safe.encode(
      createHmac("sha256", sessionHMAC)
        .update(message)
        .digest()
        .slice(0, 12)
    );
    return ["v1", this.requestID, hash].join("|");
  }

  private getMacMessage(requestMethod: string, requestURL: string) {
    const { hostname, pathname, search } = new URL(requestURL);
    return [
      this.session.id,
      requestMethod.toUpperCase(),
      hostname + pathname + "?" + search,
      "v1",
      this.requestID
    ].join("|");
  }

  private createSessionHMAC() {
    return createHmac("sha256", Buffer.from(this.session.key, "hex"))
      .update(
        Buffer.from("He never wears a Mac, in the pouring rain. Very strange.")
      )
      .digest();
  }
}
