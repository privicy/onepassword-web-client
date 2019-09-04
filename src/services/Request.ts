import {
  createHmac,
  randomBytes,
  createCipheriv,
  createDecipheriv
} from "crypto";
import base64safe from "urlsafe-base64";
import { baseURL } from "../config";
import {
  Session,
  HttpBody,
  HttpMethod,
  HttpHeaders,
  SecureRequestResponse
} from "../types";

export default class {
  private session: Session;
  private requestID: number = 1;

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
      "x-agilebits-client": "1Password for Web/637",
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
    let { iv, data, kid } = (await this.request(endpoint, method, payload, {
      "X-AgileBits-Session-ID": this.session.id,
      "X-AgileBits-MAC": await this.createMACHeader(
        method,
        `https://my.1password.com/api/${endpoint}`
      )
    })) as SecureRequestResponse;
    if (kid !== this.session.id) throw new Error("Session mismatch.");
    const decipher = createDecipheriv(
      "aes-256-gcm",
      Buffer.from(this.session.key, "hex"),
      base64safe.decode(iv)
    );
    decipher.setAuthTag(base64safe.decode(data).slice(-16));
    data = decipher.update(base64safe.decode(data).slice(0, -16), null, "utf8");
    data += decipher.final("utf8");
    return JSON.parse(data);
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
