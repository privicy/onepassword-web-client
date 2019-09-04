import base64safe from "urlsafe-base64";
import { find } from "lodash";
import { Cipher } from "./services/Cipher";
import { Onepassword } from "./services/Onepassword";
import {
  Client,
  Entry,
  Key,
  Session,
  VaultKey,
  DecryptedItemOverview,
  DecryptedItemDetail
} from "./types";

export default class OnepasswordClient implements Client {
  private cipher: Cipher;
  private onepassword: Onepassword;

  public constructor() {
    this.cipher = new Cipher();
    this.onepassword = new Onepassword();
  }

  public async login(
    email: string,
    password: string,
    secret: string
  ): Promise<void> {
    const key = this.getKey(secret);
    this.cipher.setKey(key);
    const { userAuth, sessionID } = await this.onepassword.auth(email, key);
    const { bigA, littleA } = await this.cipher.generateSRPKeys();
    const { bigB } = await this.onepassword.SRPExchange(sessionID, bigA);
    this.cipher.setAuth({ ...userAuth, email, password, littleA, bigA, bigB });
    const sessionKey = bigB ? await this.cipher.getSessionKey(sessionID) : null;
    this.setSession({ id: sessionID, key: sessionKey });
    const clientHash = this.cipher.clientVerifyHash();
    const serverHash = this.cipher.serverVerifyHash(clientHash);
    await this.onepassword.verifySessionKey(clientHash, serverHash);
  }

  public async getAccounts(): Promise<Entry[]> {
    const encKeySets = await this.onepassword.getKeySets();
    const masterPrivateKey = this.cipher.getMasterPrivateKey(encKeySets);
    const encVaults = await this.onepassword.getVaults();
    const entries = encVaults.map(async ({ uuid, access }) => {
      const items = await this.onepassword.getItemsOverview(uuid);
      const { encVaultKey } = access[0];
      const { k } = JSON.parse(
        masterPrivateKey.decrypt(base64safe.decode(encVaultKey.data)).toString()
      ) as VaultKey;

      return items.map(async item => {
        const { encOverview } = item;
        const { url, title, tags } = this.cipher.decryptItem(
          k,
          encOverview.data,
          encOverview.iv
        ) as DecryptedItemOverview;
        const { encDetails } = await this.onepassword.getItemDetail(
          item.uuid,
          uuid
        );
        const { fields } = this.cipher.decryptItem(
          k,
          encDetails.data,
          encDetails.iv
        ) as DecryptedItemDetail;
        const username = find(fields, ["designation", "username"]);
        const password = find(fields, ["designation", "password"]);
        return {
          username: username ? username.value : "",
          password: password ? password.value : "",
          url,
          name: title,
          otp: "",
          type: tags[0]
        };
      });
    });
    return await Promise.all((await Promise.all(entries)).flat());
  }

  public async addAccount(entry: Entry): Promise<boolean> {
    return false;
  }

  private setSession(session: Session) {
    this.onepassword.setSession(session);
    this.cipher.setSession(session);
  }

  private getKey(secretKey: string): Key {
    const formattedKey = secretKey.replace(/-/g, "");
    return {
      format: formattedKey.slice(0, 2),
      id: formattedKey.slice(2, 8),
      key: formattedKey.slice(8)
    };
  }
}
