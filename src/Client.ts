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
  DecryptedItemDetail,
  EntryCredentials,
  EncryptedItemModified,
  RawEntry
} from "./types";
import { extractOtp } from "./utilities";

export default class OnepasswordClient implements Client {
  private cipher: Cipher;
  private onepassword: Onepassword;

  public constructor() {
    this.cipher = new Cipher();
    this.onepassword = new Onepassword();
  }

  public async login(
    password: string,
    email: string,
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
    const items = await this.onepassword.getItemsOverview();
    const entries = items.reduce((result: Entry[], item): Entry[] => {
      const {
        access: [{ encVaultKey }],
        encOverview
      } = item;
      try {
        const { k } = JSON.parse(
          masterPrivateKey
            .decrypt(base64safe.decode(encVaultKey.data))
            .toString()
        ) as VaultKey;
        const decryptedItem = this.cipher.decryptItem(
          k,
          encOverview.data,
          encOverview.iv
        ) as DecryptedItemOverview;

        const { url, title, tags, ainfo } = decryptedItem;

        if (url) {
          result.push({
            url: url,
            name: title,
            type: tags && tags.length ? tags[0] : null,
            username: ainfo
          });
        }
      } catch (e) {
        console.error("cant decrypt item: ", item, e);
      }
      return result;
    }, []);
    return entries;
  }

  public async getAccountCredentials(fqdn: string): Promise<EntryCredentials> {
    let item: EncryptedItemModified;
    const encKeySets = await this.onepassword.getKeySets();
    const masterPrivateKey = this.cipher.getMasterPrivateKey(encKeySets);
    const items = await this.onepassword.getItemsOverview();
    for (let i = 0; i < items.length; i++) {
      const {
        encOverview,
        access: [{ encVaultKey }]
      } = items[i];
      const { k } = JSON.parse(
        masterPrivateKey.decrypt(base64safe.decode(encVaultKey.data)).toString()
      ) as VaultKey;
      try {
        const { url } = this.cipher.decryptItem(
          k,
          encOverview.data,
          encOverview.iv
        ) as DecryptedItemOverview;
        if (url.match(new RegExp(fqdn))) {
          item = items[i];
          break;
        }
      } catch {}
    }
    if (!item) throw new Error("Account not found.");

    const {
      access: [{ encVaultKey }]
    } = item;
    const { k } = JSON.parse(
      masterPrivateKey.decrypt(base64safe.decode(encVaultKey.data)).toString()
    ) as VaultKey;
    const { encDetails } = await this.onepassword.getItemDetail(
      item.uuid,
      item.vaultID
    );
    const { fields, sections } = this.cipher.decryptItem(
      k,
      encDetails.data,
      encDetails.iv
    ) as DecryptedItemDetail;
    const username = find(fields, ["designation", "username"]);
    const password = find(fields, ["designation", "password"]);
    const otp = extractOtp(sections);
    return {
      username: username ? username.value : "",
      password: password ? password.value : "",
      otp
    };
  }

  public async addAccount(entry: RawEntry): Promise<void> {}

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
