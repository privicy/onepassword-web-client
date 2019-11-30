import base64safe from "urlsafe-base64";
import { find } from "lodash";
import { Cipher } from "./services/Cipher";
import { Onepassword } from "./services/Onepassword";
import {
  Client,
  Entry,
  PublicKey,
  DecryptedItemOverview,
  DecryptedItemDetail,
  EntryCredentials,
  EncryptedItemModified,
  RawEntry
} from "./types";
import { extractOtp, getKey } from "./utilities";

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
    const key = getKey(secret);
    this.cipher.setKey(key);
    const { userAuth, sessionID } = await this.onepassword.auth(email, key);
    const { bigA, littleA } = await this.cipher.generateSRPKeys();
    const { bigB } = await this.onepassword.SRPExchange(sessionID, bigA);
    this.cipher.setAuth({ ...userAuth, email, password, littleA, bigA, bigB });
    const sessionKey = bigB ? await this.cipher.getSessionKey(sessionID) : null;
    this.onepassword.setSession({ id: sessionID, key: sessionKey });
    this.cipher.setSession({ id: sessionID, key: sessionKey });
    const clientHash = this.cipher.clientVerifyHash();
    const serverHash = this.cipher.serverVerifyHash(clientHash);
    await this.onepassword.verifySessionKey(clientHash, serverHash);
  }

  public async getAccounts(): Promise<Entry[]> {
    const encKeySets = await this.onepassword.getKeySets();
    const masterPrivateKey = this.cipher.getMasterPrivateKeys(encKeySets);
    const items = await this.onepassword.getItemsOverview();
    const entries = items.reduce((result: Entry[], item): Entry[] => {
      const {
        access: [{ encVaultKey, encryptedBy }],
        encOverview
      } = item;
      try {
        const { k } = JSON.parse(
          masterPrivateKey[encryptedBy]
            .decrypt(base64safe.decode(encVaultKey.data))
            .toString()
        ) as PublicKey;
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
    const masterPrivateKey = this.cipher.getMasterPrivateKeys(encKeySets);
    const items = await this.onepassword.getItemsOverview();
    for (let i = 0; i < items.length; i++) {
      const {
        encOverview,
        access: [{ encVaultKey, encryptedBy }]
      } = items[i];
      const { k } = JSON.parse(
        masterPrivateKey[encryptedBy]
          .decrypt(base64safe.decode(encVaultKey.data))
          .toString()
      ) as PublicKey;
      const { url } = this.cipher.decryptItem(
        k,
        encOverview.data,
        encOverview.iv
      ) as DecryptedItemOverview;
      if (url.match(new RegExp(fqdn))) {
        item = items[i];
        break;
      }
    }
    if (!item) throw new Error("Account not found.");

    const {
      access: [{ encVaultKey, encryptedBy }]
    } = item;
    const { k } = JSON.parse(
      masterPrivateKey[encryptedBy]
        .decrypt(base64safe.decode(encVaultKey.data))
        .toString()
    ) as PublicKey;
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
}
