import base64safe from "urlsafe-base64";
import { Cipher } from "./services/Cipher";
import { Onepassword } from "./services/Onepassword";
import { Client, Entry, Key, Session, VaultKey } from "./types";

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
    secret?: string
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

  public async getAccounts(): Promise<any> {
    const encKeySets = await this.onepassword.getKeySets();
    const masterPrivateKey = this.cipher.getMasterPrivateKey(encKeySets);
    const encVaults = await this.onepassword.getVaults();
    encVaults.map(async ({ uuid, access }) => {
      const items = await this.onepassword.getItemsOverview(uuid);
      const { encVaultKey } = access[0];
      const decryptKey = JSON.parse(
        masterPrivateKey.decrypt(base64safe.decode(encVaultKey.data)).toString()
      ) as VaultKey;
      items.map(async (item: any) => {
        const {
          uuid: itemId,
          encOverview: { data: dataOverview, iv: dataiv }
        } = item;

        const {
          encDetails: { data, iv }
        } = await this.onepassword.getItemDetail(itemId, uuid);
      });
    });
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

const client = new OnepasswordClient();

client
  .login(
    "inovicsolutions@yahoo.com",
    "Sibi1234@@",
    "A3-4TNVYT-SZE2GC-SBTX4-QG96A-AJM4Y-H4K9N"
  )
  .then(() => client.getAccounts())
  .catch(console.log);
