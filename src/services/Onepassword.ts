import { randomBytes } from "crypto";
import { flatten } from "lodash";
import RequestService from "./Request";
import {
  Key,
  Device,
  Session,
  AuthResponse,
  UserAuth,
  Keysets,
  EncryptedVault,
  EncryptedItem,
  EncryptedItemModified
} from "../types";
import { device } from "../config";

export class Onepassword {
  private device: Device = device;
  private session: Session;
  private requestService: RequestService = new RequestService();

  public setSession(session: Session) {
    this.session = session;
    this.requestService.setSession(session);
  }

  public async auth(
    email: string,
    key: Key,
    self: boolean = false
  ): Promise<Record<"userAuth", UserAuth> & Record<"sessionID", string>> {
    if (!self)
      this.device.uuid = randomBytes(26)
        .toString("hex")
        .slice(0, 26);
    const endpoint = `v2/auth/${email}/${key.format}/${key.id}/${this.device.uuid}`;
    const { status, sessionID, userAuth } = (await this.requestService.request(
      endpoint,
      "GET"
    )) as AuthResponse;
    if (status === "ok") {
      return { userAuth, sessionID };
    } else {
      const device = await this.enrollDevice(sessionID);
      if (!device) throw new Error("Device couldn't be registered.");
      return await this.auth(email, key, true);
    }
  }

  public async SRPExchange(
    sessionID: string,
    bigA: string
  ): Promise<Record<"bigB", string>> {
    const endpoint = "v1/auth";
    const payload = {
      sessionID: sessionID,
      userA: bigA
    };
    const headers = { "X-AgileBits-Session-ID": sessionID };
    const {
      sessionID: newSessionID,
      userB
    } = await this.requestService.request(endpoint, "POST", payload, headers);
    if (sessionID !== newSessionID)
      throw new Error("Invalid master password or secret key.");
    return { bigB: userB };
  }

  public async verifySessionKey(
    clientVerifyHash: string,
    serverHash: string
  ): Promise<boolean> {
    const message = {
      sessionID: this.session.id,
      clientVerifyHash,
      client: "1Password for Web/959",
      device: this.device
    };
    const { serverVerifyHash } = await this.requestService.secureRequest(
      "v2/auth/verify",
      "POST",
      message
    );
    if (serverVerifyHash !== serverHash)
      throw new Error("Possible MIM attack.");
    return true;
  }

  public async getKeySets(): Promise<Keysets[]> {
    const endpoint = "v1/account/keysets";
    const { keysets } = await this.requestService.secureRequest(
      endpoint,
      "GET"
    );
    return keysets as Keysets[];
  }

  public async getVaults(): Promise<EncryptedVault[]> {
    const endpoint = "v1/vaults";
    return await this.requestService.secureRequest(endpoint, "GET");
  }

  public async getItemsOverview(
    vaultId: string
  ): Promise<EncryptedItemModified[]> {
    const endpoint = `v1/vault/${vaultId}/items/overviews`;
    const { items } = await this.requestService.secureRequest(endpoint, "GET");
    return items;
  }

  public async getItemDetail(
    itemID: string,
    vaultID: string
  ): Promise<EncryptedItem> {
    const endpoint = `v1/vault/${vaultID}/item/${itemID}`;
    const { item } = await this.requestService.secureRequest(endpoint, "GET");
    return item;
  }

  private async enrollDevice(sessionID: string): Promise<boolean> {
    const endpoint = `v1/device`;
    const payload = this.device;
    const headers = { "X-AgileBits-Session-ID": sessionID };
    const { success } = await this.requestService.request(
      endpoint,
      "POST",
      payload,
      headers
    );
    return success;
  }
}
