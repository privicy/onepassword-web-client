export type EntryFields =
  | "name"
  | "url"
  | "type"
  | "username"
  | "password"
  | "otp";

export type Entry = Record<EntryFields, string>;

export interface Client {
  login: (
    password: string,
    username?: string,
    secret?: string
  ) => Promise<void>;
  getAccounts: () => Promise<Entry[]>;
  addAccount: (account: Entry) => Promise<void>;
}

export type Device = Record<
  | "clientName"
  | "clientVersion"
  | "model"
  | "name"
  | "osName"
  | "osVersion"
  | "userAgent"
  | "uuid",
  string
>;

export type Key = Record<"format" | "id" | "key", string>;

export type Auth = {
  email: string;
  password: string;
  littleA?: string;
  bigA?: string;
  bigB?: string;
  method?: string;
  alg?: string;
  iterations?: number;
  salt?: string;
};

export type Session = Record<"id" | "key", string>;

export type Keysets = {
  masterKey: string;
  symKey: string;
  privateKey: any;
  vaultKeys: any;
};

export type HttpHeaders = Record<string, string>;
export type HttpMethod = "POST" | "GET" | "PUT" | "DELETE";
export type HttpBody = Record<string, any>;

export interface HttpRequest {
  method: HttpMethod;
  body?: HttpBody;
  headers: HttpHeaders;
}

export type UserAuth = {
  method: string;
  alg: string;
  iterations: number;
  salt: string;
};

export type AuthResponse = Record<
  "status" | "sessionID" | "accountKeyFormat" | "accountKeyUuid",
  string
> &
  Record<"userAuth", UserAuth>;

export type SecureRequestResponse = Record<
  "kid" | "enc" | "cty" | "iv" | "data",
  string
>;

export type VaultKey = {
  alg: string;
  ext: boolean;
  k: string;
  key_ops: string[];
  kty: string;
  kid: string;
};

export type EncryptedVault = {
  uuid: string;
  type: string;
  createdAt: string;
  updatedAt: string;
  attrVersion: number;
  contentVersion: number;
  itemAttrsVersion: number;
  encAttrs: EncryptionInfo;
  activeKeyUuid: string;
  activeItemCount: number;
  clientAccess: number;
  access: Array<{
    vaultUuid: string;
    accessorType: string;
    accessorUuid: string;
    acl: number;
    leaseTimeout: number;
    vaultKeySN: number;
    encryptedBy: string;
    encVaultKey: EncryptionInfo;
  }>;
};

type EncryptionInfo = {
  cty: string;
  data: string;
  enc: string;
  iv: string;
  kid: string;
};

export type EncryptedItem = {
  uuid: string;
  templateUuid: string;
  trashed: string;
  createdAt: string;
  updatedAt: string;
  changerUuid: string;
  packageUuid: string;
  itemVersion: number;
  encryptedBy: string;
  encOverview: EncryptionInfo;
  encDetails?: EncryptionInfo;
};

export type DecryptedItemOverview = {
  title: string;
  url: string;
  ainfo: string;
  ps: number;
  pbe: number;
  pgrng: boolean;
  URLs: Record<string, string>[];
  b5UserUUID: string;
  tags: string[];
};

export type DecryptedItemDetail = {
  sections: Array<{ name: string; title: string; fields: string[] }>;
  fields: Array<{
    name: string;
    value: string;
    type: string;
    designation: string;
  }>;
  notesPlain: string;
};
