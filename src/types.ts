export type EntryFields = "id" | "name" | "url" | "username" | "type";

export type Entry = Record<EntryFields, string>;

export type EntryCredentialsFields = "username" | "password" | "otp";

export type EntryCredentials = Record<EntryCredentialsFields, string>;

export type RawEntryFields = EntryFields & EntryCredentialsFields;

export type RawEntry = Entry & EntryCredentials;

export interface Client {
  login: (
    password: string,
    username?: string,
    secret?: string
  ) => Promise<void>;
  getEntries: () => Promise<Entry[]>;
  getEntry: (fqdn: string) => Promise<EntryDetail>;
  getEntryCredentials: (fqdn: string) => Promise<EntryCredentials>;
  addEntry: (account: Entry) => Promise<string>;
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
  encPriKey: EncryptedPayload;
  encSPriKey: EncryptedPayload;
  encSymKey: EncryptedPayload;
  encryptedBy: string;
  pubKey: AsymettricKey;
  sn: Number;
  sPubKey: AsymettricKey;
  uuid: string;
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

export type AsymettricKey = {
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
  encAttrs: EncryptedPayload;
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
    encVaultKey: EncryptedPayload;
  }>;
};

export type EncryptedPayload = {
  alg?: string;
  cty: string;
  data: string;
  enc: string;
  iv?: string;
  kid: string;
  p2c?: number;
  p2s?: string;
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
  encOverview: EncryptedPayload;
  encDetails?: EncryptedPayload;
};

export type EncryptedItemModified = {
  vaultID: string;
  access: EncryptedVault["access"];
} & EncryptedItem;

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
  sections: Array<{ name: string; title: string; fields: Array<{
      k: string;
      n: string;
      t: string;
      v: string;
    }> }>;
  fields: Array<{
    name: string;
    value: string;
    type: string;
    designation: string;
  }>;
  password: string;
  notesPlain: string;
  username: string;
};

export type EntryDetail = {
  sections: Array<{ name: string; title: string; fields: Array<{
      id: string;
      title: string;
      value: string;
      type: string;
    }> }>;
  fields: Array<{
    name: string;
    value: string;
    type: string;
    designation: string;
  }>;
  password: string;
  notesPlain: string;
  username: string;
};
