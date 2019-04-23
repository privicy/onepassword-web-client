export interface Device {
  clientName: string;
  clientVersion: string;
  model: string;
  name: string;
  osName: string;
  osVersion: string;
  userAgent: string;
  uuid: string;
}

export interface Key {
  format: string;
  id: string;
  key: string;
}

export interface Auth {
  email: string;
  password: string;
  littleA?: string;
  bigA?: string;
  bigB?: string;
  method?: string;
  alg?: string;
  iterations?: number;
  salt?: string;
}

export interface Session {
  id: string;
  key: string;
}

export interface Keysets {
  masterKey: string;
  symKey: string;
  privateKey: any;
  vaultKeys: any;
}
