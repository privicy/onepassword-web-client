export interface JWK {
  kid: string;
  k: string;
  kty?: string;
  alg?: string;
  key_ops?: Array<string>;
  cty?: string;
}
