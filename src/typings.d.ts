declare module "futoin-hkdf" {
  export type HkdfOptions = Record<"salt" | "info" | "hash", Buffer | string>;
  function hkdf(
    salt: Buffer | string,
    length: number,
    options: HkdfOptions
  ): Buffer;
  export default hkdf;
}
