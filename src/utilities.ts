import queryString from "querystring";
import { Key } from "./types";

export const pluck = (properties: string[], data: any[]) => {
  const obj: any = {};
  properties.map(param => {
    obj[param] = [];
  });
  return data.reduce((acc, obj) => {
    Object.keys(obj).map(key => {
      if (properties.includes(key)) {
        acc[key].push(obj[key]);
      }
    });
  }, obj);
};

export const extractOtp = (sections: any[]) => {
  let otp = "";
  sections.map(({ fields }) => {
    Array.isArray(fields) &&
      fields.map(({ n, v }: any) => {
        if (!!n.match(/TOTP/gi)) {
          const { secret = "" } = queryString.parse(v.split("?").pop());
          otp = secret as string;
        }
      });
  });
  return otp;
};

export const getKey = (secretKey: string): Key => {
  const formattedKey = secretKey.replace(/-/g, "");
  return {
    format: formattedKey.slice(0, 2),
    id: formattedKey.slice(2, 8),
    key: formattedKey.slice(8)
  };
};
