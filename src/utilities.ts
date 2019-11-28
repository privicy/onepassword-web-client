import queryString from "querystring";

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
