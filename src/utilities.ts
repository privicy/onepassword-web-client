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
