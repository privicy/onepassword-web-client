const path = require("path");

module.exports = {
  entry: "./src/library.ts",
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: "ts-loader",
        exclude: /node_modules/
      }
    ]
  },
  devtool: "source-map",
  target: "web",
  mode: "production",
  node: {
    buffer: true,
    crypto: true
  },
  devServer: {
    contentBase: "./dist"
  },
  resolve: {
    extensions: [".tsx", ".ts", ".js"]
  },
  output: {
    filename: "library.js",
    path: path.resolve(__dirname, "dist"),
    libraryTarget: "umd",
    globalObject: "typeof self !== 'undefined' ? self : this"
  }
};
