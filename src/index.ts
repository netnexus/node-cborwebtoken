module.exports = {
    decode: require('./decode'),
    verify: require('./verify'),
    sign: require('./sign'),
  };

  export type Secret = string | Buffer | {key: string, passphrase: string}