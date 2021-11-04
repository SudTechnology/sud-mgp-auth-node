const Jwt = require('jsonwebtoken');

const effectTime = 2 * 3600000; // token有效时间(毫秒)
let getToken = function (claims, secret) {
    claims.exp = Math.floor(Date.now() / 1000) * 1000 + effectTime;
    let result = {};
    result.token = Jwt.sign(claims, secret);
    result.exp = claims.exp;
    return result;
};

let parseToken = function (token, secret) {
    try {
        let decoded = Jwt.verify(token, secret, {clockTimestamp: Date.now()});
        return decoded;
    } catch(err) {
        console.error('jwt verify fail!');
        return null;
    }
};

let updateToken = function (token, secret) {
    let claims = parseToken(token, secret);
    if (!claims) {
        return null;
    }

    return getToken(claims, secret);
};

exports.getToken = getToken;
exports.parseToken = parseToken;
exports.updateToken = updateToken;
