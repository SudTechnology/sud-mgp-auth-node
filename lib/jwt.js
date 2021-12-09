const Jwt = require('jsonwebtoken');

const TokenSuccess  = 0;
const TokenCreateFailed = 1001; // token创建失败
const TokenVerifyFailed = 1002; // token验证失败
const TokenDecodeFailed = 1003; // token解密失败
const TokenInvalid      = 1004; // token非法
const TokenExpired      = 1005; // token失效

const EffectTime = 2 * 3600000; // token有效时间(秒)
const HalfHour = 1800000; // 半个小时(毫秒)
let getToken = function (claims, secret, expireDuration) {
    let effectTime = EffectTime
    if (expireDuration) {
        effectTime = Math.max(expireDuration, HalfHour)
    }
    claims.exp = Math.floor((Date.now() + effectTime) / 1000);
    try {
        let result = {};
        result.isSuccess = true;
        result.errorCode = TokenSuccess;
        result.data = {};
        result.data.token = Jwt.sign(claims, secret);
        result.data.exp = claims.exp * 1000;
        return result;
    } catch (err) {
        return {isSuccess: false, errorCode: TokenCreateFailed}
    }
};

let parseToken = function (token, secret) {
    try {
        let decoded = Jwt.verify(token, secret);
        return {isSuccess: true, errorCode: TokenSuccess, data: decoded};
    } catch(err) {
        console.error('jwt verify fail! err:' + JSON.stringify(err));
        if (err.name === 'JsonWebTokenError') {
            return {isSuccess: false, errorCode: TokenInvalid};
        } else if (err.name === 'TokenExpiredError') {
            return {isSuccess: false, errorCode: TokenExpired};
        } else {
            return {isSuccess: false, errorCode: TokenDecodeFailed};
        }
    }
};

let updateToken = function (token, secret) {
    let ret = parseToken(token, secret);
    if (!ret.isSuccess) {
        return ret;
    }

    return getToken(ret.data, secret);
};

exports.getToken = getToken;
exports.parseToken = parseToken;
exports.updateToken = updateToken;
