const Jwt = require('./lib/jwt.js');

module.exports.NewSudMGPAuth = function(appId, appSecret) {
    return new SudMGPAuth(appId, appSecret);
};

let SudMGPAuth = function (appId, appSecret) {
    this.appId = appId;
    this.appSecret = appSecret;
}

SudMGPAuth.prototype.getCode = function (uid, expireDuration) {
    let result = Jwt.getToken({
        app_id: this.appId,
        uid: uid
    }, this.appSecret, expireDuration);
    if (result.data) {
        return {code: result.data.token, expireDate: result.data.exp};
    } else {
        return {code: "", expireDate: 0};
    }
};

SudMGPAuth.prototype.getSSToken = function (uid, expireDuration) {
    let result = this.getCode(uid, expireDuration);
    return {token: result.code, expireDate: result.expireDate};
};

SudMGPAuth.prototype.getUidByCode = function (code) {
    let ret = Jwt.parseToken(code, this.appSecret);
    if (!ret.isSuccess) {
        return ret;
    }
    return {isSuccess: ret.isSuccess, errorCode: ret.errorCode, uid: ret.data.uid };
};

SudMGPAuth.prototype.getUidBySSToken = function (ssToken) {
    let ret = Jwt.parseToken(ssToken, this.appSecret);
    if (!ret.isSuccess) {
        return ret;
    }
    return {isSuccess: ret.isSuccess, errorCode: ret.errorCode, uid: ret.data.uid };
};

SudMGPAuth.prototype.verifyCode = function (code) {
    let ret = Jwt.parseToken(code, this.appSecret);
    return ret.errorCode;
};

SudMGPAuth.prototype.verifySSToken = function (ssToken) {
    let ret = Jwt.parseToken(ssToken, this.appSecret);
    return ret.errorCode;
};


