const Jwt = require('./lib/jwt.js');

module.exports.NewSudMGPAuth = function(appId, appSecret) {
    return new SudMGPAuth(appId, appSecret);
};

let SudMGPAuth = function (appId, appSecret) {
    this.appId = appId;
    this.appSecret = appSecret;
}

SudMGPAuth.prototype.getCode = function (uid) {
    let result = Jwt.getToken({
        app_id: this.appId,
        uid: uid
    }, this.appSecret);
    return {code: result.token, expire_date: result.exp};
};

SudMGPAuth.prototype.getSSToken = function (uid) {
    let result = this.getCode(uid);
    return {ss_token: result.code, expire_date: result.expire_date};
};

SudMGPAuth.prototype.getUidByCode = function (code) {
    let claims = Jwt.parseToken(code, this.appSecret);
    if (!claims) {
        return {is_success: false};
    }
    return {uid: claims.uid, is_success: true};
};

SudMGPAuth.prototype.getUidBySSToken = function (ssToken) {
    let claims = Jwt.parseToken(ssToken, this.appSecret);
    if (!claims) {
        return {is_success: false};
    }
    return {uid: claims.uid, is_success: true};
};

SudMGPAuth.prototype.verifyCode = function (code) {
    let claims = Jwt.parseToken(code, this.appSecret);
    return claims ? false : true;
};

SudMGPAuth.prototype.verifySSToken = function (ssToken) {
    let claims = Jwt.parseToken(ssToken, this.appSecret);
    return claims ? false : true;
};


