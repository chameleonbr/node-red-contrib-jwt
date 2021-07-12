module.exports = function (RED) {
    var jwt = require('jsonwebtoken');
    var fs = require('fs');
    function JwtSign(n) {
        RED.nodes.createNode(this, n);
        this.name = n.name;
        this.payload = n.payload;
        this.alg = n.alg;
        this.exp = n.exp;
        this.jwkurl = n.jwkurl;
        this.jwkkid = n.jwkkid;
        this.secret = n.secret;
        this.key = n.key;
        this.signvar = n.signvar;
        this.storetoken = n.storetoken;
        var node = this;

        if (node.jwkurl) {
            GetJWK(node.jwkurl, node);
        }else{
            node.jwk = false;
            // changed to load key on deploy level and not on runtime level why fs.readFileSync is sync.
            if (node.alg === 'RS256' ||
                node.alg === 'RS384' ||
                node.alg === 'RS512' ||
                node.alg === 'ES256' ||
                node.alg === 'ES384' ||
                node.alg === 'ES512') {
                node.secret = process.env.NODE_RED_NODE_JWT_PRIVATE_KEY || fs.readFileSync(node.key);
            } else {
                node.secret = process.env.NODE_RED_NODE_JWT_SECRET || node.secret;
            }
        }
        node.on('input', function (msg, send, done) {
            send = send || function() { node.send.apply(node,arguments) }
            done = done || function(err) { if(err)node.error(err, msg); }

            try {
                if (node.jwk) {
                    //use JWK to sign
                    var key = node.jwk.findKeyById(node.jwkkid);
                    if (key === undefined) {
                        console.log("No Key Found in JWK: " + node.jwkkid)
                    }
                    node.secret = key.key.toPrivateKeyPEM();
                }
                jwt.sign(msg[node.signvar],
                    node.secret,
                    {algorithm: node.alg, expiresIn: node.exp, keyid: node.jwkkid}, function (err, token) {
                        if (err) {
                            done(err);
                        } else {
                            msg[node.storetoken] = token;
                            send(msg);
                            done();
                        }
                    });
            } catch (err) {
                node.error(err.message);
            }
        });
    }
    RED.nodes.registerType("jwt sign", JwtSign);

    function contains(a, obj) {
        for (var i = 0; i < a.length; i++) {
            if (a[i] === obj) {
                return true;
            }
        }
        return false;
    }

    function JwtVerify(n) {
        RED.nodes.createNode(this, n);
        this.name = n.name;
        this.payload = n.payload;
        this.alg = n.alg;
        this.jwkurl = n.jwkurl;
        this.secret = n.secret;
        this.secb64enc = n.secb64enc;
        this.key = n.key;
        this.signvar = n.signvar;
        this.storetoken = n.storetoken;
        var node = this;

        if (node.jwkurl) {
            GetJWK(node.jwkurl, node);
        }else{
            node.jwk = false;
            if (contains(node.alg, 'RS256') || contains(node.alg, 'RS384') || contains(node.alg, 'RS512') || contains(node.alg, 'ES512') || contains(node.alg, 'ES384') || contains(node.alg, 'ES256')) {
                node.secret = process.env.NODE_RED_NODE_JWT_PUBLIC_KEY || fs.readFileSync(node.key);
            } else {
                node.secret = process.env.NODE_RED_NODE_JWT_SECRET || node.secret;
            }
        }

        node.on('input', function (msg, send, done) {
            send = send || function() { node.send.apply(node,arguments) }
            done = done || function(err) { if(err)node.error(err, msg); }
            if (node.signvar === 'bearer') {
                if (msg.req !== undefined && msg.req.get('authorization') !== undefined) {
                    var authz = msg.req.get('authorization').split(' ');
                    if(authz.length == 2 && (authz[0] === 'Bearer' || (msg.prefix !== undefined && authz[0] === msg.prefix))){
                        msg.bearer = authz[1];
                    }
                } else if (msg.req.query.access_token !== undefined) {
                    msg.bearer = msg.req.query.access_token;
                } else if (msg.req.body !== undefined && msg.req.body.access_token !== undefined) {
                    msg.bearer = msg.req.body.access_token;
                }
            }

            if (node.jwk) {
                //use JWK to verify
                var header = GetTokenHeader(msg[node.signvar]);
                //find kid if present
                var kid = header.kid;
                var key;

                if (kid !== undefined) {
                    key = node.jwk.findKeyById(kid);
                } else {
                    //...otherwise use first key in set
                    key = node.jwk.keys[0];
                }

                node.alg = header.alg;
                node.secret = key.key.toPublicKeyPEM();
            }

            if (node.secb64enc === "true"){
                node.secret = Buffer.from(node.secret, 'base64');
            }

            jwt.verify(msg[node.signvar], node.secret, {algorithms: node.alg}, function (err, decoded) {
                if (err) {
                    msg['payload'] = err;
                    msg['statusCode'] = 401;
                    done(err);
                } else {
                    msg[node.storetoken] = decoded;
                    send([msg, null]);
                    done();
                }
            });
        });
    }
    RED.nodes.registerType("jwt verify", JwtVerify);

    function GetJWK(url, node) {
        //fetch jwk and cache it in node
        var jwk;
        var njwk = require('node-jwk');
        var request = require("request");
        request({
            url: url,
            json: true
        }, function (error, response, body) {
            if (!error && response.statusCode === 200) {
                node.jwk = njwk.JWKSet.fromObject(body);
                console.log(node.jwk._keys.length + " keys loaded from JWK: " + url );
            } else {
                console.log("Unable to fetch JWK: " + url);
            }
        })
    }

    function GetTokenKid(token) {
        //get kid from token header
        var header = GetTokenHeader(token);
        return header.kid;
    }

    function GetTokenHeader(token) {
        var json = jwt.decode(token, {complete: true});
        return json.header;
    }
};


