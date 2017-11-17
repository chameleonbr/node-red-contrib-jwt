module.exports = function (RED) {
    var jwt = require('jsonwebtoken');
    var fs = require('fs');
    function JwtSign(n) {
        RED.nodes.createNode(this, n);
        this.name = n.name;
        this.payload = n.payload;
        this.alg = n.alg;
        this.exp = n.exp;
        this.secret = n.secret;
        this.key = n.key;
        this.signvar = n.signvar;
        this.storetoken = n.storetoken;
        var node = this;
        node.on('input', function (msg) {
            try {
                if (node.alg === 'RS256' ||
                        node.alg === 'RS384' ||
                        node.alg === 'RS512') {
                    node.secret = process.env.NODE_RED_NODE_JWT_PRIVATE_KEY || fs.readFileSync(node.key);
                } else {
                    node.secret = process.env.NODE_RED_NODE_JWT_SECRET || node.secret;
                }
                jwt.sign(msg[node.signvar],
                        node.secret,
                        {algorithm: node.alg, expiresIn: node.exp}, function (token) {
                    msg[node.storetoken] = token;
                    node.send(msg);
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
        this.secret = n.secret;
        this.key = n.key;
        this.signvar = n.signvar;
        this.storetoken = n.storetoken;
        var node = this;
        node.on('input', function (msg) {
            if (contains(node.alg, 'RS256') || contains(node.alg, 'RS384') || contains(node.alg, 'RS512')) {
                node.secret = process.env.NODE_RED_NODE_JWT_PUBLIC_KEY || fs.readFileSync(node.key);
            } else {
                node.secret = process.env.NODE_RED_NODE_JWT_SECRET || node.secret;
            }

            if (node.signvar === 'bearer') {
                if (msg.req !== undefined && msg.req.get('authorization') !== undefined) {
                    var authz = msg.req.get('authorization').split(' ');
                    if(authz.length == 2 && authz[0] === 'Bearer'){
                        msg.bearer = authz[1];
                    }
                } else if (msg.req.query.access_token !== undefined) {
                    msg.bearer = msg.req.query.access_token;
                } else if (msg.req.body !== undefined && msg.req.body.access_token !== undefined) {
                    msg.bearer = msg.req.body.access_token;
                }
            }

            jwt.verify(msg[node.signvar], node.secret, {algorithms: node.alg}, function (err, decoded) {
                if (err) {
                    msg['payload'] = err;
                    msg['statusCode'] = 401;
                    node.error(err,msg);
                } else {
                    msg[node.storetoken] = decoded;
                    node.send([msg, null]);
                }
            });
        });
    }
    RED.nodes.registerType("jwt verify", JwtVerify);
};