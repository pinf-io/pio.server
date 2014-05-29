
const ASSERT = require("assert");
const PATH = require("path");
const FS = require("fs-extra");
const URL = require("url");
const QUERYSTRING = require("querystring");
const EVENTS = require("events");
const HTTP = require('http');
const DNODE = require('dnode');
const SPAWN = require("child_process").spawn;
const DEEPMERGE = require("deepmerge");
const UUID = require("uuid");
const HTTP_PROXY = require("http-proxy");
const CRYPTO = require("crypto");
const MEMCACHED = require('memcached');


function main(callback) {

    var pioConfig = FS.readJsonSync(PATH.join(__dirname, "../.pio.json"));
//console.log(JSON.stringify(pioConfig, null, 4));

    ASSERT.equal(typeof pioConfig.env.PORT, "number");
    ASSERT.equal(typeof pioConfig.env.DNODE_PORT, "number");

    var authCode = CRYPTO.createHash("sha1");
    authCode.update(["auth-code", pioConfig.config.pio.instanceId, pioConfig.config.pio.instanceSecret].join(":"));
    authCode = authCode.digest("hex");


    var sessions = {};
    var memcached = null;
    // @see https://github.com/3rd-Eden/node-memcached
    if (pioConfig.config.memcachedHost) {
        function tryToConnect() {
            // First see if there is a server available at all.
            // If not we retry at configured interval until successful.
            var connection = new MEMCACHED(pioConfig.config.memcachedHost, {
                failures: 1,
                retries: 1,
                timeout: 2 * 1000,
                remove: true
            });
            return connection.stats(function(err, stats) {
                if (err) {
                    if (err.code !== "ECONNREFUSED") {
                        console.error("err", err.stack);
                    }
                    setTimeout(function() {
                        tryToConnect();
                    }, 3 * 1000);
                    return;
                }
                connection.end();
                console.log("Connecting to memcached server: " + pioConfig.config.memcachedHost);
                // We found a server so now we need to setup a connection with proper parameters.
                memcached = new MEMCACHED(pioConfig.config.memcachedHost, {
                    failures: 10,
                    retries: 10,
                    reconnect: 5 * 1000,
                    timeout: 3 * 1000,
                    retry: 5 * 1000
                });
                // Periodically touch sessions in DB
                // TODO: Configure session timeout.
                setInterval(function() {
                    console.log("Touch memcache sessions: " + Object.keys(sessions).length);
                    for (var id in sessions) {
                        memcached.touch(id, 60 * 60, function (err) {
                            if (err) {
                                console.log("error touching memcache entry", err);
                            }
                        });
                    }
                }, 60 * 5 * 1000);
            });
        }
        tryToConnect();
    }
    function makeSession(callback) {
        var id = UUID.v4();
        console.log("Create new session!");
        if (memcached) {
            // TODO: Configure session timeout.
            return memcached.set(id, "", 60 * 60, function (err) {
                if (err) return callback(err);
                sessions[id] = "";
                return callback(null, id);
            });
        }
        sessions[id] = "";
        return callback(null, id);
    }
    function ensureSession(_authCode, id, callback) {
        if (!id) {
            if (_authCode === authCode) {
                return makeSession(callback);
            }
            // Not authorized: No session id and no auth code to create session id!
            return callback(null, false);
        }
        if (typeof sessions[id] !== "undefined") {
            return callback(null, id);
        }
        if (memcached) {
            return memcached.get(id, function(err, data) {
                if (err) {
                    console.error("error getting from memcached", err);
                    // Not authorized: session id not found!
                    return callback(null, false);
                }
                sessions[id] = data;
                return callback(null, id);
            });
        }
        // Not authorized: session id not found!
        return callback(null, false);
    }



    var dnode = DNODE(function(client) {

        function normalizeCallback(callback) {
            return function(err) {
                if (err) {
console.log("GOT error:", err.code, err.stack);
                    return callback({
                        code: err.code || null,
                        stack: err.stack
                    });
                }
                return callback.apply(null, Array.prototype.slice.call(arguments, 0));
            };
        }

        function authorize(args, callback, proceed) {
            if (
                args &&
                args.$authCode &&
                args.$authCode === authCode
            ) {
                return proceed();
            }
            // TODO: If rejecting same IP too often block it for a while.
            var err = new Error("Not authorized!");
            err.code = 403;
            return callback(err);
        }

        this.ping = function (args, callback) {
            callback = normalizeCallback(callback);
            return authorize(args, callback, function() {
                return callback(null, {
                    timeClient: args.timeClient,
                    timeServer: Date.now()
                });
            });
        }

        this.config = function (args, callback) {
            callback = normalizeCallback(callback);
            return authorize(args, callback, function() {
                try {
                    ASSERT.equal(typeof args.servicePath, "string", "'args.servicePath' must be set!");
                    function getSyncPIOdescriptor(callback) {
                        var path = PATH.join(args.servicePath, "live/.pio.json");
                        return FS.exists(path, function(exists) {
                            if (!exists) {
                                path = PATH.join(args.servicePath, "sync/.pio.json");
                                return FS.exists(path, function(exists) {
                                    if (!exists) {
                                        return callback(null, null);
                                    }
                                    return FS.readJson(path, callback);
                                });
                            }
                            return FS.readJson(path, callback);
                        });
                    }
                    return getSyncPIOdescriptor(callback);
                } catch(err) {
                    return callback(err);                
                }
            });
        }

        this._putFile = function(args, callback) {
            callback = normalizeCallback(callback);
            return authorize(args, callback, function() {
                try {
                    ASSERT.equal(typeof args.path, "string", "'args.path' must be set!");
                    ASSERT.equal(typeof args.body, "string", "'args.body' must be set!");
                    console.log("_putFile", args.path);
                    return FS.outputFile(args.path, new Buffer(args.body, "base64"), function(err) {
                        if (err) return callback(err);
                        console.log("_putFile write done", args.path);
                        return FS.chown(args.path, 1000, 1000, function(err) {
                            if (err) return callback(err);                        
                            console.log("_putFile chown done", args.path);
                            return callback(null, true);
                        });
                    });
                } catch(err) {
                    return callback(err);
                }
            });
        }

        this._runCommands = function(args, callback) {
            callback = normalizeCallback(callback);
            return authorize(args, callback, function() {
                try {
                    ASSERT.equal(Array.isArray(args.commands), true, "'args.commands' must be set!");
                    ASSERT.equal(typeof args.cwd, "string", "'args.cwd' must be set!");
                    var commandsFilePath = PATH.join(__dirname, "../.tmp", UUID.v4() + ".sh");
                    return FS.exists(args.cwd, function(exists) {
                        if (!exists) {
                            return callback(new Error("Cannot call commands! 'cwd' path '" + args.cwd + "' does not exist!"));
                        }
        console.log("Running commands in cwd: " + args.cwd);
        process.stdout.write(args.commands.join("\n") + "\n\n");    
                        return FS.outputFile(commandsFilePath, [
                            "#!/bin/sh -e"
                        ].concat(args.commands).join("\n"), function(err) {
                            if (err) return callback(err);
                            var env = process.env;
                            var opts = {
                                cwd: args.cwd,
                                env: env
                            };
                            if (pioConfig.config["pio.vm"].user === "root") {
                                env.HOME = "/root";
                            } else {
                                env.HOME = "/home/" + pioConfig.config["pio.vm"].user;
                                // TODO: Determine user and group integers dynamically based on user.
                                opts.uid = 1000;
                                opts.gid = 1000;
                            }
        console.log("env", env);
        console.log("opts", opts);

                            var proc = SPAWN("sh", [
                                commandsFilePath
                            ], opts);
                            function allDone(code) {
                                if (!callback) {
                                    return;
                                }
                                var cb = callback;
                                callback = null;
        console.log("Commands done with exit code: " + code);
                                return FS.unlink(commandsFilePath, function(err) {
                                    if (err) {
                                        console.error("WARN: Error unlinking file:", commandsFilePath);
                                        // TODO: Log into alert system.
                                        // TODO: Schedule file for later deletion.
                                    }
                                    return cb(null, code);
                                });
                            }
                            var command_re = /\[pio:([^\]]+)\]\[([^\]]+)\]/;
                            var timeoutId = null;
                            proc.on("error", function(err) {

        process.stderr.write(err.stack);
                                client.stderr(args.$requestId, new Buffer(err.stack).toString("base64"));

                                return allDone(500);
                            });
                            proc.stdout.on('data', function (data) {
        process.stdout.write(data);
                                client.stdout(args.$requestId, data.toString("base64"));
                                var m = data.toString().match(command_re);
                                if (m) {
                                    // Look for output `[pio:return-ok-after-timeout][2000]` to set a timeout.
                                    if (m[1] === "return-ok-after-timeout") {
                                        if (timeoutId) {
                                            clearTimeout(timeoutId);
                                        }
        // TODO: Send this notice through backchannel.
        process.stdout.write("[pio] set process return-ok-after-timeout: " + parseInt(m[2]) + "\n");
        client.stdout(args.$requestId, new Buffer("[pio] set process return-ok-after-timeout: " + parseInt(m[2]) + "\n").toString("base64"));
                                        timeoutId = setTimeout(function() {
                                            timeoutId = null;
        // TODO: Send this notice through backchannel.
        process.stdout.write("[pio] leave process running due to return-ok-after-timeout and return\n");
        client.stdout(args.$requestId, new Buffer("[pio] leave process running due to return-ok-after-timeout and return\n").toString("base64"));

                                            // Assume script is going to exit fine.
                                            // TODO: Keep trak of process and alert if not done after some time.
                                            return allDone(0);
                                        }, parseInt(m[2]));
                                    }
                                }
                            });
                            proc.stderr.on('data', function (data) {
        process.stderr.write(data);
                                client.stderr(args.$requestId, data.toString("base64"));
                            });
                            return proc.on('close', function (code) {
                                if (timeoutId) {
                                    clearTimeout(timeoutId);
                                    timeoutId = null;
                                }
                                return allDone(code);
                            });
                        });
                    });
                } catch(err) {
                    return callback(err);
                }
            });
        }
    });

    dnode.on("error", function(err) {
        console.error(err.stack);
        process.exit(1);
    });

    var dnodeServer = dnode.listen(pioConfig.env.DNODE_PORT, "0.0.0.0");
    console.log("Listening on: dnode://0.0.0.0:" + pioConfig.env.DNODE_PORT);



    var vhosts = {};
    for (var pluginId in  pioConfig["config.plugin"]) {
        for (var hostname in pioConfig["config.plugin"][pluginId]) {
            if (pioConfig["config.plugin"][pluginId].vhosts) {
                var _vhosts = pioConfig["config.plugin"][pluginId].vhosts;
                for (var host in _vhosts) {
                    if (typeof _vhosts[host] === "string") {
                        _vhosts[host] = {
                            "target": _vhosts[host]
                        };
                    }
                }
                vhosts = DEEPMERGE(vhosts, _vhosts);
            }
        }
    }
    console.log("vhosts", JSON.stringify(vhosts, null, 4));
    var proxy = HTTP_PROXY.createProxyServer({});
    var server = HTTP.createServer(function(req, res) {
        function respond500(err) {
            console.error("error request", req.url);
            console.error(err.stack);
            res.writeHead(500);
            return res.end("Internal server error!");
        }
        var urlParts = URL.parse(req.url);
        var qs = urlParts.query ? QUERYSTRING.parse(urlParts.query) : {};

        // @source http://stackoverflow.com/a/3409200/330439
        function parseCookies(request) {
            var list = {},
                rc = request.headers.cookie;
            rc && rc.split(';').forEach(function( cookie ) {
                var parts = cookie.split('=');
                list[parts.shift().trim()] = unescape(parts.join('='));
            });
            return list;
        }

        var cookies = parseCookies(req);

        var originalHost = (req.headers.host && req.headers.host.split(":").shift()) || null;
        var host = null;
        var byIP = false;
        // If accessing by IP we convert the IP to our default hostname.
        if (originalHost === pioConfig.config['pio.vm'].ip) {
            byIP = true;
            host = pioConfig.config['pio'].hostname;
        } else {
            host = originalHost;
        }

        function ensureAuthorized(proceed) {
            // TODO: Hook in more generically and document this route.
            if (urlParts.pathname === "/.set-session-cookie" && qs.sid) {
                res.writeHead(204, {
                    'Set-Cookie': 'x-pio-server-sid=' + qs.sid,
                    'Content-Type': 'text/plain',
                    'Content-Length': "0"
                });
                return res.end();
            }
            if (vhosts[host] && vhosts[host].expose) {
                return proceed();
            }
            return ensureSession(null, cookies["x-pio-server-sid"], function(err, sessionId) {
                if (err) return respond500(err);
                if (qs["auth-code"] === authCode) {
                    return ensureSession(qs["auth-code"], null, function(err, sessionId) {
                        if (err) return respond500(err);
                        var payload = [
                            '<script>'
                        ];
                        for (var host in vhosts) {
                            // TODO: Use ajax and only continue until we confirm session has been initialized on all vhosts.
                            if (byIP) {
                                var target = vhosts[host].target.split(":");
                                payload.push('document.write(\'<img src="//' + pioConfig.config['pio.vm'].ip + ':' + target[1] + '/.set-session-cookie?sid=' + sessionId + '" width="0" height="0">\');');
                             } else {
                                payload.push('document.write(\'<img src="//' + host + ':\' + window.location.port + \'/.set-session-cookie?sid=' + sessionId + '" width="0" height="0">\');');
                            }
                        }
                        payload.push('setTimeout(function() {');
                        if (byIP) {
                            if (vhosts[pioConfig.config.adminSubdomain + "." + pioConfig.config['pio'].hostname]) {
                                var target = vhosts[pioConfig.config.adminSubdomain + "." + pioConfig.config['pio'].hostname].target.split(":");
                                payload.push('window.location.href = "//' + pioConfig.config['pio.vm'].ip + ':' + target[1] + '";');
                            } else {
                                res.writeHead(404);
                                console.error("Admin subdomain '" + pioConfig.config.adminSubdomain + "' not found in configured vhosts!", req.url, req.headers, vhosts);
                                return res.end("Admin subdomain '" + pioConfig.config.adminSubdomain + "' not found in configured vhosts!");
                            }
                        } else {
                            payload.push('window.location.href = "//' + pioConfig.config.adminSubdomain + '." + window.location.host;');
                        }
                        payload.push('}, 3 * 1000);');
                        payload.push('</script>');
                        payload.push('Redirecting after initializing session ...');
                        payload = payload.join("\n");
                        res.writeHead(200, {
                            'Set-Cookie': 'x-pio-server-sid=' + sessionId,
                            'Content-Type': 'text/html',
                            'Content-Length': payload.length
                        });
                        res.end(payload);
                        return;
                    });
                }
                if (!sessionId || sessionId !== cookies["x-pio-server-sid"]) {
                    res.writeHead(403);
                    return res.end("Forbidden");
                }
                return proceed(null);
            });
        }

        if (!vhosts[host] && host !== pioConfig.config.pio.hostname) {
            res.writeHead(404);
            console.error("Virtual host '" + host + "' not found!", req.url, req.headers);
            return res.end("Virtual host '" + host + "' not found!");
        }

        var origin = null;
        if (req.headers.origin) {
            origin = req.headers.origin;
        } else
        if (req.headers.host) {
            origin = [
                (pioConfig.env.PORT === 443) ? "https" : "http",
                "://",
                req.headers.host
            ].join("");
        }
        res.setHeader("Access-Control-Allow-Methods", "GET");
        res.setHeader("Access-Control-Allow-Credentials", "true");
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, Cookie");
        if (req.method === "OPTIONS") {
            return res.end();
        }

        return ensureAuthorized(function() {

            try {

                // TODO: Hook in more generically and document this route.
                if (req.url === "/.instance-id/" + pioConfig.config["pio"].instanceId) {
                    res.writeHead(204);
                    return res.end();
                }

                if (!vhosts[host]) {
                    res.writeHead(404);
                    console.error("Virtual host '" + host + "' not found!", req.url, req.headers);
                    return res.end("Virtual host '" + host + "' not found!");
                }

//                console.log("Proxy request", req.url, "for", "http://" + vhosts[host]);

                return proxy.web(req, res, {
                    target: "http://" + vhosts[host].target
                }, function(err) {
                    if (err.code === "ECONNREFUSED") {
                        res.writeHead(502);
                        return res.end("Bad Gateway");
                    }
                    return respond500(err);
                });
            } catch(err) {
                return respond500(err);
            }
        });
    });
    var httpServer = server.listen(pioConfig.env.PORT, "0.0.0.0");
    console.log("Listening on: http://0.0.0.0:" + pioConfig.env.PORT);
    console.log("Instance identity: " + "http://" + pioConfig.config["pio"].hostname + ":" + pioConfig.env.PORT + "/.instance-id/" + pioConfig.config["pio"].instanceId);

    // curl -v --header "Host: pio.catalog" http://54.198.95.219:8013/catalog/io.pinf.pio/a35593c282b9d36dba07104ae594dg3df43b841e

    return callback(null, {
        api: {
            shutdown: function(callback) {
                return dnodeServer.close(function() {
                    return httpServer.close(callback);
                });
            }
        }
    });
}


if (require.main === module) {
    try {
        return main(function(err) {
            if (err) {
                console.error(err.stack);
                return process.exit(1);
            }
            // Continue running server.
        });
    } catch(err) {
        console.error(err.stack);
        return process.exit(1);
    }
}

