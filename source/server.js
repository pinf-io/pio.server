
const ASSERT = require("assert");
const PATH = require("path");
const FS = require("fs-extra");
const EVENTS = require("events");
const HTTP = require('http');
const DNODE = require('dnode');
const SPAWN = require("child_process").spawn;
const DEEPMERGE = require("deepmerge");
const UUID = require("uuid");
const HTTP_PROXY = require("http-proxy");
const CRYPTO = require("crypto");


function main(callback) {

    var pioConfig = FS.readJsonSync(PATH.join(__dirname, "../.pio.json"));
console.log(JSON.stringify(pioConfig, null, 4));

    ASSERT.equal(typeof pioConfig.env.PORT, "number");
    ASSERT.equal(typeof pioConfig.env.DNODE_PORT, "number");

    var authCode = CRYPTO.createHash("sha1");
    authCode.update(["auth-code", pioConfig.config.pio.instanceId, pioConfig.config.pio.instanceSecret].join(":"));
    authCode = authCode.digest("hex");

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

        this.info = function (args, callback) {
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
                            env.HOME = "/home/" + pioConfig.config["pio.vm"].user;
        console.log("env", env);
                            var proc = SPAWN("sh", [
                                commandsFilePath
                            ], {
                                cwd: args.cwd,
                                env: env,
                                uid: 1000,
                                gid: 1000
                            });
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
                vhosts = DEEPMERGE(vhosts, pioConfig["config.plugin"][pluginId].vhosts);
            }
        }
    }
    console.log("vhosts", vhosts);
    var proxy = HTTP_PROXY.createProxyServer({});
    var server = HTTP.createServer(function(req, res) {
        function respond500(err) {
            console.error("error request", req.url);
            console.error(err.stack);
            res.writeHead(500);
            return res.end("Internal server error!");
        }
        try {
            if (req.url === "/.instance-id/" + pioConfig.config["pio"].instanceId) {
                res.writeHead(204);
                return res.end();
            }
            var host = req.headers.host.split(":").shift();
            if (!vhosts[host]) {
                res.writeHead(404);
                return res.end("Virtual host '" + host + "' not found!");
            }
            console.log("Proxy request", req.url, req.headers, "for", "http://" + vhosts[host]);


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
            res.setHeader("Access-Control-Allow-Headers", "Content-Type");
            if (req.method === "OPTIONS") {
                return res.end();
            }

            return proxy.web(req, res, {
                target: "http://" + vhosts[host]
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

