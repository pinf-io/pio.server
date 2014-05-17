#!/bin/bash -e

MON_VERSION="1.2.3"
NODE_VERSION="v0.10.26"

CONFIGURED_DIR=$(date +%s%N)


sudo apt-get -y install git-core realpath


if [ ! -d "configured/$CONFIGURED_DIR" ]; then
	mkdir -p configured/$CONFIGURED_DIR
fi
cp -Rf sync/scripts configured/$CONFIGURED_DIR/scripts
cp -Rf sync/source configured/$CONFIGURED_DIR/source
cp -Rf sync/source configured/$CONFIGURED_DIR/install


cd configured/$CONFIGURED_DIR/install
if [ ! -d "../../../packages/node-$NODE_VERSION" ]; then
	sh $PIO_SCRIPTS_PATH/install-nodejs.sh $NODE_VERSION
	rm ../../../packages/node || true
	ln -s node-$NODE_VERSION ../../../packages/node
fi
if [ ! -d "../../../packages/mon-$MON_VERSION" ]; then
    sh $PIO_SCRIPTS_PATH/install-mon.sh $MON_VERSION
	rm ../../../packages/mon || true
	ln -s mon-$MON_VERSION ../../../packages/mon
fi
sudo mkdir node_modules
sudo chown $PIO_SERVICE_OS_USER:$PIO_SERVICE_OS_USER node_modules
../../../packages/node/bin/npm install --production
cd ../../..


cp sync/.pio.json configured/$CONFIGURED_DIR

rm -f live || true
ln -s configured/$CONFIGURED_DIR live


sudo chmod -Rf ug+x "$PIO_SERVICE_PATH/live/scripts"


launchScript='
#!/bin/bash -e
. '$PIO_BIN_PATH'/activate.sh
export PATH='$PATH'
export PORT='$PORT'
'$PIO_SERVICE_PATH'/packages/node/bin/node '$PIO_SERVICE_PATH'/live/install/server.js >> '$PIO_SERVICE_LOG_BASE_PATH'.log 2>&1 
'
echo "$launchScript" | sudo tee $PIO_SCRIPTS_PATH/_launch.sh
sudo chmod ug+x $PIO_SCRIPTS_PATH/_launch.sh


initScript='
description "'$PIO_SERVICE_ID_SAFE'"

start on local-filesystems
stop on shutdown

script
    exec '$PIO_SERVICE_PATH'/packages/mon/mon --pidfile "'$PIO_SERVICE_RUN_BASE_PATH'.pid" --mon-pidfile "'$PIO_SERVICE_RUN_BASE_PATH'.mon.pid" --log "'$PIO_SERVICE_LOG_BASE_PATH'.log" '$PIO_SCRIPTS_PATH'/_launch.sh  >> '$PIO_SERVICE_LOG_BASE_PATH'.launch.log 2>&1
end script

pre-start script
    echo "\\n\\n[`date -u +%Y-%m-%dT%T.%3NZ`] (/etc/init/app-'$PIO_SERVICE_ID_SAFE'.conf) ########## STARTING ##########\\n" >> '$PIO_SERVICE_LOG_BASE_PATH'.log
end script

pre-stop script
    rm -f '$PIO_SERVICE_RUN_BASE_PATH'.pid
    echo "\\n[`date -u +%Y-%m-%dT%T.%3NZ`] (/etc/init/app-'$PIO_SERVICE_ID_SAFE'.conf) ^^^^^^^^^^ STOPPING ^^^^^^^^^^\\n\\n" >> '$PIO_SERVICE_LOG_BASE_PATH'.log
end script
'
if [ -f "/etc/init/app-$PIO_SERVICE_ID_SAFE.conf" ]; then
    sudo stop app-$PIO_SERVICE_ID_SAFE || true
fi
echo "$initScript" | sudo tee /etc/init/app-$PIO_SERVICE_ID_SAFE.conf
sudo start app-$PIO_SERVICE_ID_SAFE
