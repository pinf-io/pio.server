#!/bin/bash

if [ -f "/etc/init/app-$PIO_SERVICE_ID_SAFE.conf" ]; then
    sudo stop app-$PIO_SERVICE_ID_SAFE || true
fi
sudo start app-$PIO_SERVICE_ID_SAFE
