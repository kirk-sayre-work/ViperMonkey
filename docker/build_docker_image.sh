#!/bin/bash

if [[ $1 == "-h" ]]; then
    echo "Build a local copy of the ViperMonkey Docker image."
    echo "The built image needs to be pushed out to the global Docker image repository manually."
    echo ""
    echo "This script MUST be run from the /docker directory in the Git repo!"
   exit
fi

# Need local copies of LibreOffice macro files to copy into image.
cp ../vipermonkey/libreoffice_macros/Module1.xba .
cp ../vipermonkey/libreoffice_macros/libreoffice_config_dir.tar.gz .

# Build the docker image.
sudo docker build -t kirksayre/vipermonkey_pypy3:latest .

# Done.
echo "Done. Image is built."
