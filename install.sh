#! /bin/bash
set -e

cd build/
make -j 32
sudo cp -r ./usr / || true
sudo rm /boot/*6.15* || true
sudo rm -r /lib/modules/6.15* || true
sudo make INSTALL_MOD_STRIP=1 modules_install
sudo make install
