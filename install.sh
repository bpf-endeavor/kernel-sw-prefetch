#! /bin/bash
cd build/
sudo rm /boot/*6.15*
sudo rm -r /lib/modules/6.15*

sudo make INSTALL_MOD_STRIP=1 modules_install
sudo make install
