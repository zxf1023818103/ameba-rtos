import os
import array as arr
import subprocess

Major = 0
Minor = 0
Build = 0
with open('../amazon-freertos/ports/amebaDplus/config_files/ota_demo_config.h') as f:
    for line in f:
        if line.find('define APP_VERSION_MAJOR') != -1:
            x = line.split()
            Major = int(x[2])
        if line.find('define APP_VERSION_MINOR') != -1:
            x = line.split()
            Minor = int(x[2])
        if line.find('define APP_VERSION_BUILD') != -1:
            x = line.split()
            Build = int(x[2])

print('Major:' + str(Major))
print('Minor:' + str(Minor))
print('Build:' + str(Build))

#version = 0xffffffff
version = Major*1000000 + Minor*1000 + Build
version_byte = version.to_bytes(4,'little')

# fix OTA_All header
with open("../../../../amebadplus_gcc_project/OTA_All.bin", 'r+b') as f:
    f.seek(0)
    f.write(version_byte)
    print("Successfully modified OTA_All.bin version")

#caculate signature and output to IDT-OTA-Signature
subprocess.call(['sh', './signer_gcc.sh'])

