# libaesni
Advanced Encryption Standard (AES) library using Intel AES-NI
# Installation
```shell
git clone https://github.com/Wirtos/libaesni
cd libaesni
# builds static library by default, add -DBUILD_SHARED_LIBS=ON
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_ASM_NASM_COMPILER="path/to/yasm" -DCMAKE_INSTALL_PREFIX="/folder/to/install/" 
cmake --build build --config Release --target install
```
