# gpbs-dissector
wireshark dissector for gpbs protocol
## Building instructions
Get wireshark code
```
git clone https://code.wireshark.org/review/wireshark
cd wireshark
git checkout wireshark-1.12.7
```
Get gpbs-dissector code
```
git clone https://github.com/mkevac/gpbs-dissector.git
cp -r gpbs-dissector/* wireshark/plugins/
```
Build
```
cd wireshark
./autogen.sh
./configure --prefix=/home/marko/opt/wireshark --with-qt=no --with-gtk3=yes
make install -j8
```
