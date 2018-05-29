
1-Install the following libraries :
sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils
sudo apt-get install sqlite3

wget https://www.cryptopp.com/cryptopp563.zip
unzip -aoq cryptopp563.zip -d cryptopp
cd cryptopp
make

2-Then, run the following command in the terminal:
g++ geemail.cpp -Wno-write-strings -lgcrypt --std=c++11 -lsqlite3

The “gee mail.db” database should be in the same directory.
