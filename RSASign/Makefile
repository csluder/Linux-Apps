all:
	g++ -shared -Wall -fPIC -o rsaSign.so RSASign.cpp -lcrypto
	g++ -Wall -fPIC -o rsaSign.a -c RSASign.cpp -lcrypto
	g++ appSigningTool.cpp rsaSign.a -o appSigningTool -lcrypto
	g++ sigVerify.cpp rsaSign.a -o sigVerify -lcrypto

