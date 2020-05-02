# microRSA
RSA encrypt library for small microcontrollers.

### Benchmark ATmega328P @ 16MHz

|RSA|Runtime (ms)|CPU Cycles|RAM (bytes)|
|---|--:|--:|--:|
|RSA1024|1804|28.9M|665|
|RSA768*|1013|16.2M|505|
|RSA512*|444|7.1M|345|
 
Flash: <2500 bytes with Arduino compiler 

*1) Anything below RSA1024 problably should not be used. See https://en.wikipedia.org/wiki/RSA_Factoring_Challenge

*2) By default exponent 3 is used. e=3 involves only 2 multiplications. With e=65537 this is 17 multiplications, so the runtime will be 8.5 times as long.

>There is no known attack against small public exponents such as e = 3, provided that the proper padding is used.
>https://en.wikipedia.org/wiki/RSA_(cryptosystem)

Better use the rsa_encrypt_pkcs() function with enough random bytes to ensure proper padding.

### Configuration
```#define RSA_BITS``` sets the bit length  
```#define RSA_E_ROUNDS``` sets the number of rounds for the exponent. Rounds=1 for e=3, Rounds=16 for e=65537  

### Generate RSA Keys 
On linux for example a Raspberry Pi:
```
#generate rsa512 key with exponent 3
openssl genrsa -3 -out rsa512.pem 512
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKLIhiD7MXmki18SbXDYEpIqLhUWdZFeC3UvLeFzwaiRyi1pZMtE
GQF8Y3gMnjk5SjEOy1KbAfOu928KFC7Vpg8CAQMCQGyFrsCndlEYXOoMSPXlYbbG
yWNkTmDpXPjKHpZNK8W1dlDCzL07C+pqAEo9lG+a26YoCKKisKuE2g5blWfkPQsC
IQDVsWmTpyOuiZyJmjV1A6wJMiMrafWS3udFK+XHGGrnGQIhAMMC254IR9iYQNlu
esqOJPeFr5L0sWYTgGstmuz6lGNnAiEAjnZGYm9tHwZoW7wjo1fIBiFsx5v5DJSa
Lh1D2hBHRLsCIQCCAee+sC/lutXmSacxtBilA8ph+HZEDQBHc7yd/GLs7wIhAJwj
RYacHiwKw4Fh91C2P7GWGzYhcIAX6s/Y/USkTycp
-----END RSA PRIVATE KEY-----

#show modulus (public key) as hex string
openssl rsa -in rsa512.pem -noout -modulus | sed 's/Modulus=//'
A2C88620FB3179A48B5F126D70D812922A2E151675915E0B752F2DE173C1A891CA2D6964CB4419017C63780C9E39394A310ECB529B01F3AEF76F0A142ED5A60F

#raw encrypt
echo '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' | xxd -r -p - | openssl rsautl -raw -encrypt -inkey rsa512.pem | xxd -p -c256 -
299da147204aaab26f8c26fb9f11b7f92365fe083d10a87ebab49dbc787d01a4178fb5d8c07d6732ca3258e739222d7ad1473ad7b6fc14f929a6737d1856d29f

#raw decrypt
echo '299da147204aaab26f8c26fb9f11b7f92365fe083d10a87ebab49dbc787d01a4178fb5d8c07d6732ca3258e739222d7ad1473ad7b6fc14f929a6737d1856d29f' | xxd -r -p - | openssl rsautl -raw -decrypt -inkey rsa512.pem | xxd -p -c256 -
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f

#pkcs decrypt for raw encrypted plain text failes as expected
echo '299da147204aaab26f8c26fb9f11b7f92365fe083d10a87ebab49dbc787d01a4178fb5d8c07d6732ca3258e739222d7ad1473ad7b6fc14f929a6737d1856d29f' | xxd -r -p - | openssl rsautl -pkcs -decrypt -inkey rsa512.pem | xxd -p -c256 -
RSA operation error - padding check failed

#pkcs decrypt for pkcs encrypted plain text
echo '0B91BCE41408BC687F0C45495410ECFBA0592FB61AF7DBAD26FDF4F806912286740FB64161266F3697473F8BC8E4D9FAC1F37D7F4251956ECB4CA909B492583B' | xxd -r -p - | openssl rsautl -pkcs -decrypt -inkey rsa512.pem | xxd -p -c256 -
0001020304

#raw decrypt for pkcs encrypted plain text
echo '0B91BCE41408BC687F0C45495410ECFBA0592FB61AF7DBAD26FDF4F806912286740FB64161266F3697473F8BC8E4D9FAC1F37D7F4251956ECB4CA909B492583B' | xxd -r -p - | openssl rsautl -raw -decrypt -inkey rsa512.pem | xxd -p -c256 -
0002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000001020304
```
