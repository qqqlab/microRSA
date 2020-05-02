# microRSA512
RSA512 encrypt library for small microcontrollers.

### Benchmark Arduino ATmega328P 
Flash: 2408 bytes  
RAM: 5 * (64+1 + 2) =  335 bytes  
Runtime: 440ms @ 16MHz = 2.7M CPU Cycles   

### Generate RSA Keys 
on linux for example a Raspberry Pi:
```
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

#get modulus (public key) as hex string
openssl rsa -in rsa512.pem -noout -modulus | sed 's/Modulus=//'
A2C88620FB3179A48B5F126D70D812922A2E151675915E0B752F2DE173C1A891CA2D6964CB4419017C63780C9E39394A310ECB529B01F3AEF76F0A142ED5A60F

#raw encrypt
echo '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' | xxd -r -p - | openssl rsautl -raw -encrypt -inkey rsa512.pem | xxd -p -c256 -
299da147204aaab26f8c26fb9f11b7f92365fe083d10a87ebab49dbc787d01a4178fb5d8c07d6732ca3258e739222d7ad1473ad7b6fc14f929a6737d1856d29f

#raw decrypt
echo '299da147204aaab26f8c26fb9f11b7f92365fe083d10a87ebab49dbc787d01a4178fb5d8c07d6732ca3258e739222d7ad1473ad7b6fc14f929a6737d1856d29f' | xxd -r -p - | openssl rsautl -raw -decrypt -inkey rsa512.pem | xxd -p -c256 -
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f

#pkcs decrypt for raw encrypted plain text
echo '299da147204aaab26f8c26fb9f11b7f92365fe083d10a87ebab49dbc787d01a4178fb5d8c07d6732ca3258e739222d7ad1473ad7b6fc14f929a6737d1856d29f' | xxd -r -p - | openssl rsautl -pkcs -decrypt -inkey rsa512.pem | xxd -p -c256 -
RSA operation error - padding check failed

#pkcs decrypt for pkcs encrypted plain text
echo '0B91BCE41408BC687F0C45495410ECFBA0592FB61AF7DBAD26FDF4F806912286740FB64161266F3697473F8BC8E4D9FAC1F37D7F4251956ECB4CA909B492583B' | xxd -r -p - | openssl rsautl -pkcs -decrypt -inkey rsa512.pem | xxd -p -c256 -
0001020304

#raw decrypt for pkcs encrypted plain text
echo '0B91BCE41408BC687F0C45495410ECFBA0592FB61AF7DBAD26FDF4F806912286740FB64161266F3697473F8BC8E4D9FAC1F37D7F4251956ECB4CA909B492583B' | xxd -r -p - | openssl rsautl -raw -decrypt -inkey rsa512.pem | xxd -p -c256 -
0002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000001020304
```
