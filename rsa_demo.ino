/*
RSA: 2408 bytes flash 
RSA512 needs 5 * (64+1 + 4) =  345 bytes RAM (//alloc 1 byte extra to prevent reallocs when doing operations + 2 byte len + 2 byte capacity)
440ms @ 16MHz = 2.7M Cycles

#generate rsa keys on linux for example a Raspberry Pi:
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

#get modulus as hex string
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

#show info
openssl rsa -in rsa512.pem -text


PKCS1-V1_5-ENCRYPT ((n, e), M)

   Input:
   (n, e)   recipient's RSA public key (k denotes the length in octets
            of the modulus n)
   M        message to be encrypted, an octet string of length mLen,
            where mLen <= k - 11

   Output:
   C        ciphertext, an octet string of length k

   Error: "message too long"

   Steps:

   1. Length checking: If mLen > k - 11, output "message too long" and
      stop.

   2. EME-PKCS1-v1_5 encoding:

      a. Generate an octet string PS of length k - mLen - 3 consisting
         of pseudo-randomly generated nonzero octets.  The length of PS
         will be at least eight octets.

      b. Concatenate PS, the message M, and other padding to form an
         encoded message EM of length k octets as

            EM = 0x00 || 0x02 || PS || 0x00 || M.


RSA768 e=3 key used in example:

-----BEGIN RSA PRIVATE KEY-----
MIIByQIBAAJhAKuFrORWoerYrwycoe5OzqrfPZoRRuaK6zP3N4E01y3KxwKuqYUy
kA0GPptUS3z/L/wjENTAGdd9+uZMJjkrED+ygZ/+Ec+7Pmln2rOggJwhTnsw61TY
RFTSUU+KsiS4YQIBAwJgclkd7Y8WnJB0sxMWnt80ceopEWDZ7wdHd/olAM3kyTHa
AcnGWMxgCK7UZ42HqKoe5RzGbzpdmJPPCaOuWYIjPzbZyBlbDaA3idgYxzF6fbq3
RxpdzEaOCqCvAIHiA/gDAjEA4zn5ZryhAKeH2RN2R0YJj0CYJgNfjp+w+6M1lWzy
//eI2oNgP6totmBR3kPwQG5nAjEAwT3txyvscfi8fsMqa6HR0Z+izdSprKs6HwB/
82lV35GytgX+YsMGjoD48IPu3lX3AjEAl3v7mdMWAG+v5gz5hNlbtNW6xAI/tGp1
/Rd5Dkih//pbPFeVf8ebJEA2lC1K1Z7vAjEAgNPz2h1IS/soVIIcR8E2i7/B3o3G
cxzRagBVTPDj6mEhzq6plyyvCatQoFf0lDlPAjBapuYCuaMv8wvL0IfaaOOtuIb+
h4rLUKG82YhyDzcesqf3rV4utaOZWDasUBEcuqM=
-----END RSA PRIVATE KEY-----


RSA1024 e=3 key used in example:

-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDY4UB1dtkQAyZEVs8ZNuSa1w+nXPOox8Dqgyuvg79p7mdce7PD
gpTtzr5izPHqooyJb0hhuG+P0Wp3eKlDtxd1OaE1zNQX6sgrT4BuE+VJCmoxu3ES
FUiEK/p05RVYIxd5Wg3GHAfxcizdJ6IkU6dBhcFRsMARE0ewLpZyFp7FpwIBAwKB
gQCQlir4+eYKrMQtjzS7ee28j1/E6KJwhStHAh0frSpGnu+S/SKCVw3z3ymXM0vx
wbMGSjBBJZ+1Nkb6UHDXz2T3lrizAhFKwOUi/J/WKp7jeTATvkUnjcvo1vR9hFD4
kFOQpTOkpQhjfjFtSIT+bL0HRxpuPobDSPSmBcLU37Vh2wJBAPQFRl8jN/iekH0D
68Byuw1ybcr2xbtbWUxwNmNC/Nv/Pgf3QCcIydyuFgBd9WfdGBKo3NZZOYWYx/Oa
58pNMksCQQDjhuLqlu/Q0eZXjMEThDjHL6ZTEpEFO02dG4I7WOZumuJaSQ79cpJY
NKM6fLFIrp6IcM98nLKgP+8yV0r8wYCVAkEAoq4u6hd6pb8K/gKdKvcnXkxJMfnZ
J5I7iErO7NdTPVTUBU+AGgXb6HQOqulORT4QDHCTOZDRA7sv97yaht4hhwJBAJev
QfG59TXhRDpd1g0C0ITKbuIMYK4niRNnrCeQmZ8R7DwwtKj3DDrNwib9y4XJvwWg
ilMTIcAqn3bk3KiBAGMCQQDEy+xBwYrguJl7PBAuMHOPfAogczQwUpycRlWCwZUu
xtl7xqLuXNDNLxvp8RYynbaEtAHFxHNVqivMEDM/Tlif
-----END RSA PRIVATE KEY-----

RSA1024 e=65537 key used in example:

-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDD0yqK4/r6zkSpbutQ1ru/vAlYLd5cdTLuqwVK4iWUoPWI2DU+
dko/uDBP6dVYFq4MuVLNxZlkVxUBUuLxy1lT/HEMt/G22wJypfWClqqSScfr5j/a
UOI1CYTXCZlfDTiVbHV+P9Vo9yTq1GLTyHclpGojyc6ldPP4DJObPd5crwIDAQAB
AoGAD8hbK2qIdeJeAlHgQVmtNBzRm/vGaik/+6BpAsoLQVlfsLHMSMZ74XrU2fv8
p+bcDEZ7d/4vCLlEBiFKDTbYchop5YEhmb+han3x9x4wez1IbyrWZcDqTrwfqyv/
01PDtL0balE1i7AJ5s3pNFPrfyNqttvYw8sdxW9oZS6WVKECQQD2oIJpyW3JRSi9
kFXV9CfUZSzpf1+dEZN6GfCZUNgBQsGbGKAnNqRpHOLyKqdc11t+WDuu+1nQBmGc
9HZSDg+nAkEAy0RkKSwevzFokc/YtFMWVQajTL4f0AT96pypMWwicz2hX45Uzw4A
3gVfbFk3UcBnntsHe9+fmA6ddHn9hMwruQJBAKy26525+rChRk667eHQArSzxigf
k44j6OvxjpVQEHWRkpRTQpUzpyAVormFNX/HMcPhdqqsS9FrJqEMcnA0eLECQHyV
Zm51xEKbHeSA5+leI4npj50xyn3NEXQCoRDRnivT0lym+AQQKSfrUxktdWJ98wTC
akvaPA8OpiMFwgTqvsECQQCqg7p8YdYZkgQxr4/2uSFxKz7jrJhAOT2JCKndQfei
R5gQ3k+RnG2uDA3EHhztddN5AzPrZV90gMtBfzlcWAEg
-----END RSA PRIVATE KEY-----

            
*/

#include "qqq_rsa.h"

/*
//RSA512 example
//const char* modulus_s= "A2C88620FB3179A48B5F126D70D812922A2E151675915E0B752F2DE173C1A891CA2D6964CB4419017C63780C9E39394A310ECB529B01F3AEF76F0A142ED5A60F";
//const char* crypt_s=   "299DA147204AAAB26F8C26FB9F11B7F92365FE083D10A87EBAB49DBC787D01A4178FB5D8C07D6732CA3258E739222D7AD1473AD7B6FC14F929A6737D1856D29F"; 
//const char* pkcs_s=    "0B91BCE41408BC687F0C45495410ECFBA0592FB61AF7DBAD26FDF4F806912286740FB64161266F3697473F8BC8E4D9FAC1F37D7F4251956ECB4CA909B492583B";

//RSA768 example
const char* modulus_s= "AB85ACE456A1EAD8AF0C9CA1EE4ECEAADF3D9A1146E68AEB33F7378134D72DCAC702AEA98532900D063E9B544B7CFF2FFC2310D4C019D77DFAE64C26392B103FB2819FFE11CFBB3E6967DAB3A0809C214E7B30EB54D84454D2514F8AB224B861";
const char* crypt_s=   "";
const char* pkcs_s=    "";
*/

//RSA1024 example
const char* modulus_s= "D8E1407576D91003264456CF1936E49AD70FA75CF3A8C7C0EA832BAF83BF69EE675C7BB3C38294EDCEBE62CCF1EAA28C896F4861B86F8FD16A7778A943B7177539A135CCD417EAC82B4F806E13E5490A6A31BB71121548842BFA74E515582317795A0DC61C07F1722CDD27A22453A74185C151B0C0111347B02E9672169EC5A7";
//note: strings commented out as it does not fit in memory...
const char* crypt_s= ""; // "42D37E36C30F12959E7FEBA2CA1C887DFE1F1000211D879ECEB1F47F9DB74802B740D5BABCBF3AFBF502F86B1B6CBB3FD210F456928F8FDEB4B569FC9FE8C45C68A8FEE3DD50D71E1521DA96A6C9206E92AB77010345E09FBC0BFF3849F87137577D5F9F7611A67C3CF8F82E5844D4A9DB759DBC3683082D4FCD072E61951B6B";
const char* pkcs_s= ""; //   "54DBCFFA88C301182644E30E5B91926675FC23D93DB6968A1253968665210A3815B4E07E32A612C9D5691C594DC81045133FCB7F5919337D74AD89B5986026010E8EB583964ECB8101503EDAB36BC34772E6ABE56A69D4FBA29C71A0A94FFA79C7FA3283FF06BEFD81B35A7EE5D447A587D619F3B0BAE849027D975FE0234F72";

/*
//RSA1024 e=65537 example
const char* modulus_s= "C3D32A8AE3FAFACE44A96EEB50D6BBBFBC09582DDE5C7532EEAB054AE22594A0F588D8353E764A3FB8304FE9D55816AE0CB952CDC5996457150152E2F1CB5953FC710CB7F1B6DB0272A5F58296AA9249C7EBE63FDA50E2350984D709995F0D38956C757E3FD568F724EAD462D3C87725A46A23C9CEA574F3F80C939B3DDE5CAF";
const char* crypt_s= "";
const char* pkcs_s= "";
*/

//convert hex string to binary, returns len
uint8_t hex2bin(char* string, uint8_t *bin, uint8_t binlen) { 
  int i=0;   
  uint8_t b=0;
  int nibble = 0;
  int pos=0;
  while(string[i] != '\0' && pos < binlen) {
    char c = string[i];
    if(c>='0' && c<='9') {
      nibble++;
      b = b*0x10 + c - '0'; 
    }else if(c>='A' && c<='F'){
      nibble++;
      b = b*0x10 + c - 'A' + 10; 
    }else if(c>='a' && c<='f'){
      nibble++;
      b = b*0x10 + c - 'a' + 10; 
    }
    i++;
    if(nibble==2) {
      bin[pos++] = b;
      b=0;
      nibble=0;
    }
  }
  //trailing nibble
  if(nibble>0) bin[pos++] = b;
  return pos;
}

void printbin(uint8_t* b, uint8_t len) {
  for (int i=0; i<len; i++) { 
    if (b[i]<0x10) Serial.print("0");
    Serial.print(b[i],HEX); 
  }
  Serial.print(" len=");
  Serial.print(len);
}

void printbinreverse(uint8_t* b, uint8_t len) {
  for (int i=len-1; i>=0; i--) { 
    if (b[i]<0x10) Serial.print("0");
    Serial.print(b[i],HEX); 
  }
  Serial.print(" len=");
  Serial.print(len);
}

void create_msg(uint8_t *msg) {
  for(uint8_t i=0;i<RSA_BYTES;i++) msg[i] = i;
}

void setup() {
  Serial.begin(115200);
  Serial.println("RSA Test v8");
}

int i;
void loop() {
  Serial.print("======= run");
  Serial.println(i++);
  test512();
  delay(1000);
}



void test512(void){
  uint8_t modulus[RSA_BYTES];
  uint8_t msg[RSA_BYTES];


  hex2bin(modulus_s,modulus,RSA_BYTES);
  Serial.print("\nmodulus= ");
  printbin(modulus, RSA_BYTES);

  create_msg(msg);
  Serial.print("\nmessage= ");
  printbin(msg, RSA_BYTES);

  Serial.print("\n\nRAW ENCRYPT: ");
  uint32_t t1 = millis();
  uint8_t rv = rsa_encrypt_raw(modulus, msg);
  uint32_t t2 = millis();
  Serial.print("retval=" + (rv==0 ? "OK" : " ERROR" + String(rv)));

  Serial.print("\nencryted=");
  printbin(msg, RSA_BYTES);

  Serial.print("\nexpected=");
  Serial.print(crypt_s);
  Serial.print("\n");

  Serial.print("nruntime " + String(t2-t1) + "ms " + String( (t2-t1) * (F_CPU / 1000000)) + "kCycles");

  create_msg(msg);
  Serial.print("\n\nPKCS ENCRYPT: ");
  uint8_t rnd_enc[RSA_BYTES];
  //note: rnd_enc should be random, but this is a test to check encrypted value.
  //thats why it's set to 0xAA. It already helps a bit to not initialize rnd_enc at all.
  memset(rnd_enc, 0xAA, RSA_BYTES); 
  rv = rsa_encrypt_pkcs(modulus, msg, 5, rnd_enc);
  Serial.print("retval=" + (rv==0 ? "OK" : " ERROR" + String(rv)));
    
  Serial.print("\npkcs=    ");
  printbin(rnd_enc, RSA_BYTES); 
  
  Serial.print("\nexpected=");
  Serial.print(pkcs_s);
  Serial.print("\n\n");
}

