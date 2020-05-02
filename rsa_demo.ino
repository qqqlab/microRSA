/*
RSA: 2408 bytes flash 
needs 5 * (64+1 + 2) =  335 bytes RAM (//alloc 1 byte extra to prevent reallocs when doing operations + 1 byte len + 1 byte capacity)
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
*/

#include "qqq_rsa.h"

const char* modulus_s= "A2C88620FB3179A48B5F126D70D812922A2E151675915E0B752F2DE173C1A891CA2D6964CB4419017C63780C9E39394A310ECB529B01F3AEF76F0A142ED5A60F";
const char* msg_s=     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"; 
const char* crypt_s=   "299DA147204AAAB26F8C26FB9F11B7F92365FE083D10A87EBAB49DBC787D01A4178FB5D8C07D6732CA3258E739222D7AD1473AD7B6FC14F929A6737D1856D29F"; 
const char* pkcs_s=    "0B91BCE41408BC687F0C45495410ECFBA0592FB61AF7DBAD26FDF4F806912286740FB64161266F3697473F8BC8E4D9FAC1F37D7F4251956ECB4CA909B492583B";

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

void setup() {
  Serial.begin(115200);
  Serial.println("RSA Test v7");
}

int i;
void loop() {
  Serial.print("======= run");
  Serial.println(i++);
  test512();
  delay(1000);
}



void test512(void){
  uint8_t modulus[64];
  uint8_t msg[64];


  hex2bin(modulus_s,modulus,64);
  Serial.print("\nmodulus= ");
  printbin(modulus,64);

  hex2bin(msg_s,msg,64);
  Serial.print("\nmessage= ");
  printbin(msg,64);

  Serial.print("\n\nRAW ENCRYPT: ");
  uint32_t t1 = millis();
  uint8_t rv = rsa_encrypt_raw(modulus, msg);
  uint32_t t2 = millis();
  Serial.print("retval=" + (rv==0 ? "OK" : " ERROR" + String(rv)));

  Serial.print("\nencryted=");
  printbin(msg,64);

  Serial.print("\nexpected=");
  Serial.print(crypt_s);
  Serial.print("\n");

  Serial.print("nruntime " + String(t2-t1) + "ms " + String( (t2-t1) * F_CPU / 1000000) + "kCycles");

  hex2bin(msg_s,msg,64);
  Serial.print("\n\nPKCS ENCRYPT: ");
  uint8_t rnd_enc[64];
  //note: rnd_enc should be random, but this is a test to check encrypted value.
  //thats why it's set to 0xAA. It already helps a bit to not initialize rnd_enc at all.
  memset(rnd_enc,0xAA,64); 
  rv = rsa_encrypt_pkcs(modulus, msg, 5, rnd_enc);
  Serial.print("retval=" + (rv==0 ? "OK" : " ERROR" + String(rv)));
    
  Serial.print("\npkcs=    ");
  printbin(rnd_enc,64); 
  
  Serial.print("\nexpected=");
  Serial.print(pkcs_s);
  Serial.print("\n\n");
}
