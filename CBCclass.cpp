
#include "CSE539project.h"

CBC::CBC(bool newSession, byte* wrapKey) {
    //newSession = false : continue old encryption session with old key
    //newSession =  true : start new encryption session with new key
    //SCP: OOP53-CPP
    rg = new RandGen(wrapKey);

    key = rg->getKey();
}

CBC::CBC(byte dKey[], byte* wrapKey) {
    //the 128 bit key is supplied from the invoking function
    //RandGen is not used here.

    key = new byte[16];
    for (int i=0; i<16; i++) {
        key[i] = dKey[i];
    }

    rg = new RandGen(wrapKey);

}

CBC::~CBC() {
    //release memory acquired by the key
    //SCP: MEM51-CPP, MEM53-CPP
    delete [] key;
    key = nullptr;
}

string CBC::encrypt(string inText) {

    //SCP: MEM52-CPP
    if (key == nullptr) {
        return "error!";
    }

    byte* pText = nullptr; //padded plain text
    byte* IV = nullptr;
    int pLen {0}; //Length after padding

    //padding the plain text with 10000...
    pText = padPlainText(inText, pLen);

    //number of bytes of cipher text
    int cLen = pLen + 16;

    byte cText[cLen] {0};

    //generate IV
    IV = requestIV();

    //copy IV to C0
    for(int i = 0; i<16; i++) {
        cText[i] = IV[i];
    }

    //generate C1, C2, ... in CBC  mode
    AES aes(key);

    for(int i=1; i<(cLen / 16); i++) {
        byte inBlock[16] {0};
        byte* outBlock = nullptr;

        //input block for AES used as PRP
        for(int j=0; j < 16; j++) {
            //copy (i-1)th plain text block
            inBlock[j] = pText[((i-1)*16) + j];

            //XOR with (i-1)th cipher text block
            inBlock[j] ^= cText[((i-1)*16) + j];
        }

        //Encrypt with AES, used as a PRP
        outBlock = aes.encrypt(inBlock);

        //Copy output of AES-PRP to i-th cipher text block
        for(int j=0; j<16; j++) {
            //copy i-th plain text block
            cText[(i*16) + j] = outBlock[j];
        }

        //release memory
        //SCP: MEM51-CPP
        delete [] outBlock;
        outBlock = nullptr;
    }

    //generate output string
    string outText {""};
    for (int i=0; i < cLen; i++) {
        outText.push_back((char) cText[i]);
    }

    //free dynamically allocated memory
    //SCP: MEM51-CPP
    delete [] pText;
    delete [] IV;
    pText = nullptr;
    IV = nullptr;
    //SCP: MSC52-CPP
    return outText;
}




byte* CBC::padPlainText(string inText, int& pLen) {
    //Convert input string to plain text bytes.
    //Padding:
        //Number of plain text bytes must be a multiple of AES block size = 16 bytes.
        //If length of input string is not a multiple of 16, pad it with (binary) 100000...
    //return the padded plain text and its length (pLen)

    int inLen = inText.length();    //input length in bytes

    //compute length of padded plain text
    pLen = (inLen % 16) ? (inLen - (inLen % 16) + 16) : (inLen + 16);
    //SCP: EXP53-CPP
    byte* pText = nullptr;
    pText = new byte[pLen];

    //copy characters of inText to pText
    for(int i = 0; i < inLen; i++) {
        pText[i] = (byte) inText[i];
    }

    //Assign padding byte 0x80
    pText[inLen] = 0x80;

    //Assign 0x00 to remaining bytes
    if ((inLen + 1) < pLen) {
        for (int i=inLen+1; i < pLen; i++) {
            pText[i] = 0x00;
        }
    }

    return pText;
}

byte* CBC::requestIV() {
    byte* ret;

    ret = rg->IVGen();

    return ret;
}



string CBC::decrypt(string inText) {
    //SCP: MEM52-CPP
    if (key == nullptr) {
        return "";
    }

    //Length of  cipher text
    int cLen = inText.length();

    //Copy cipher text as string into a byte array
    byte cText[cLen] {0}; //cipher text

    for (int i=0; i<cLen; i++) {
        cText[i] = (byte) inText[i];
    }

    //generate m0, m1, m2, ... in CBC  mode
    AES aes(key);
    byte pText[cLen - 16] {0};

    for(int i=1; i<(cLen / 16); i++) {
        byte inBlock[16] {0};
        byte* outBlock = nullptr;

        //input block for AES used as PRP
        for(int j=0; j<16; j++) {
            //copy i-th cipher text block
            inBlock[j] = cText[(i*16) + j];
        }

        //Decrypt with AES, used as a PRP
        outBlock = aes.decrypt(inBlock);

        //XOR output of inverse-AES-PRP with (i-1)-th cipher text block.
        //Store the result in (i-1)th plain text block
        for(int j=0; j<16; j++) {
            pText[((i-1)*16) + j] = outBlock[j] ^ cText[((i-1)*16) + j];
        }

        //release memory
        //SCP: MEM51-CPP
        delete [] outBlock;
        outBlock = nullptr;
    }

    //detect index from where padding starts
    int pEnd {0};
    for(pEnd=(cLen-17); (pEnd >= 0) && (pText[pEnd] == 0x00); pEnd--) {}

    //generate output string
    string outText {""};
    for (int i=0; i < pEnd; i++) {
        outText.push_back((char) pText[i]);
    }
    //SCP: MSC52-CPP
    return outText;
}
