
#include "CSE539project.h"
#include <windows.h>
#include <Wincrypt.h>

RandGen::RandGen(byte* wrapper) {
    //invoking function must know the correct wrapper key to retrive old key
    wrapKey = new byte[16];
    for (int i=0; i<16; i++) {
        wrapKey[i] = wrapper[i];
    }
}

RandGen::~RandGen() {
    //release memory acquired by wrapKey
    //SCP: MEM51-CPP
    delete [] wrapKey;
    wrapKey = nullptr;
}

int RandGen::updateKey(byte* oldKey) {
    //verify the old key supplied by the calling function with the stored key
    //if the stored key matches, update the key with a new random key
    byte* storedKey = nullptr;
    storedKey = getKey();

    for (int i = 0; i < 16; i++) {
        if (storedKey[i] != oldKey[i]) {
            //unauthorized user!
            return 0;
        }
    }

    //delete memory allocated to stored key
    //SCP: MEM51-CPP
    delete [] storedKey;
    storedKey = nullptr;

    //get a new key
    byte* newKey = nullptr;
    newKey = KeyGen();

    //put new key in a string object
    string newKeyStr {""};
    for (int i =0; i<16; i++) {
        newKeyStr.push_back((char) newKey[i]);
    }

    //encrypt the new key with the provided wrapper key
    //invoke CBC object with wrapper key
    CBC cbc(wrapKey, wrapKey);

    string eKey;
    if(!newKeyStr.empty()){
        eKey = cbc.encrypt(newKeyStr);
    }

    //open file to write the encrypted secure key
    ofstream ofKey;
    ofKey.open("SecureKey.bin", ios::out | ios::trunc);

    ofKey.seekp(0, ios::beg);

    ofKey << eKey;
    //SCP: FIO51-CPP
    ofKey.close();

    //release memory allocated to newKey
    //SCP: MEM51-CPP
    delete [] newKey;
    newKey = nullptr;

    //SCP: MSC52-CPP
    return 1;
}


byte* RandGen::getKey() {
    //read encrypted secure key stored at SecureKey.bin, decrypt it using the wrapper key
    //note: wrapper key must be correct!

    //open file to read secure key
    ifstream ifKey;
    string readKey;
    ifKey.open("SecureKey.bin", ios::in);
    if(!ifKey.good()) {
        cout << endl << "secure key not found!" << endl;
        return nullptr;
    }
    //SCP: FIO50-CPP
    ifKey.seekg(0, ios::end);
    readKey.reserve(ifKey.tellg());
    ifKey.seekg(0, ios::beg);
    readKey.assign((istreambuf_iterator<char>(ifKey)), istreambuf_iterator<char>());
    //SCP: FIO51-CPP
    ifKey.close();

    //invoke CBC object with wrapper key
    CBC cbc(wrapKey, wrapKey);

    //decrypt the secure key
    string dKey;
    if(!readKey.empty()){
        dKey = cbc.decrypt(readKey);
    }
    //allocate memory for the key, and return that key
    byte* k = new byte[16];

    for (int i = 0; i<16; i++) {
        k[i] = dKey[i];
    }

    return k;
}

byte* RandGen::KeyGen(){
    byte* k=nullptr;
    k=CryptoGen();
    return k;
}

byte* RandGen::IVGen(){
    byte* k=nullptr;
    k=CryptoGen();
    return k;
}


byte* RandGen::CryptoGen(){
    BYTE* key = new BYTE[16];
    HCRYPTPROV hCryptProv;
    //SCP: MSC50-CPP, MSC51-CPP
    CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    CryptGenRandom(hCryptProv, 16, key);
    CryptReleaseContext(hCryptProv, 0);
    return ((byte*) key);
}

