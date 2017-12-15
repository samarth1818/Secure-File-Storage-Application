#include <iostream>
#include <cstdint>
#include <cstring>
#include <string>
#include <fstream>
#include <streambuf>

//SCP: DCL51
#define Nr 10

typedef uint8_t byte;
typedef uint32_t word;

using namespace std;



class AES {
    public:
        //SCP: MEM53-CPP
        AES(byte seed[16]);  //constructor
        //SCP: MEM51-CPP, MEM53-CPP
        ~AES(); //destructor
        byte* encrypt(byte in[16]);
        byte* decrypt(byte in[16]);

    private:
        word* key;  //store the expanded key through the lifetime of an AES object
        byte sBox[16][16] {{0}};
        byte sBoxInv[16][16] {{0}};
        //SCP: DCL50-separate functions for each computation
        byte* encryptBlock(byte in[16]);
        byte* decryptBlock(byte in[16]);

        word* keyExpansion(byte seed[16]);
        word SubWord(word temp);
        word RotWord(word temp);
        word nextRcon(word rc);

        void addRoundKey(byte state[4][4], word roundKey[4]);

        void subBytes(byte state[4][4]);
        void shiftRows(byte state[4][4]);
        void mixColumns(byte state[4][4]);

        void invSubBytes(byte state[4][4]);
        void invShiftRows(byte state[4][4]);
        void invMixColumns(byte state[4][4]);

        byte mult_GF(byte x, byte y);
};

class RandGen{
    public:
        //SCP: MEM51-CPP, MEM53-CPP
        RandGen(byte* wrapper);  //Constructor
        ~RandGen(); //Destructor

        byte* IVGen();
        byte* getKey();
        int updateKey(byte* oldKey);

    private:
        byte* KeyGen();
        byte* CryptoGen();

        byte* wrapKey;
};

class CBC{
    public:
        //SCP: MEM51-CPP, MEM53-CPP
        CBC(bool newSession, byte* wrapKey);   //constructor 1. Key taken using RandGen object
        CBC(byte dKey[], byte* wrapKey);    //supply key from the outside
        ~CBC(); //destructor

        string encrypt(string inText);
        string decrypt(string inText);

    private:
        //SCP: OOP53-CPP
        RandGen* rg = nullptr;
        byte* key;  //store the key throughout the lifetime of a CBC object


        //helper functions
        byte* padPlainText(string inText, int& pLen);
        byte* requestIV();
};





class fileStorage {
    public:
        void showGUI();

    private:
        int updateKey();
        int encryptFile();
        int decryptFile();
        void testConsoleInputs();
};
