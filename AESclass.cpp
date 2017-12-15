
#include "CSE539project.h"

AES::AES(byte seed[16]) {

    //define substitution box
    byte sBoxInit[][16] =
    {//      0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
    /*0*/{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    /*1*/{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    /*2*/{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    /*3*/{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    /*4*/{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    /*5*/{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    /*6*/{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    /*7*/{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    /*8*/{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    /*9*/{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    /*a*/{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    /*b*/{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    /*c*/{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    /*d*/{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    /*e*/{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    /*f*/{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };

    //define inverse substitution box
    byte sBoxInvInit[][16] =
    {//      0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
    /*0*/{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    /*1*/{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    /*2*/{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    /*3*/{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    /*4*/{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    /*5*/{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    /*6*/{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    /*7*/{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    /*8*/{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    /*9*/{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    /*a*/{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    /*b*/{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    /*c*/{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    /*d*/{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    /*e*/{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    /*f*/{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
    };

    for (int i=0; i<16; i++) {
        for (int j=0; j<16; j++) {
            sBox[i][j] = sBoxInit[i][j];
            sBoxInv[i][j] = sBoxInvInit[i][j];
        }
    }

    //Store the expanded key
    key = keyExpansion(seed);
}

AES::~AES() {
    //release memory acquired by expanded key
    //SCP: MEM51-CPP
    delete [] key;
    key = nullptr;
}

byte* AES::encrypt(byte in[16]) {
    byte* out = nullptr;

    //encrypt each block
        //only one block considered at this stage.
    out = encryptBlock(in);

    return out;
}

byte* AES::decrypt(byte in[16]) {
    byte* out = nullptr;

    //encrypt each block
        //only one block considered at this stage.
    out = decryptBlock(in);
    return out;
}


byte* AES::encryptBlock(byte in[16]) {
    byte* out = nullptr;
    out = new byte[16];

    word roundKey[4] {0} ;
    byte state[4][4] {{0}};

    //copy 1-D input block to 2-D state block
    for (int j = 0; j<4; j++) {
        for (int i = 0; i<4; i++) {
            state[i][j] = in[(4 * j) + i];
        }
    }

    //prepare round key for round 0
    for (int i = 0; i<4; i++) {
        roundKey[i] = key[i];
    }

    addRoundKey(state, roundKey);

    //AES rounds
    for (int round = 1; round<Nr; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);

        //prepare round key for this round
        for (int i=0; i<4; i++) {
            roundKey[i] = key[(4*round) + i];
        }
        addRoundKey(state, roundKey);
    }

    //final round
        subBytes(state);
        shiftRows(state);
        //prepare round key for final round
        for (int i=0; i<4; i++) {
            roundKey[i] = key[(4*Nr) + i];
        }
        addRoundKey(state, roundKey);

    //copy 2-D state block to 1-D output block
    for (int j = 0; j<4; j++) {
        for (int i = 0; i<4; i++) {
            out[(4 * j) + i] = state[i][j];
        }
    }

    return out;
}


byte* AES::decryptBlock(byte in[16]) {
    byte* out = new byte[16];
    word roundKey[4] {0};
    byte state[4][4] {{0}};

    //copy 1-D input block to 2-D state block
    for (int j = 0; j<4; j++) {
        for (int i = 0; i<4; i++) {
            state[i][j] = in[(4 * j) + i];
        }
    }

    //prepare round key for round 0
    for (int i = 0; i<4; i++) {
        roundKey[i] = key[(4*Nr)+i];
    }

    addRoundKey(state, roundKey);

    //AES rounds
    for (int round = Nr-1; round>0; round--) {
        invShiftRows(state);
        invSubBytes(state);

        //prepare round key for this round
        for (int i=0; i<4; i++) {
            roundKey[i] = key[(4*round) + i];
        }
        addRoundKey(state, roundKey);

        invMixColumns(state);
    }

    //final round
        invShiftRows(state);
        invSubBytes(state);
        //prepare round key for final round
        for (int i=0; i<4; i++) {
            roundKey[i] = key[i];
        }
        addRoundKey(state, roundKey);

    //copy 2-D state block to 1-D output block
    for (int j = 0; j<4; j++) {
        for (int i = 0; i<4; i++) {
            out[(4 * j) + i] = state[i][j];
        }
    }

    return out;
}

word AES::RotWord(word temp)
{
    byte b[4];
    word w {0x00000000};
    word mask {0xff000000};

    //extract the 4 bytes from word using mask and put them in b[] array
    //SCP: DCL50
    for(auto i=0;i<4;i++)
    {
        b[i] = (byte) ((temp & (mask >> (8*i))) >> (24 - (8*i)));
    }

    byte k {0x00};
    k=b[0];
    b[0]=b[1];
    b[1]=b[2];
    b[2]=b[3];
    b[3]=k;

    //concatenate 4 bytes into a word
    for(int i=0;i<4;i++)
    {
        //SCP: EXP50-CPP
        w = w + (((word) b[i]) << (24 - (8*i)));
    }
    return w;
}

word AES::SubWord(word temp)
{
    word w {0x00000000};
    byte b[4];
    word mask {0xff000000};

    //extract the 4 bytes from word using mask and put them in b[] array
    //SCP: DCL50
    for(auto i=0;i<4;i++)
    {
        b[i]=(byte) ((temp & (mask>>(8*i))) >> (24 - (8*i)));
    }

    //get the Substitution variables for each of 4 bytes
    for(int i=0;i<4;i++)
    {
        b[i] = sBox[(int)((b[i]&0xf0)>>4)][(int)((b[i]&0x0f))];
    }

    //concatenate 4 bytes into a word
    for(int i=0;i<4;i++)
    {
        w = w + (((word) b[i]) << (24 - (8*i)));
    }
    return w;
}

word AES::nextRcon(word rc)
{
    word w {0x00000000};
    byte b {0x00};

    //extract most significant byte of rc
    b = (byte) (rc >> 24);

    //multiply b with 2 in GF 2^8
    b = mult_GF(b, 0x02);

    w = ((word) b) << 24;

    return w;
}

word* AES::keyExpansion(byte seed[16]) {

    //SCP: DCL50, DCL51
    auto Nk=4;
    auto Nb=4;

    word* key = nullptr;

    key = new word[4*(Nr+1)];

    byte s {0x00};
    word temp {0x00000000};
    auto i=0;
    while(i<Nk)
    {
        key[i]=0x00000000;
        for(auto k=0;k<4;k++)
        {
            s = seed[(4*i) + k];
            //SCP: EXP50-CPP
            key[i] = key[i] + (((word) s) << (8*(3-k)));
        }
        //SCP: EXP50-CPP
        i=i+1;
    }
    i=Nk;
    word Rcon {0x01000000};
    while(i<(Nb*(Nr+1)))
    {
        temp=key[i-1];
        if((i%Nk) == 0)
        {
            temp = (SubWord(RotWord(temp))) ^ Rcon;

            //update Rcon for the next round key
            Rcon = nextRcon(Rcon);
        }
        else if(Nk>6 && (i%Nk)== 4)
        {
            temp=SubWord(temp);
        }

        key[i]=key[i-Nk]^temp;
        //SCP: EXP50-CPP
        i=i+1;
    }

    return key;
}

void AES::addRoundKey(byte state[4][4], word roundKey[4]) {
    word mask {0xff000000};

    for (int j=0; j<4; j++) {
        word temp {roundKey[j]};
        for (int i=0; i<4; i++) {
            state[i][j] ^= (byte) ((temp & (mask >> (8*i))) >> (24-(8*i)));
        }
    }

    return;
}

void AES::subBytes(byte state[4][4]) {
    byte temp {0x00};
    byte x_mask {0xf0};
    byte y_mask {0x0f};

    for (int i=0; i<4; i++) {
        for (int j=0; j<4; j++) {
            temp = state[i][j];
            int x = (int) ((temp & x_mask) >> 4);
            int y = (int) (temp & y_mask);
            state[i][j] = sBox[x][y];
        }
    }

    return;
}

void AES::mixColumns(byte state[4][4]) {
    byte fixed_poly[4] {0x02, 0x01, 0x01, 0x03};
    byte temp[4] {0x00};

    //j: iterate through columns of state
    //i: iterate through rows of state
    for (int j = 0; j<4 ; j++) {
        for (int i=0; i<4; i++) {
            temp[i] = 0x00;
            for (int k=0; k<4; k++) {
                int m = ((i-k) % 4);
                m = (m < 0) ? (m + 4) : m;
                temp[i] ^= mult_GF(state[k][j], fixed_poly[m]);
            }
        }

        //update state at column j
        for (int i=0; i<4; i++) {
            state[i][j] = temp[i];
        }
    }

    return;
}

byte AES::mult_GF(byte x, byte y) {
    word irr_poly {0x0000011b};
    word res {0x00000000};
    word x_word {(word) x};
    word y_word {(word) y};

    //divide and conquer method to compute x*y
    while(y_word) {
        if (y_word % 2) {
            res = res ^ x_word;
        }
        x_word <<= 1;
        x_word = (x_word & 0x00000100) ? (x_word ^ irr_poly) : x_word;
        y_word >>= 1;
    }

    return ((byte) res);
}

void AES::shiftRows(byte state[4][4]) {
    byte temp {0x00};
    for (int i=1; i<4; i++) {
        for (int j=0; j<i; j++) {
            temp = state[i][0];
            state[i][0] = state[i][1];
            state[i][1] = state[i][2];
            state[i][2] = state[i][3];
            state[i][3] = temp;
        }
    }

    return;
}

void AES::invSubBytes(byte state[4][4]) {
    byte temp {0x00};
    byte x_mask {0xf0};
    byte y_mask {0x0f};

    for (int i=0; i<4; i++) {
        for (int j=0; j<4; j++) {
            temp = state[i][j];
            int x = (int) ((temp & x_mask) >> 4);
            int y = (int) (temp & y_mask);
            state[i][j] = sBoxInv[x][y];
        }
    }

    return;
}

void AES::invMixColumns(byte state[4][4]) {
    byte fixed_poly[4] {0x0e, 0x09, 0x0d, 0x0b};
    byte temp[4] {0x00};

    //j: iterate through columns of state
    //i: iterate through rows of state
    for (int j = 0; j<4 ; j++) {
        for (int i=0; i<4; i++) {
            temp[i] = 0x00;
            for (int k=0; k<4; k++) {
                int m = ((i-k) % 4);
                m = (m < 0) ? (m + 4) : m;
                temp[i] ^= mult_GF(state[k][j], fixed_poly[m]);
            }
        }

        //update state at column j
        for (int i=0; i<4; i++) {
            state[i][j] = temp[i];
        }
    }

}

void AES::invShiftRows(byte state[4][4]) {
    byte temp {0x00};
    for (int i=1; i<4; i++) {
        for (int j=0; j<i; j++) {
            temp = state[i][3];
            state[i][3] = state[i][2];
            state[i][2] = state[i][1];
            state[i][1] = state[i][0];
            state[i][0] = temp;
        }
    }

    return;
}
