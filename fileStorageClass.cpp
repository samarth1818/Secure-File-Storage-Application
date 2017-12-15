
#include "CSE539project.h"

void fileStorage::showGUI() {
    cout << "This is a simulation for secure file encryption/retrieval as a part of F'17 CSE539 project." << endl << endl;

    while (1) {
        cout << endl << "Select a number to continue..." << endl;
        cout << "<1>\tUpdate key"<<endl;
        cout << "<2>\tEncrypt a file"<<endl;
        cout << "<3>\tDecrypt a file"<<endl;
        cout << "<4>\tTest project using console inputs"<<endl;
        cout << "<0>\tEXIT" << endl << endl;
        cout << "::I want to... ";

        string menuSel {""};
        cin >> menuSel;

        if (!menuSel.compare("0")) {
            return;
        } else if (!menuSel.compare("1")) { //Update key
            int i;
            i = updateKey();

            if (i == 1) {
                cout << "Key successfully updated!" << endl << endl;
            } else if (i == 0) {
                cout << "Unauthorized key update attempted!" << endl << endl;
            } else {}

        } else if (!menuSel.compare("2")) { //Encrypt a file

            if (encryptFile()) {
                cout << "File successfully encrypted!" << endl << endl;
            } else {
                cout <<"File error!"<< endl << endl;
            }

        } else if (!menuSel.compare("3")) { //Decrypt a file

            if (decryptFile()) {
                cout << "File successfully decrypted!" << endl << endl;
            } else {
                cout <<"File error!"<< endl << endl;
            }

        } else if (!menuSel.compare("4")) { //Test project using console inputs

            testConsoleInputs();

        } else {
            cout << "You don't have that option!" << endl << endl;
        }

    }

    return;
}

int fileStorage::updateKey() {
    cout << endl << "If the secure key is updated, any file encrypted with the old key will never be recovered" << endl;
    cout << endl << "Select an option to continue..."<<endl;

    cout << "<1>\tUpdateKey: Simulate authorized user"<<endl;
    cout << "<2>\tUpdateKey: Simulate unauthorized user"<<endl;
    cout << "<0>\tCancel"<<endl<<endl;
    cout << "I want to... ";
    cin.ignore();

    string UKsel;
    cin >> UKsel;

    if (!UKsel.compare("0")) {
        return -1;  //-1 represents cancel operation
    } else if (!UKsel.compare("1")) {
        //authorized key update
        //providing read old key for update
        byte* oldKey;
        byte wrapKey[16] =
        {
        0x32,	0x43,	0xf6,	0xa8,	0x88,	0x5a,	0x30,	0x8d,	0x31,	0x31,	0x98,	0xa2,	0xe0,	0x37,	0x07,	0x34
        };

        RandGen rg(wrapKey);

        oldKey = rg.getKey();

        if (rg.updateKey(oldKey)) {
            delete [] oldKey;
            oldKey = nullptr;
            return 1;
        } else {
            delete [] oldKey;
            oldKey = nullptr;
            return 0;
        }

    } else if (!UKsel.compare("2")) {
        byte* oldKey;
        byte wrapKey[16] =
        {
        0x32,	0x43,	0xf6,	0xa8,	0x88,	0x5a,	0x30,	0x8d,	0x31,	0x31,	0x98,	0xa2,	0xe0,	0x37,	0x07,	0x34
        };

        RandGen rg(wrapKey);

        oldKey = rg.getKey();

        //change first byte of old key;
        oldKey[0] ^= 0xff;

        if (rg.updateKey(oldKey)) {
            cout << "Key successfully updated!" << endl;
            delete [] oldKey;
            oldKey = nullptr;
            return 1;
        } else {
            cout << "Unauthorized key update attempted!" << endl;
            delete [] oldKey;
            oldKey = nullptr;
            return 0;
        }

    } else {
        cout << "You don't have that option!";
        return -1; //-1 represents cancel operation
    }

}

int fileStorage::encryptFile() {
    //get file path
    cout << endl;
    string fPath;
    cout << "Enter path of file to encrypt:" << endl;
    cin.ignore();
    getline(cin, fPath);
    ifstream iFile;
    string fileContents;

    //open and check if file is valid
    iFile.open(fPath, ios::in);
    if (!iFile.good()) {
        return 0;
    }

    //read file contents
    //SCP: FIO50-CPP
    iFile.seekg(0, ios::end);
    fileContents.reserve(iFile.tellg());
    iFile.seekg(0, ios::beg);
    fileContents.assign((istreambuf_iterator<char>(iFile)), istreambuf_iterator<char>());
    //SCP:FIO51-CPP
    iFile.close();

    //encrypt the file
    //first, create a wrapper key that must agree with the wrapper key used to store secure key
    byte wrapKey[16] =
        {
        0x32,	0x43,	0xf6,	0xa8,	0x88,	0x5a,	0x30,	0x8d,	0x31,	0x31,	0x98,	0xa2,	0xe0,	0x37,	0x07,	0x34
        };

    //next, invoke CBC object with the given wrapper key.
    //next, This object will retrieve stored secure key for all encryptions. wrapKey must be correct.
    CBC cbc(false, wrapKey);

    //next, encrypt
    string encContents;
    encContents = cbc.encrypt(fileContents);

    //store cipher into the same file and maintain a file log
    ofstream oFile;
    oFile.open(fPath, ios::out | ios::trunc);
    oFile.seekp(0, ios::beg);

    oFile << encContents;
    //SCP: FIO51CPP
    oFile.close();

    return 1;
}


int fileStorage::decryptFile() {
    //get file path
    cout << endl;
    cout << "Enter path of file to decrypt:"<<endl;
    string fPath;
    cin.ignore();
    getline(cin, fPath);
    ifstream iFile;
    string fileContents;

    //open and check if file is valid
    iFile.open(fPath, ios::in);
    if (!iFile.good()) {
        return 0;
    }

    //read file contents
    //SCP: FIO50-CPP
    iFile.seekg(0, ios::end);
    fileContents.reserve(iFile.tellg());
    iFile.seekg(0, ios::beg);
    fileContents.assign((istreambuf_iterator<char>(iFile)), istreambuf_iterator<char>());
    //SCP: FIO51-CPP
    iFile.close();

    //encrypt the file
    //first, create a wrapper key that must agree with the wrapper key used to store secure key
    byte wrapKey[16] =
        {
        0x32,	0x43,	0xf6,	0xa8,	0x88,	0x5a,	0x30,	0x8d,	0x31,	0x31,	0x98,	0xa2,	0xe0,	0x37,	0x07,	0x34
        };

    //next, invoke CBC object with the given wrapper key.
    //next, This object will retrieve stored secure key for all encryptions. wrapKey must be correct.
    CBC cbc(false, wrapKey);

    //next, decrypt
    string decContents;
    decContents = cbc.decrypt(fileContents);

    //store cipher into the same file and maintain a file log
    ofstream oFile;
    oFile.open(fPath, ios::out | ios::trunc);
    //SCP: FIO50-CPP
    oFile.seekp(0, ios::beg);

    oFile << decContents;

    oFile.close();

    return 1;
}

void fileStorage::testConsoleInputs() {
    string exit_str {"EXIT"};

    byte wrapKey[16] =
        {
        0x32,	0x43,	0xf6,	0xa8,	0x88,	0x5a,	0x30,	0x8d,	0x31,	0x31,	0x98,	0xa2,	0xe0,	0x37,	0x07,	0x34
        };

    CBC cbc(false, wrapKey);

    cin.ignore();

    while (1) {


        cout << "Enter plain text, or type <EXIT> to return:" << endl;

        string inText;
        string outText;
        string recText;

        getline(cin, inText);

        if (!inText.compare(exit_str)) {
            break;
        }

        outText = cbc.encrypt(inText);

        cout << endl << "Encrypted Text:" << endl;
        cout << outText << endl;

        recText = cbc.decrypt(outText);

        cout << endl << "Decrypted Text:" << endl;
        cout << recText << endl << endl << endl;

    }

    return;

}
