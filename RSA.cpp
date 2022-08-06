#include "RSA.h"

RSA::RSA(){
    /// initialization
    SetSeed((NTL::conv<NTL::ZZ>((long)time(nullptr))));
    /// p is 996 bits long
    /// q is 997 bits long
    conv<ZZ>(p,"592726698946096999543273374356257240998789301664802624765569055561098719474060171306641597488953716650914356553166749890714859755982453244221134973504468255667746068841303079065407442921819742501341890800715030783798672457134757252402042702677890340801551079344805261806304071101993922516882436235993");
    conv<ZZ>(q,"711585890477090024287186823446180884825547207382397863922740117252737273865554697201077086195706300376137171070378792875360347709517253610197012882970607370146975828202428370045368585402186875451969155354458469136697187640387577072457353795795723419911986823594783620348200193662137879179419032163399");

    computePublicKey();
    computePrivateKey();
}

RSA::RSA(const std::pair<ZZ, ZZ>& public_key, const std::pair<ZZ,ZZ>& private_key) {
    n = public_key.first;
    e = public_key.second;
    d = private_key.second;
}

void RSA::computePrivateKey(){
    InvMod(d,(ZZ) e,phin);
}

void RSA::computePublicKey(){
    n = p * q ;
    phin = (p-1)*(q-1);

    do{
        e = RandomBnd(phin);
    }while(GCD(e,phin)!=1);
}

std::pair<ZZ,ZZ> RSA::getPublicKey(){return {n,e};}

std::pair<ZZ,ZZ> RSA::getPrivateKey(){return {n,d};}

void RSA::printPublicKey() {
    std::cout<<"public key is (n, e): "<<printHexadecimal(n)<<"\n"<<printHexadecimal(e)<<"\n";
}

void RSA::printPrivateKey() {
    std::cout<<"public key is (n, d): "<<printHexadecimal(n)<<"\n"<<printHexadecimal(d)<<"\n";
}

string RSA::encrypt(const std::string& s){
    ZZ value = messageToZZ(s);
    ZZ cryptedMessage;

    PowerMod(cryptedMessage,value,e,n);

    return zzToMessage(cryptedMessage);
}

string RSA::decrypt(const std::string& s){
    ZZ value = messageToZZ(s);
    ZZ decryptedMessage;

    PowerMod(decryptedMessage,value,d,n);

    return zzToMessage(decryptedMessage);
}

string RSA::encrypt(const std::string& s, const std::pair<ZZ, ZZ>& public_key) {
    ZZ value = messageToZZ(s);
    ZZ cryptedMessage;

    PowerMod(cryptedMessage,value,public_key.second,public_key.first);

    return zzToMessage(cryptedMessage);
}

string RSA::decrypt(const std::string& s, const std::pair<ZZ, ZZ> &private_key) {
    ZZ value = messageToZZ(s);
    ZZ decryptedMessage;

    PowerMod(decryptedMessage,value,private_key.second,private_key.first);

    return zzToMessage(decryptedMessage);
}

char RSA::valuetochar(long v)
{
    char c;
    switch (v)
    {
        case 0: c='A';break;case 1: c='B';break;case 2: c='C';break;case 3: c='D';break;
        case 4: c='E';break;case 5: c='F';break;case 6: c='G';break;case 7: c='H';break;
        case 8: c='I';break;case 9: c='J';break;case 10: c='K';break;case 11: c='L';break;
        case 12: c='M';break;case 13: c='N';break;case 14: c='O';break;case 15: c='P';break;
        case 16: c='Q';break;case 17: c='R';break;case 18: c='S';break;case 19: c='T';break;
        case 20: c='U';break;case 21: c='V';break;case 22: c='W';break;case 23: c='X';break;
        case 24: c='Y';break;case 25: c='Z';break;case 26: c='a';break;case 27: c='b';break;
        case 28: c='c';break;case 29: c='d';break;case 30: c='e';break;case 31: c='f';break;
        case 32: c='g';break;case 33: c='h';break;case 34: c='i';break;case 35: c='j';break;
        case 36: c='k';break;case 37: c='l';break;case 38: c='m';break;case 39: c='n';break;
        case 40: c='o';break;case 41: c='p';break;case 42: c='q';break;case 43: c='r';break;
        case 44: c='s';break;case 45: c='t';break;case 46: c='u';break;case 47: c='v';break;
        case 48: c='w';break;case 49: c='x';break;case 50: c='y';break;case 51: c='z';break;
        case 52: c='0';break;case 53: c='1';break;case 54: c='2';break;case 55: c='3';break;
        case 56: c='4';break;case 57: c='5';break;case 58: c='6';break;case 59: c='7';break;
        case 60: c='8';break;case 61: c='9';break;case 62: c='+';break;case 63: c='/';break;
        default: c='?';break;
    }

    return c;
}

long RSA::chartovalue(char c)
{
    char v;
    switch (c)
    {
        case 'A': v = 0;break;case 'B': v = 1;break;case 'C': v = 2;break;case 'D': v = 3;break;
        case 'E': v = 4;break;case 'F': v = 5;break;case 'G': v = 6;break;case 'H': v = 7;break;
        case 'I': v = 8;break;case 'J': v = 9;break;case 'K': v = 10;break;case 'L': v = 11;break;
        case 'M': v = 12;break;case 'N': v = 13;break;case 'O': v = 14;break;case 'P': v = 15;break;
        case 'Q': v = 16;break;case 'R': v = 17;break;case 'S': v = 18;break;case 'T': v = 19;break;
        case 'U': v = 20;break;case 'V': v = 21;break;case 'W': v = 22;break;case 'X': v = 23;break;
        case 'Y': v = 24;break;case 'Z': v = 25;break;case 'a': v = 26;break;case 'b': v = 27;break;
        case 'c': v = 28;break;case 'd': v = 29;break;case 'e': v = 30;break;case 'f': v = 31;break;
        case 'g': v = 32;break;case 'h': v = 33;break;case 'i': v = 34;break;case 'j': v = 35;break;
        case 'k': v = 36;break;case 'l': v = 37;break;case 'm': v = 38;break;case 'n': v = 39;break;
        case 'o': v = 40;break;case 'p': v = 41;break;case 'q': v = 42;break;case 'r': v = 43;break;
        case 's': v = 44;break;case 't': v = 45;break;case 'u': v = 46;break;case 'v': v = 47;break;
        case 'w': v = 48;break;case 'x': v = 49;break;case 'y': v = 50;break;case 'z': v = 51;break;
        case '0': v = 52;break;case '1': v = 53;break;case '2': v = 54;break;case '3': v = 55;break;
        case '4': v = 56;break;case '5': v = 57;break;case '6': v = 58;break;case '7': v = 59;break;
        case '8': v = 60;break;case '9': v = 61;break;case '+': v = 62;break;case '/': v = 63;break;
        default: v='?';break;
    }

    return v;
}

ZZ RSA::messageToZZ(const std::string& s){
    ZZ result;

    for(auto ch : s){
        result *= 64;
        result += chartovalue(ch);
    }

    return result;
}

std::string RSA::zzToMessage(ZZ value){
    string result,temp,ch;

    do{
        ch = valuetochar(value % 64);
        temp.append(ch);
        value/=64;
    }while(value > 63);

    if(value!=0){
        ch = valuetochar(value % 64);
        temp.append(ch);
    }

    for(int i = (int)temp.size() - 1 ; i >=0 ; i--) {
        result += (temp[i]);
    }

    return result;
}

std::string RSA::printHexadecimal(ZZ value){
    string  result,temp,ch;
    int     inttemp;

    do{
        inttemp = value % 16;

        if(inttemp<10){
            ch = valuetochar(inttemp+52);
        }else ch = valuetochar(inttemp-10);

        temp.append(ch);
        value/=16;
    }while(value > 15);

    if(value!=0){
        inttemp = value % 16;

        if(inttemp<10){
            ch = valuetochar(inttemp+52);
        }else ch = valuetochar(inttemp-10);

        temp.append(ch);
    }

    for(int i = (int)temp.size() - 1 ; i >=0 ; i--) {
        result += (temp[i]);
    }

    return result;
}
