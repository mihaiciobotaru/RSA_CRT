#include "RSA_CRT.h"

RSA_CRT::RSA_CRT(){
    SetSeed((NTL::conv<NTL::ZZ>((long)time(nullptr))));
    /// p is 2^1279 - 1
    /// q is 2^2203 - 1
    /// initialization
    //conv<ZZ>(p,"10407932194664399081925240327364085538615262247266704805319112350403608059673360298012239441732324184842421613954281007791383566248323464908139906605677320762924129509389220345773183349661583550472959420547689811211693677147548478866962501384438260291732348885311160828538416585028255604666224831890918801847068222203140521026698435488732958028878050869736186900714720710555703168729087");
    // conv<ZZ>(q,"1475979915214180235084898622737381736312066145333169775147771216478570297878078949377407337049389289382748507531496480477281264838760259191814463365330269540496961201113430156902396093989090226259326935025281409614983499388222831448598601834318536230923772641390209490231836446899608210795482963763094236630945410832793769905399982457186322944729636418890623372171723742105636440368218459649632948538696905872650486914434637457507280441823676813517852099348660847172579408422316678097670224011990280170474894487426924742108823536808485072502240519452587542875349976558572670229633962575212637477897785501552646522609988869914013540483809865681250419497686697771007");

    /// p is 512 bits
    /// q is 512 bits
    /// initialization
    conv<ZZ>(p,"13144131834269512219260941993714669605006625743172006030529504645527800951523697620149903055663251854220067020503783524785523675819158836547734770656069477");
    conv<ZZ>(q,"12288506286091804108262645407658709962803358186316309871205769703371233115856772658236824631092740403057127271928820363983819544292950195585905303695015971");

    computePublicKey();
    computePrivateKey();
}

RSA_CRT::RSA_CRT(const std::pair<ZZ, ZZ>& public_key, const std::pair<ZZ,ZZ>& private_key) {
    n = public_key.first;
    e = public_key.second;
    d = private_key.second;
}

void RSA_CRT::computePrivateKey(){
    InvMod(d,(ZZ) e,phin);
    dp = d % (p-1);
    dq = d % (q-1);
    InvMod(qinv,q,p);
}

void RSA_CRT::computePublicKey(){
    n = p * q ;
    phin = (p-1)*(q-1);

    do{
        e = RandomBnd(phin);
    }while(GCD(e,phin)!=1);
}

std::pair<ZZ,ZZ> RSA_CRT::getPublicKey(){return {n,e};}

std::tuple<ZZ,ZZ,ZZ,ZZ,ZZ> RSA_CRT::getPrivateKey(){return {dp,dq,qinv,p,q};}

void RSA_CRT::printPublicKey() {
    std::cout<<"public key is (n, e): "<<printHexadecimal(n)<<"\n"<<printHexadecimal(e)<<"\n";
}

void RSA_CRT::printPrivateKey() {
    std::cout<<"private key is (dP, dQ, qInv, p, q): "<<printHexadecimal(dp)<<"\n"<<printHexadecimal(dq)<<"\n"<<printHexadecimal(qinv)<<"\n"<<printHexadecimal(p)<<"\n"<<printHexadecimal(q)<<"\n";
}

string RSA_CRT::encrypt(const std::string& s){
    ZZ value = messageToZZ(s);
    ZZ cryptedMessage;

    PowerMod(cryptedMessage,value,e,n);

    return zzToMessage(cryptedMessage);
}

string RSA_CRT::decrypt(const std::string& s){
    ZZ value = messageToZZ(s);
    ZZ decryptedMessage;
    ZZ x1,x2,h;

    PowerMod(x1,value%p,d,p);
    PowerMod(x2,value%q,d,q);
    decryptedMessage = crt(p,x1,q,x2);

    return zzToMessage(x2);
}

ZZ RSA_CRT::inv(ZZ a, ZZ m) {
    ZZ m0 = m, temp, quotient;
    ZZ x0 , x1 = ZZ(1);

    if (m == 1)
        return ZZ(0);

    // Apply extended Euclid Algorithm
    while (a > 1) {
        quotient = a / m;

        temp = m;
        m = a % m, a = temp;

        temp = x0;
        x0 = x1 - quotient * x0;
        x1 = temp;
    }

    if (x1 < 0)
        x1 += m0;

    return x1;
}

ZZ RSA_CRT::crt(const ZZ& a1, const ZZ& p1, const ZZ& a2, const ZZ& p2) {
    ZZ prod = a1 * a2;
    // Initialize result
    ZZ result;

    ZZ pp = prod / a1;
    result += p1 * inv(pp, a1) * pp;

    pp = prod / a2;
    result += p2 * inv(pp, a2) * pp;

    return result % prod;
}

string RSA_CRT::encrypt(const std::string& s, const std::pair<ZZ, ZZ>& public_key) {
    ZZ value = messageToZZ(s);
    ZZ cryptedMessage;

    PowerMod(cryptedMessage,value,public_key.second,public_key.first);

    return zzToMessage(cryptedMessage);
}

string RSA_CRT::decrypt(const std::string& s, const std::pair<ZZ, ZZ> &private_key) {
    ZZ value = messageToZZ(s);
    ZZ decryptedMessage;

    PowerMod(decryptedMessage,value,private_key.second,private_key.first);

    return zzToMessage(decryptedMessage);
}

char RSA_CRT::valuetochar(long v)
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

long RSA_CRT::chartovalue(char c)
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

ZZ RSA_CRT::messageToZZ(const std::string& s){
    ZZ result;

    for(auto ch : s){
        result *= 64;
        result += chartovalue(ch);
    }

    return result;
}

std::string RSA_CRT::zzToMessage(ZZ value){
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

std::string RSA_CRT::printHexadecimal(ZZ value){
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
