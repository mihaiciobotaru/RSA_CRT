#ifndef RSA_RSA_H
#define RSA_RSA_H

#include <NTL/ZZ.h>
#include "random"
#include <utility>

using namespace std;
using namespace NTL;

class RSA {
private:
    ZZ p, q, n, phin, e, d;

    static char valuetochar(long v);
    static long chartovalue(char c);
    static ZZ messageToZZ(const std::string& s);
    static std::string zzToMessage(ZZ value);
    void computePublicKey();
    void computePrivateKey();
public:

    RSA();
    RSA(const std::pair<ZZ,ZZ>& public_key,const std::pair<ZZ,ZZ>& private_key);
    std::pair<ZZ,ZZ> getPublicKey();
    std::pair<ZZ,ZZ> getPrivateKey();
    void printPublicKey();
    void printPrivateKey();
    string encrypt(const std::string& s);
    string decrypt(const std::string& s);
    static string encrypt(const std::string& s, const std::pair<ZZ,ZZ>& public_key);
    static string decrypt(const std::string& s, const std::pair<ZZ,ZZ>& private_key);
    static std::string printHexadecimal(ZZ value);
};


#endif //RSA_RSA_H
