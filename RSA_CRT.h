#ifndef RSA_RSA_CRT_H
#define RSA_RSA_CRT_H

#include <NTL/ZZ.h>
#include <utility>
#include <random>

using namespace std;
using namespace NTL;

class RSA_CRT{
private:
    ZZ p, q, n, phin, e, d, dp, dq, qinv;

    static char valuetochar(long v);
    static long chartovalue(char c);
    static ZZ messageToZZ(const std::string& s);
    static std::string zzToMessage(ZZ value);
    void computePublicKey();
    void computePrivateKey();
    static ZZ crt(const ZZ& a1,const ZZ& p1,const ZZ& a2, const ZZ& p2);
    static ZZ inv(ZZ a, ZZ m);
public:

    RSA_CRT();
    RSA_CRT(const std::pair<ZZ,ZZ>& public_key,const std::pair<ZZ,ZZ>& private_key);
    std::pair<ZZ,ZZ> getPublicKey();
    std::tuple<ZZ,ZZ,ZZ,ZZ,ZZ> getPrivateKey();
    void printPublicKey();
    void printPrivateKey();
    string encrypt(const std::string& s);
    string decrypt(const std::string& s);
    static string encrypt(const std::string& s, const std::pair<ZZ,ZZ>& public_key);
    static string decrypt(const std::string& s, const std::pair<ZZ,ZZ>& private_key);
    static std::string printHexadecimal(ZZ value);
};


#endif //RSA_RSA_CRT_H
