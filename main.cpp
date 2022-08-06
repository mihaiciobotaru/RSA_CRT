#include <iostream>
#include <chrono>
#include "RSA.h"
#include "RSA_CRT.h"
typedef std::chrono::system_clock::time_point time_m;
int main() {
    RSA              rsa           = RSA();
    RSA_CRT          rsa_crt       = RSA_CRT();
    string           plaintext     = "HelloWorld";
    string           cryptedText;
    time_m           start;
    time_m           stop;


    std::cout<<"============= RSA =============\n\n";


    rsa.printPublicKey();
    rsa.printPrivateKey();

    std::cout<<"plaintext: "<<plaintext<<"\n\n";
    cryptedText = rsa.encrypt(plaintext);
    std::cout<<"cryptotext: "<<cryptedText<<"\n\n";
    start = std::chrono::high_resolution_clock::now();
    std::cout<<"decrypted text: "<<rsa.decrypt(cryptedText)<<"\n\n";
    stop = std::chrono::high_resolution_clock::now();
    auto duration1 = std::chrono::duration_cast<std::chrono::microseconds>(stop-start);
    std::cout<<"Time for RSA decryption to execute: "<<duration1.count()<<" microseconds\n";


    std::cout<<"============= RSA-CRT =============\n\n";


    rsa_crt.printPublicKey();
    rsa_crt.printPrivateKey();

    std::cout<<"plaintext: "<<plaintext<<"\n\n";
    cryptedText = rsa_crt.encrypt(plaintext);
    std::cout<<"cryptotext: "<<cryptedText<<"\n\n";
    start = std::chrono::high_resolution_clock::now();
    std::cout<<"decrypted text: "<<rsa_crt.decrypt(cryptedText)<<"\n\n";
    stop = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(stop-start);
    std::cout<<"Time for RSA-CRT decryption to execute: "<<duration2.count()<<" microseconds\n";
    std::cout<<"RSA-CRT decryption took "<<duration1.count()/duration2.count()<<"x less time to execute than RSA.\n";

    return 0;
}
