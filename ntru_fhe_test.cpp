

#include "FINAL.h"
using namespace std;


//g++ -o ntru_fhe_test ntru_fhe_test.cpp -O3 -I final final/libfinal.a -lntl -lgmp -lfftw3 -lm

int main(){
    SchemeNTRU fhe;
    int aa[4]={0,0,1,1};
    int bb[4]={0,1,0,1};
    vector<Ctxt_NTRU> a_lwe(4);
    vector<Ctxt_NTRU> b_lwe(4);

clock_t start=clock();
    for(int i=0;i<4;i++){
        fhe.encrypt(a_lwe[i],aa[i]);
        fhe.encrypt(b_lwe[i],bb[i]);
        
    }
    printf("Average Encrypt time is %f seconds\n", (double)(clock() - start) / CLOCKS_PER_SEC/8);

    Ctxt_NTRU res;
    
    start=clock();

    for(int i=0;i<4;i++){
        fhe.and_gate(res,a_lwe[i],b_lwe[i]);
        int output = fhe.decrypt(res);
        printf("out = %d \n",output);
    }

    printf("Average AND time is %f seconds\n", (double)(clock() - start) / CLOCKS_PER_SEC/4);




}