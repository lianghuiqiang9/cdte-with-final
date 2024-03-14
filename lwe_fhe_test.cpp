#include "FINAL.h"
using namespace std;


//g++ -o lwe_fhe_test lwe_fhe_test.cpp -O3 -I final final/libfinal.a -lntl -lgmp -lfftw3 -lm

//./lwe_fhe_test

int main(){
    SchemeLWE fhe;
    int aa[4]={0,0,1,1};
    int bb[4]={0,1,0,1};
    vector<Ctxt_LWE> a_lwe(4);
    vector<Ctxt_LWE> b_lwe(4);

clock_t start=clock();
    for(int i=0;i<4;i++){
        fhe.encrypt(a_lwe[i],aa[i]);
        fhe.encrypt(b_lwe[i],bb[i]);
        
    }
    printf("Average Encrypt time is %f ms\n", (double)(clock() - start)/1000 /8);

    Ctxt_LWE res;
    
    start=clock();

    for(int i=0;i<4;i++){
        fhe.and_gate(res,a_lwe[i],b_lwe[i]);
        //int output = fhe.decrypt(res);
        //printf("out = %d \n",output);
    }

    printf("Average AND time is %f ms\n", (double)(clock() - start) / 1000/4);
    start=clock();
    for(int i=0;i<4;i++){
        fhe.xor_gate(res,a_lwe[i],b_lwe[i]);
        //int output = fhe.decrypt(res);
        //printf("out = %d \n",output);
    }

    printf("Average XOR time is %f ms\n", (double)(clock() - start) / 1000/4);
    start=clock();
    for(int i=0;i<4;i++){
        fhe.nand_gate(res,a_lwe[i],b_lwe[i]);
        //int output = fhe.decrypt(res);
        //printf("out = %d \n",output);
    }

    printf("Average NAND time is %f ms\n", (double)(clock() - start) / 1000/4);


}