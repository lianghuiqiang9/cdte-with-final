
# Model process
This is a two-party dense state model, the server and the client. 
1. The server sends the decision tree cipher to the client, 
2. The client uses it in the dense state decision tree, then the plaintext data is evaluated, and a ciphertext result is returned and sent to the server. 
3. The server gets the ciphertext result, and decrypts it with the private key to get the evaluation result.


# 1. should install "gmp", "ntl" first

g++ ntl_test.cpp -o ntl_test -lntl -pthread -lgmp

./ntl_test

if pass, the "GMP", "NTL" is successful instal.

# 2. should install "fftw3" first


# 3. then instal final, in the final file

cd final
make 

g++ -o lwe_fhe_test lwe_fhe_test.cpp -O3 -I final final/libfinal.a -lntl -lgmp -lfftw3 -lm

./lwe_fhe_test

if pass, the "final" is successful instal.

# 4. then compile the cdte

g++ -o cdte cdte.cpp src/utils.cpp src/node.cpp -O3 -I./include -I final final/libfinal.a -lntl -lgmp -lfftw3 -lm 

./cdte

####The FINAL library used here, because there is addition, which can reduce a lot of operations.
