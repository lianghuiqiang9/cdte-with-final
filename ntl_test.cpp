#include <NTL/ZZ.h>

using namespace std;
using namespace NTL;

//g++ ntl_test.cpp -o ntl_test -lntl -pthread -lgmp

//./ntl_test

int main()
{
   ZZ a, b, c;
   cout<<"please enter two number"<<endl;
   cin >> a;
   cin >> b;
   c = (a+1) * (b+1);
   cout << c << "\n";
}
