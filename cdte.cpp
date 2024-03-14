#include <iostream>
#include <fstream>
#include "client.h"
#include "server.h"
#include "node.h"
#include "utils.h"
#include "FINAL.h"


//./cdte

//g++ -o cdte cdte.cpp src/utils.cpp src/node.cpp -O3 -I./include -I final final/libfinal.a -lntl -lgmp -lfftw3 -lm 


using namespace std;


void flatten(Node& a,vector<Node*>& vec){
    if (!a.is_leaf()){
        flatten(*(a.left), vec);
        vec.push_back(&a);
        flatten(*(a.right), vec);
    }
}

std::vector<Node*> flatten(Node& a){
    vector<Node*> vec;
    flatten(a, vec);
    return vec;
}


//ENC(m >= t)
Ctxt_LWE greater_or_equal_cipher(SchemeLWE&fhe , std::vector<Ctxt_LWE> m,int data_bits, std::vector<Ctxt_LWE> t){
    
    Ctxt_LWE res,andyn,xnor;
    fhe.encrypt(res,1);
    //i=0;
    fhe.xor_gate(xnor,m[0],t[0]);
        fhe.not_gate(xnor,xnor);//xnor    
        fhe.not_gate(andyn,t[0]);
        fhe.and_gate(andyn,m[0],andyn);//andyn
        res=xnor+andyn;

    for(int i=1;i<data_bits;++i){
        fhe.xor_gate(xnor,m[i],t[i]);
        fhe.not_gate(xnor,xnor);//xnor    
        fhe.not_gate(andyn,t[i]);
        fhe.and_gate(andyn,m[i],andyn);//andyn
        fhe.and_gate(res,res,xnor);//
        //fhe.or_gate(res,res,andyn);
        res = res + andyn;//or
    }
    return res;
}


// Assume that the control bit of each internal node is already set
void traverse_rec(vector<Ctxt_LWE>& out, Node& node, SchemeLWE& fhe){
    Ctxt_LWE& parent = node.value;
    if (node.is_leaf()) {

        for(int i=0;i<node.LWECipher_class_leaf.size();i++){
            Ctxt_LWE temp;
            fhe.and_gate(temp,node.LWECipher_class_leaf[i],parent);
            out[i] = out[i] + temp;//or
        }
    }else{
        fhe.and_gate(node.right->value, parent, node.control_bit);
        node.left->value = parent - node.right->value;  //and not
        traverse_rec(out, *(node.left), fhe);
        traverse_rec(out, *(node.right), fhe);
    }
}

void traverse(vector<Ctxt_LWE>& out, Node& node, SchemeLWE& fhe,Ctxt_LWE& LWE_0,Ctxt_LWE& LWE_1){
    for(auto &e:out){
        fhe.encrypt(e,0);
    }
    fhe.encrypt(node.value,1);
    traverse_rec(out, node, fhe);
}

vector<vector<Ctxt_LWE>> pdte(Node &root, std::vector<std::vector<int>> &client_data,int data_bits,int data_m, SchemeLWE& fhe,  Ctxt_LWE& LWE_0,Ctxt_LWE& LWE_1){
    
    int class_leaf_bit=max_class_leaf_value_cipher_bit(root);
    //cout<<"class_leaf_bit "<<class_leaf_bit<<endl;

    int max_feat_index_add_one = root.LWECipher_feature_index.size();
    //cout<<"max_feat_index_add_one "<<max_feat_index_add_one<<endl;
    
    std::vector<Node*> nodes=flatten(root);//
    int node_num=nodes.size();
    //cout<<"node_num "<<node_num<<endl;

    vector<vector<Ctxt_LWE>> expect_result(data_m);

    for(int i=0;i<data_m;i++){
        vector<vector<int>> m(max_feat_index_add_one,vector<int>(data_bits));
        for(int j=0; j < max_feat_index_add_one; ++j){
            //printf(" %d ",client_data[i][j]);
            m[j]=IntegerToBinaryVector(client_data[i][j],data_bits);//抽取data，变为二进制向量。
        }

        clock_t start0=clock();
        for(int j=0;j<node_num;j++){
            printf("The %d decision node for evaluation..\n", j);
            clock_t start1=clock();
            vector<Ctxt_LWE> m_cipher_bitvector(data_bits);
            for(int _i=0;_i<data_bits;_i++){fhe.encrypt(m_cipher_bitvector[_i],0);}

            for(int _j=0;_j<data_bits;++_j){
                for(int _i=0;_i<max_feat_index_add_one;++_i){
                    if(m[_i][_j]==1){
                        m_cipher_bitvector[_j]=m_cipher_bitvector[_j]+nodes[j]->LWECipher_feature_index[_i];
                    }
                }
            }
            Ctxt_LWE enc_cmp=greater_or_equal_cipher(fhe,m_cipher_bitvector,data_bits,nodes[j]->LWECipher_threshold);
            nodes[j]->control_bit=enc_cmp;
            float run_time = (double)(clock()-start1)/CLOCKS_PER_SEC;
            printf("The data in row %d at the %d decision node with %d bit. The run time is %fs\n",i,j,data_bits,run_time);

        }
        vector<Ctxt_LWE> out(class_leaf_bit);//1是class_leaf的最大bit长度
        auto start2 = clock();
        traverse(out,root,fhe,LWE_0,LWE_1);
        expect_result[i]=out;
        printf("The time for the homomorphic traversal of the data in row %d is: %f s\n",i+1,(double)(clock()-start2)/CLOCKS_PER_SEC);
        printf("The total evaluation time for the data in line % d is: %f s\n", i+1, (double)(clock()-start0)/CLOCKS_PER_SEC);
    }

    return expect_result;
}

//g++ -o cdte cdte.cpp src/utils.cpp src/node.cpp -O3 -I./include -I final final/libfinal.a -lntl -lgmp -lfftw3 -lm 

//./cdte

int main(){
    cout<<"******************************* step 1: server begin *******************************"<<endl;

    auto start1=clock();
    auto start=clock();
    float run_time;

    cout<<"The server reads the privacy decision tree information"<<endl;
    string address_tree="data/heart_11bits/model.json";//"data/heart_11bits/model.json";
    int data_bits_s=11;//11

    std::ifstream ifs(address_tree);
    nlohmann::json j = nlohmann::json::parse(ifs);
    auto root = Node(j);
    auto root_original = Node(j);//仅做备份比较

    int t_bits=data_bits_s;//即是数据的最大比特长度，也是门限值的最大比特长度。

    cout<<"The server prints the decision tree."<<endl;
    print_tree(root);
    cout<<"The server sets the bit length of the decision result based on the decision tree."<<endl;
    int class_leaf_bit=bitLength(max_class_leaf_value(root));//这里要看情况的，是否是自己告诉，还是运算出来。但是肯定是服务器要自己做了，因为这里设置为最大也好像没有关系的。
    cout<<"Bit length of the decision node:"<<class_leaf_bit<<endl;
    int max_feat_index_add_one = max_feature_index(root)+1;//13
    cout<<"The largest property index add one: "<<max_feat_index_add_one<<endl;

    cout<<"The server initializes fully homomorphic encryption."<<endl;
    SchemeLWE fhe;
    std::cout << "The generation of the all-homomorphic scheme is completed in the following time" << float(clock()-start)/CLOCKS_PER_SEC <<" s"<< std::endl;

    std::cout << "LWE_0, LWE_1." << std::endl;
    Ctxt_LWE LWE_0;fhe.encrypt(LWE_0,0);//注意不要进行改动。
    Ctxt_LWE LWE_1;fhe.encrypt(LWE_1,1);

    start=clock();
    cout<<"The server encrypts the decision tree and prints the encrypted part of the decision tree data."<<endl;
    enc_tree(root,fhe,t_bits,class_leaf_bit,max_feat_index_add_one);

    //print_tree(root);
    //cout<<"The server decrypts the decision tree."<<endl;
    //dec_tree(root,fhe,t_bits,class_leaf_bit,max_feat_index_add_one);
    //cout<<"The server decrypts the decision tree and verifies the results."<<endl;
    //print_tree(root);
    cout<<"The server encrypts the decision tree and prints the encrypted part of the decision tree data time is : "<<float(clock()-start)/CLOCKS_PER_SEC <<" s"<< std::endl;
    
    std::cout << "The time it takes for the server to complete step 1 is: " << float(clock()-start1)/CLOCKS_PER_SEC <<" s"<< std::endl;

    cout<<"The server sends the fully homomorphic default parameters fhe and the secret state decision tree root to the client."<<endl;
    //fhe,LWE_0,LWE_1,root
    cout<<"******************************* step 1: server end *******************************"<<endl;

    cout<<"******************************* step 2: client begin *******************************"<<endl;
    //cout<<"The client receives the fully homomorphic default parameter fhe, the secret state decision tree root. and deserialize"<<endl;
    start=clock();

    print_tree(root);

    cout<<"The client reads the private data"<<endl;
    string address="data/heart_11bits/x_test.csv";//"data/heart_11bits/model.json";
    int data_bits=data_bits_s;//11
    
    int data_m=5;
    //int data_m;cout<<"Please enter the number of rows of read data"<<endl;cin>>data_m;
    std::vector<std::vector<int>> client_data=read_csv_to_vector(address,data_bits,data_m);
    int data_n=client_data[0].size();

    cout<<"The client prints the file and tests whether it is read correctly"<<endl;
    print_data(client_data);

    cout<<"The client performs a privacy decision tree evaluation.."<<endl;
    vector<vector<Ctxt_LWE>> expect_result;
    
    expect_result=pdte(root,client_data,data_bits,data_m,fhe,LWE_0,LWE_1);//这个pdte这个函数十分重要。

    run_time = float(clock()-start)/CLOCKS_PER_SEC;
    std::cout << "Client evaluation"<< data_m <<" row data is based on the time it takes to complete step 2 " << run_time <<" s"<< std::endl;

    cout << "The client sends the ciphertext of the comparison result to the server"<<endl;
    //expect_result two dim LWECiphertext
    cout<<"*******************************ste 2: client end*******************************"<<endl;

    cout<<"*******************************step 3: server begin *******************************"<<endl;

    cout << "The server receives the ciphertext of the comparison result"<<endl;

    start=clock();

    cout << "The server decrypts and verifies it"<<endl;
    vector<int> pdte_result(data_m);
    for(int i=0;i<expect_result.size();i++){
        vector<int> expect_result_bits(expect_result[i].size());
        for(int k=0;k<expect_result_bits.size();k++){
            expect_result_bits[k]=fhe.decrypt(expect_result[i][k]);
        }
        pdte_result[i]=BinaryVectorTointeger(expect_result_bits);
        std::vector<unsigned int> pf(client_data[i].size());
        for(int k=0;k<pf.size();k++){pf[k]=client_data[i][k];}
        int actural_result=root_original.eval(pf);
        printf("The %d line data, pdte_result[%d]= %d, actural_result[%d]= %d\n",i+1,i,pdte_result[i],i, actural_result);
    }

    printf( "The time it takes for the server to complete step 3 is: %f s\n",(double)(clock()-start)/CLOCKS_PER_SEC);
    
    printf("The total run time: %f s\n",(double)(clock()-start1)/CLOCKS_PER_SEC);

    printf("*******************************step 3: server end*******************************\n");

    return 0;
}

/*
******************************* step 1: server begin *******************************
服务器读取隐私决策树信息
服务器打印决策树。
                 (class: 0)
         (f: 7, t: 1746)
                 (class: 1)
 (f: 8, t: 1944)
                 (class: 2)
         (f: 10, t: 1954)
                         (class: 3)
                 (f: 4, t: 1633)
                         (class: 4)
服务器根据决策树设置决策结果的比特长度。
决策结点的比特长度：3
最大的属性索引+1：11
服务器初始化全同态加密。
Started generating the secret key of the base scheme
Generation time of the secret key of the base scheme: 1.7e-05
Started generating the secret key of the bootstrapping scheme
Generation time of the secret key of the bootstrapping scheme: 0.016491
KSKey-gen time: 0.216121
Bootstrapping key generation: 0.389834
全同态方案生成完成，时间为0.623394 s
计算LWE_0，LWE_1。
服务器对决策树进行加密并打印加密决策树部分数据。
服务器对决策树进行加密并打印加密决策树部分数据时间为 0.008435 s
服务器完成步骤1的时间为 0.632034 s
服务器将全同态默认参数fhe，密态决策树root发送给客户端。
******************************* step 1: server end *******************************
******************************* step 2: client begin *******************************
客户端接收到全同态默认参数fhe，密态决策树root。并进行逆序列化
                 (class: 0)
         (f: 0, t: 0)
                 (class: 0)
 (f: 0, t: 0)
                 (class: 0)
         (f: 0, t: 0)
                         (class: 0)
                 (f: 0, t: 0)
                         (class: 0)
客户端读取隐私数据
客户端打印文件，测试是否正确读取
701 2047 2047 1361 605 1842 1861 1445 1842 819 2047 0 0 
客户端进行隐私决策树评估..

进入第 0 个决策节点中进行评估..
第 0 行数据在第 0 个决策结点在 11 比特上。运行时间为 3.592105  s
进入第 1 个决策节点中进行评估..
第 0 行数据在第 1 个决策结点在 11 比特上。运行时间为 3.586958  s
进入第 2 个决策节点中进行评估..
第 0 行数据在第 2 个决策结点在 11 比特上。运行时间为 3.587418  s
进入第 3 个决策节点中进行评估..
第 0 行数据在第 3 个决策结点在 11 比特上。运行时间为 3.586662  s
第 1 行数据同态遍历的时间为: 1.578651 s
第 1 行数据总的评估时间为: 15.932065 s
客户端评估1行数据以完成步骤2的时间为 15.9324 s
客户端向服务器发送比较结果的密文
*******************************ste 2: client end*******************************
*******************************step 3: server begin *******************************
服务器接收到比较结果的密文
服务器解密并进行验证
第 1 行数据, pdte_result[0]= 2, actural_result[0]= 2
服务器完成 step 3 的时间为 0.000052 s
总的运行时间为 16.564644 s
*******************************step 3: server end*******************************


*/