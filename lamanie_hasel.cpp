#include <iostream>
#include <string>
#include <fstream>
#include <openssl/evp.h>
#include <pthread.h>
#include <vector>
#include <csignal>
#include <cstring>
#include <algorithm>
#include <math.h>
#include <unistd.h>

#define ARRAY_SIZE 408
#define NUM_THREADS 2
#define MD5_LENGTH 33
using namespace std;

//g++ lamanie_hasel.cpp -o lamanie_hasel.out -lpthread -lssl -lcrypto 


char kodyMD5[ARRAY_SIZE][MD5_LENGTH];   //tablica statyczna kodów MD55
vector<string> dictionary;              //słownik
vector<string> found_words;
vector<string> found_md5;

struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int ready;
    int index;
    char *code;
    string password;
} global = {PTHREAD_MUTEX_INITIALIZER,
            PTHREAD_COND_INITIALIZER};

int work=1;

int tablica[1000];
 
// **** Po otrzymaniu syngału SIGHUP konsument wyświetla podsumowanie
void signalHandler(int signum)
{
    std::cout << "Interrupt signal (" << signum << ") received.\n";
    work=0;
    for(int i=0;i<found_words.size();i++)
    {
        std::cout << "Numer:" << i << " Slowo:" << found_words.at(i) << " MD5:" << found_md5.at(i) << std::endl;
        // printf("Numer: %d, slowo: %s, kod: %s\n",i,found_words.at(i),found_md5.at(i));
    }
    exit(1);
}


void loadData(){
    // Kody MD5
    ifstream file ("hashed_passwords.txt");
    if(file.is_open())
    {
    for(int i = 0; i < ARRAY_SIZE; ++i)
    {
        file >> kodyMD5[i];
        // cout << kodyMD5[i] << endl;
    }
    }
    else
    {
        cerr << "Could not open file" << endl;
    }

    // Słownik
    ifstream file2 ("dictionary.txt");
    if(file2.is_open()){
        string word;
        while(file2 >> word)
        {
            dictionary.push_back(word);
        }
        // for(int i=0;i<dictionary.size();i++)
        // {
        //     cout << dictionary[i] << endl;
        // }
    } else
    cerr << "Could not open dictionary" << endl;

    for(int i=0;i<1000;i++){
        tablica[i]=0;
    }
}
void *Consumer(void *args)
{   
    while(work)
    {
        
        pthread_mutex_lock(&global.mutex);

        while(global.ready==0)
            pthread_cond_wait(&global.cond,&global.mutex);
        

        printf("Znaleziono słowo:%s o kodzie %s.\n", global.password.c_str(),global.code);

        found_words.push_back(global.password);
        found_md5.push_back(global.code);
        global.ready--;

        pthread_mutex_unlock(&global.mutex);
    }
    pthread_exit(NULL);
}

/*  Wątek 10
    Działa na małych literach, dodaje liczby na końcu
*/
void *Producer10(void *args)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[32];
    unsigned int md_len;
    md = EVP_get_digestbyname("MD5");
    mdctx = EVP_MD_CTX_new();

   
    int num = 0;
    while(1)
    {
    for(int i=0;i<dictionary.size();i++)
    {   
        for(int k=0;k<pow(10,num);k++)
        {
        string number;
        number+=to_string(k);
        string mess;
        if(num>0)
        {
            mess = dictionary.at(i)+number;
        }
        // else
        //     mess = dictionary.at(i);

        const char *mess1 = mess.c_str();

        /* Haszowanie słownika */
        EVP_DigestInit_ex(mdctx, md,NULL);
        EVP_DigestUpdate(mdctx,mess1,strlen(mess1));
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        
        // Zamiana hexa
        char md5string[32];
        for(int j=0;j<md_len;j++)
            sprintf(&md5string[j*2],"%02x",md_value[j]);

        // Sprawdzenie czy kod MD5 z pliku został znaleziony    
        for(int c=0;c<ARRAY_SIZE;c++)
            if((strncmp(md5string,kodyMD5[c],32)==0&&(tablica[c]==0)))
            {
                pthread_mutex_lock(&global.mutex);
                global.code=md5string;
                global.password=mess;
                global.index=c;
                tablica[c]=1;
                // puts("Watek 1 wykryl slowo");
                global.ready++;
                pthread_cond_signal(&global.cond);
                pthread_mutex_unlock(&global.mutex);
                sleep(0.1);
                break;
            }
        }
    
    }
    num++;
    }
    pthread_exit(NULL);
}


/*  Wątek 11
    Działa na małych literach, dodaje liczby na końcu i na poczatku
*/
void *Producer11(void *args)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[32];
    unsigned int md_len;
    md = EVP_get_digestbyname("MD5");
    mdctx = EVP_MD_CTX_new();

   
    int num = 0;
    while(1)
    {
    for(int i=0;i<dictionary.size();i++)
    {   
        for(int k=0;k<pow(10,num);k++)
        {
        string number;
        number+=to_string(k);
        string mess;
        if(num>0)
        {
            mess = number+dictionary.at(i)+number;
        }

        const char *mess1 = mess.c_str();

        /* Haszowanie słownika */
        EVP_DigestInit_ex(mdctx, md,NULL);
        EVP_DigestUpdate(mdctx,mess1,strlen(mess1));
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        
        // Zamiana hexa
        char md5string[32];
        for(int j=0;j<md_len;j++)
            sprintf(&md5string[j*2],"%02x",md_value[j]);

        // Sprawdzenie czy kod MD5 z pliku został znaleziony    
        for(int c=0;c<ARRAY_SIZE;c++)
            if((strncmp(md5string,kodyMD5[c],32)==0)&&(tablica[c]==0))
            {
                pthread_mutex_lock(&global.mutex);
                global.code=md5string;
                global.password=mess;
                global.index=c;
                tablica[c]=1;
                // puts("Watek 2 wykryl slowo");
                global.ready++;
                pthread_cond_signal(&global.cond);
                pthread_mutex_unlock(&global.mutex);
                sleep(0.1);
                break;
                
            }
        }
    
    }
    num++;
    }
    pthread_exit(NULL);
}

/*  Wątek 12
    Działa na wielkich literach, dodaje liczby na końcu
*/
void *Producer12(void *args)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[32];
    unsigned int md_len;
    md = EVP_get_digestbyname("MD5");
    mdctx = EVP_MD_CTX_new();

    int num =0;
    int x=0;


    while(1)
    {
    for(int i=0;i<dictionary.size();i++)
    {   
        for(int k=0;k<pow(10,num);k++)
        {
        string number;
        number+=to_string(k);
        string mess;
        if(num>0)
        {
            mess = dictionary.at(i)+number;
        }else
            mess = dictionary.at(i);

       
        // UPPERCASE LETTERS 
        std::transform(mess.begin(),mess.end(),mess.begin(),::toupper);
        const char *mess1 = mess.c_str();
        // std::cout << "Word is: " << mess1 << std::endl;

        /* Haszowanie słowa */
        EVP_DigestInit_ex(mdctx, md,NULL);
        EVP_DigestUpdate(mdctx,mess1,strlen(mess1));
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);

        // Zamiana formatu
        char md5string[32];
        for(int j=0;j<md_len;j++)
            sprintf(&md5string[j*2],"%02x",md_value[j]);

        // Sprawdzenie czy kod MD5 z pliku został znaleziony    
        for(int c=0;c<ARRAY_SIZE;c++)
            if((strncmp(md5string,kodyMD5[c],32)==0)&&(tablica[c]==0))
            {
                pthread_mutex_lock(&global.mutex);
                global.code=md5string;
                global.password=mess;
                global.index=c;
                tablica[c]=1;
                // puts("Watek 3 wykryl slowo");
                global.ready++;
                pthread_cond_signal(&global.cond);
                pthread_mutex_unlock(&global.mutex);
                sleep(0.1);
                break;
            }
        }
    }
    num++;
    }
    pthread_exit(NULL);
}

/*  Wątek 10
    Działa na małych literach, skleja ze sobą słowa, a następnie dodaje liczby na końcu
*/
void *Producer20(void *args)
{
      EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[32];
    unsigned int md_len;
    md = EVP_get_digestbyname("MD5");
    mdctx = EVP_MD_CTX_new();

    int num =0;
    int x=0;


    while(1)
    {
    for(int i=0;i<dictionary.size();i++)
    {   
        for(int k=0;k<pow(10,num);k++)
        {
            for(int d=0;d<dictionary.size();d++)
            {
            string number;
            number+=to_string(k);
            string mess;
            if(num>0)
            {
                mess = dictionary.at(i)+dictionary.at(d)+number;
            }else
                mess = dictionary.at(i)+dictionary.at(d);

            const char *mess1 = mess.c_str();

            /* Haszowanie słowa */
            EVP_DigestInit_ex(mdctx, md,NULL);
            EVP_DigestUpdate(mdctx,mess1,strlen(mess1));
            EVP_DigestFinal_ex(mdctx, md_value, &md_len);

            // Zamiana formatu
            char md5string[32];
            for(int j=0;j<md_len;j++)
                sprintf(&md5string[j*2],"%02x",md_value[j]);

            // Sprawdzenie czy kod MD5 z pliku został znaleziony    
            for(int c=0;c<ARRAY_SIZE;c++)
                if((strncmp(md5string,kodyMD5[c],32)==0)&&(tablica[c]==0))
                {
                    pthread_mutex_lock(&global.mutex);
                    global.code=md5string;
                    global.password=mess;
                    global.index=c;
                    tablica[c]=1;
                    // puts("Watek 4 wykryl slowo");
                    global.ready++;
                    pthread_cond_signal(&global.cond);
                    pthread_mutex_unlock(&global.mutex);
                    sleep(0.1);
                    break;
                }
            }
        }
    }
    num++;
    }
    pthread_exit(NULL);
}
int main(int argc,char *argv[])
{
    loadData();

    signal(SIGHUP,signalHandler);

    pthread_t threads[5];

    pthread_mutex_init(&global.mutex,NULL);
    pthread_cond_init(&global.cond,NULL);


    pthread_create(&threads[0],NULL,&Consumer,NULL);
    pthread_create(&threads[1],NULL,&Producer10,NULL);
    pthread_create(&threads[2],NULL,&Producer11,NULL);
    pthread_create(&threads[3],NULL,&Producer12,NULL);
    pthread_create(&threads[4],NULL,&Producer20,NULL);


    pthread_mutex_destroy(&global.mutex);
    pthread_cond_destroy(&global.cond);
    pthread_exit (NULL);

}