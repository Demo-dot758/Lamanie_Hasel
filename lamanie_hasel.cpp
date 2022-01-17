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
// signal(SIGHUP,signalHandler)
void signalHandler(int signum)
{
    std::cout << "Interrupt signal (" << signum << ") received.\n";
    work=0;

    std::exit(signum);
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
    // pthread_setcancelstate(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
    while(work)
    {
        
        pthread_mutex_lock(&global.mutex);

        while(global.ready==0)
            pthread_cond_wait(&global.cond,&global.mutex);
        

        printf("Znaleziono słowo:%s o kodzie %s.\n", global.password.c_str(),global.code);

        global.ready--;

        pthread_mutex_unlock(&global.mutex);
    }
    pthread_exit(NULL);
}

/*  Wątek 0
    Działa na małych literach, dodaje liczby na końcu
    -nie działa dodawanie liczb 01234 itd.
    -nie działa przesyłanie do wątku głównego
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
        // }else
        //     mess = dictionary.at(i);

        const char *mess1 = mess.c_str();

        /* Haszowanie słownika */
        EVP_DigestInit_ex(mdctx, md,NULL);
        // std::cout << "Word is: " << mess1 << std::endl;
        EVP_DigestUpdate(mdctx,mess1,strlen(mess1));
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        
        // Zamiana hexa
        char md5string[32];
        for(int j=0;j<md_len;j++)
            sprintf(&md5string[j*2],"%02x",md_value[j]);

        // Sprawdzenie czy kod MD5 z pliku został znaleziony    
        for(int c=0;c<ARRAY_SIZE;c++)
            if((strncmp(md5string,kodyMD5[c],32)==0))//&&(tablica[i]==0))
            {
                pthread_mutex_lock(&global.mutex);
                global.code=md5string;
                global.password=mess;
                global.index=c;
                // std::cout << "Znaleziono match, word: " << mess << " " << kodyMD5[c] << " " << md5string << std::endl;
                // tablica[i]=1;
                puts("Watek 1 wykryl slowo");
                global.ready++;
                pthread_cond_signal(&global.cond);
                pthread_mutex_unlock(&global.mutex);
                sleep(0.1);
                break;
                // std::unique_lock<std::mutex> ul(m);
                // m_ready=true;
                // ul.unlock();
                // m_cv.notify_one();
                // ul.lock();
                // m_cv.wait(ul,[](){return m_ready})
            }
        }
    
    }
    num++;
    }
    pthread_exit(NULL);
}

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
        }
        // }else
        //     mess = dictionary.at(i);

       
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
            if((strncmp(md5string,kodyMD5[c],32)==0)) //&&(tablica[i]==0))
            {
                pthread_mutex_lock(&global.mutex);
                global.code=md5string;
                global.password=mess;
                global.index=c;
                // tablica[i]=1;
                // std::cout << "Znaleziono match, word: " << mess << " " << kodyMD5[c] << " " << md5string << std::endl;
                puts("Watek 2 wykryl slowo");
                global.ready++;
                pthread_cond_signal(&global.cond);
                pthread_mutex_unlock(&global.mutex);
                sleep(0.1);
                break;
                // found_words.push_back(md5string);
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


    // Vector of threads
    // std::vector<thread> producer_threads;

    pthread_t threads[3];

    pthread_mutex_init(&global.mutex,NULL);
    pthread_cond_init(&global.cond,NULL);


    pthread_create(&threads[0],NULL,&Consumer,NULL);
    pthread_create(&threads[1],NULL,&Producer10,NULL);
    pthread_create(&threads[2],NULL,&Producer12,NULL);


    // thread producer12(Producer12);
    
    // for(int i=0;i<NUM_THREADS;i++)
    // {
    //     producer_threads.push_back(thread(Producer));
    // }
    
    

    // for (thread &p : producer_threads) 
    // {
    //     if (p.joinable())
    //     {
    //         p.join();
    //     }
    // }
    // for(int i=0;i<4;i++)
   
    

    pthread_mutex_destroy(&global.mutex);
    pthread_cond_destroy(&global.cond);
    pthread_exit (NULL);
//    for (int i = 0; i < 3; i++)
//         pthread_join(threads[i], NULL);
    // producer12.join();

    // for(int num=0;i<Struktura.found_words.size();num++)
    //     cout << Struktura.found_words[num] << endl;
    // return 0;
}