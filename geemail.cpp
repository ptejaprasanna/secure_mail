
#include <stdio.h>
#include <sqlite3.h>
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <gcrypt.h>
#include <iomanip>
#include <vector>
#include <stdlib.h>
#include <unistd.h>
using namespace std;

struct MyData {
    
    string id,sname,rname,subject,body,spassword,salt,date,stime;
};
struct Password{
    string passHex,passSalt;
};

static int userNameCount(void *data, int argc, char **argv, char **azColName);
static int insert_query(char* query);
static void registers();
static void logins();
static void app_menu(string username);
static void menu();
static int fetch_emails(void *ptr, int argc, char *argv[], char *names[]);
static void send_message(string username);
static void show_inbox(string username);
static void show_outbox(string username);
static string hex_to_string(const std::string& input);
static string string_to_hex(const std::string& input);
static string HexOfPass(string password,int salt);

static string encryptEmail(string sender_message, string key_value, string nonce_value);
static string decryptEmail (string encrypted_text, string passphrase, string iv);

static string string_to_hex(const std::string& input){
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}
static string hex_to_string(const std::string& input){
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();
    if (len & 1) throw std::invalid_argument("odd length");

    std::string output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2)
    {
        char a = input[i];
        const char* p = std::lower_bound(lut, lut + 16, a);
        if (*p != a) throw std::invalid_argument("not a hex digit");

        char b = input[i + 1];
        const char* q = std::lower_bound(lut, lut + 16, b);
        if (*q != b) throw std::invalid_argument("not a hex digit");

        output.push_back(((p - lut) << 4) | (q - lut));
    }
    return output;
}
static int r_salt(){
    setvbuf(stdout, NULL, _IONBF, 0);

    unsigned int randval;
    FILE *f;

    f = fopen("/dev/urandom", "r");
    fread(&randval, sizeof(randval), 1, f);
    fclose(f);
    fflush(stdout);
    usleep(1); 
    return randval;
}
static int userNameCount(void *data, int argc, char **argv, char **azColName){
//   int i;
    
    *(char*) data=0;
   
//   for(i = 0; i<argc; i++){
//       printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
//   }
//   if(argv[0][0]!='0'){ 
//      *(char*) data=1;
//   }
    
   if(argv[0][0]!='0'){ 
       *(char*) data=1;
   }
   return 0;
}
static string HexOfPass(string password,int salt){
    unsigned char result[32];
    int i,r;
    size_t index;
    char * hashBuffer = (char*)malloc(33);
    size_t txtLength;
    memset(hashBuffer, 0, 33);
    string append;
    string hash;
    //get the salt
     //int salt =283453656;//random_var();
     string StringSalt=to_string(abs(salt));
     //password+salt
     append=password+StringSalt;
     txtLength = append.length()+1;
     //printf("%zu\n",txtLength);
     
    char * textBuffer = (char*)malloc(33);
    //cout << append<<endl;
    strncpy(textBuffer,append.c_str(),txtLength);
    
    //hashing
    for(r=0;r<3;r++)
    {
     gcry_md_hash_buffer(
        GCRY_MD_SHA256, // gcry_cipher_hd_t
        hashBuffer,    // void *
        textBuffer,    // const void *
        txtLength);   // size_t

    //printf("hashBuffer = ");
    for (index = 0; index<32; index++)
    {   //printf((unsigned char)hashBuffer[index]);
        
        //printf("%02X",(unsigned char)hashBuffer[index]);
        if(r==2)
        hash+=("%02X",(unsigned char)hashBuffer[index]);
        //hash[index]=("%02X",(unsigned char)hashBuffer[index]);
    }
    strncpy(textBuffer,hashBuffer,strlen(hashBuffer));
    //printf("\n");
   // printf("%s",hash);
    }
    //cout<<hash<<endl;
    string hex=string_to_hex(hash);
    //cout<<hex<<endl;
    free(hashBuffer);
    free(textBuffer);
   
     return hex;
}
static int fetch_emails(void *ptr, int argc, char *argv[], char *names[]){
    vector<MyData> *list = reinterpret_cast<vector<MyData> *>(ptr);
    MyData d;
    d.id=argv[0] ? argv[0] : "0";
    d.sname = argv[1] ? argv[1] : "";
    d.rname = argv[2] ? argv[2] : "";
    d.subject = argv[3] ? argv[3] : "";
    d.body = argv[4] ? argv[4] : "";
    d.spassword = argv[5] ? argv[5] : "";
    d.salt=argv[6] ? argv[6] : "";
    d.date=argv[7] ? argv[7] : "";
    d.stime=argv[8] ? argv[8] : "";
    list->push_back(d);
    return 0;
}
static int fetch_password(void *ptr, int argc, char *argv[], char *names[]){
    vector<Password> *list = reinterpret_cast<vector<Password> *>(ptr);
    Password p;
    p.passHex=argv[0] ? argv[0] : "";
    p.passSalt = argv[1] ? argv[1] : "";
    list->push_back(p);
    return 0;
}
static vector<MyData> searchForEmails(char* query){
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;

    vector<MyData> list;
    /* Open database */
   rc = sqlite3_open("geemail.db", &db);
   
   if( rc ) {
      fprintf(stderr, "Error: Can't open database: %s\n", sqlite3_errmsg(db));
     
   } 
   /* Create SQL statement */
   char* sql = query;
   //sql = "SELECT * from COMPANY";

   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql, fetch_emails, (void*) &list, &zErrMsg);
   
   if( rc != SQLITE_OK ) {
      fprintf(stderr, "Error:SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   } else {
      fprintf(stdout, "Search done successfully\n");
      
   }
   sqlite3_close(db);
   return list;
}
static vector<Password> searchForPassword(char* query){
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;

    vector<Password> list;
    /* Open database */
   rc = sqlite3_open("geemail.db", &db);
   
   if( rc ) {
      fprintf(stderr, "Error: Can't open database: %s\n", sqlite3_errmsg(db));
     
   } 
   /* Create SQL statement */
   char* sql = query;
   //sql = "SELECT * from COMPANY";

   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql, fetch_password, (void*) &list, &zErrMsg);
   
   if( rc != SQLITE_OK ) {
      fprintf(stderr, "Error:SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   } else {
      fprintf(stdout, "Search done successfully\n");
      
   }
   sqlite3_close(db);
   return list;
}
//inserting into the database.
static int insert_query(char* query){

    sqlite3* db;
    char *zErrMsg = 0;
    int rc;
    rc = sqlite3_open("geemail.db", &db);
    if( rc ){
        fprintf(stderr, "Error: Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    };
    
    char* sql = query;
    rc = sqlite3_exec(db, sql, userNameCount, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
        fprintf(stderr, "Error: SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return 0;
    }else{
        fprintf(stdout, "Inserted the query successfully\n");
        return 1;
    }
    sqlite3_close(db);
    
}
static int search_in(char* query){
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;

    char data[500];
    /* Open database */
   rc = sqlite3_open("geemail.db", &db);
   
   if( rc ) {
      fprintf(stderr, "Error: Can't open database: %s\n", sqlite3_errmsg(db));
      return 0;
   } 
   /* Create SQL statement */
   char* sql = query;
   //sql = "SELECT * from COMPANY";

   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql, userNameCount, (void*) &data, &zErrMsg);
   
   if( rc != SQLITE_OK ) {
      fprintf(stderr, "Error:SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   } else {
      //fprintf(stdout, "Search done successfully\n");
      
   }
   sqlite3_close(db);
   return (int)data[0];
}
//Encryption function
static string encryptEmail(string sender_message, string key_value, string nonce_value){

    gcry_error_t     gcryError;
    gcry_cipher_hd_t gcryCipherHd;
    size_t index;
    const void* salsaKey = key_value.c_str(); // 32 bytes
    const void* iniVector = nonce_value.c_str(); // 8 bytes

    gcryError = gcry_cipher_open(
        &gcryCipherHd, // gcry_cipher_hd_t *
        GCRY_CIPHER_SALSA20,   // int
        GCRY_CIPHER_MODE_STREAM,   // int
        0);            // unsigned int
    if (gcryError)
    {
        printf("gcry_cipher_open failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));
    }
    //printf("gcry_cipher_open worked\n");
    
    gcryError = gcry_cipher_setkey(gcryCipherHd, salsaKey, 32);
    if (gcryError)
    {
        printf("gcry_cipher_setkey failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));

    }
  
    
    gcryError = gcry_cipher_setiv(gcryCipherHd, iniVector, 8);
    if (gcryError)
    {
        printf("gcry_cipher_setiv failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));
    }
    //printf("gcry_cipher_setiv worked\n");
    
    size_t txtLength = 401;
    char * encBuffer =(char *) malloc(txtLength);
    char * textBuffer =(char *) malloc(txtLength);
    memset(textBuffer, 0, 401);
    string body = "message from me";
    //decryptEmail(body,key,nonce);
    strncpy(textBuffer,sender_message.c_str(),sender_message.length());
    gcryError = gcry_cipher_encrypt(
        gcryCipherHd, // gcry_cipher_hd_t
        encBuffer,    // void *
        txtLength,    // size_t
        textBuffer,    // const void *
        txtLength);   // size_t
    if (gcryError)
    {
        printf("gcry_cipher_decrypt failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));
    }
    //printf("gcry_cipher_decrypt worked\n");
    //printf("encBuffer = ");
    string encrypted_message;
    for (index = 0; index<txtLength-1; index++){
        //printf("%02X", (unsigned char)encBuffer[index]);
        encrypted_message+=("%02X", (unsigned char)encBuffer[index]);
    }
    printf("\n");
    return encrypted_message;
}

static string decryptEmail (string encrypted_text, string passphrase, string iv){
  
  const void* value = passphrase.c_str();
  gcry_error_t     gcryError;
    gcry_cipher_hd_t gcryCipherHd;
    size_t           index;
    //string ivBytes = "AAAAAAAA"; // 8 bytes
    
    char *ivBytes = (char*)malloc(9);
    strncpy(ivBytes,iv.c_str(),iv.length());
    ivBytes[8]='\0';
    cout <<"ivBytes len: "<<strlen(ivBytes)<<endl<<ivBytes<<endl;
    //byte *ivBytes = (byte*)iv.c_str();
	

    gcryError = gcry_cipher_open(
        &gcryCipherHd, // gcry_cipher_hd_t *
        GCRY_CIPHER_SALSA20,   // int
        GCRY_CIPHER_MODE_STREAM,   // int
        0);            // unsigned int
 
   
    
    gcryError = gcry_cipher_setkey(gcryCipherHd, value, 32);
 
  
    
    gcryError = gcry_cipher_setiv(gcryCipherHd, ivBytes, 8);
 
    
    size_t txtLength = encrypted_text.length();
    char * encBuffer = (char*)malloc(txtLength+10);
    char * textBuffer = (char*)malloc(txtLength+10);
    
    strncpy(encBuffer,encrypted_text.c_str(),encrypted_text.length());
    encBuffer[encrypted_text.length()]='\0';
    txtLength=strlen(encBuffer);
        gcryError = gcry_cipher_encrypt(
        gcryCipherHd, // gcry_cipher_hd_t
        textBuffer,    // void *
        txtLength,    // size_t
        encBuffer,    // const void *
        txtLength);   // size_t
    textBuffer[encrypted_text.length()]='\0';
    string plaintextStr(textBuffer);
    free(encBuffer);
    free(textBuffer);
    free(ivBytes);
    return plaintextStr;
    
}




//the App's functions
static void menu(){
    string choice;
    while (1){


       
 
        cout << "║  1- Login to your account.                                    ║" << endl;
        cout << "║  2- Register.                                                 ║" << endl;
        cout << "║  3- Exit.                                                     ║" << endl;
  
  
        cin >> choice;
        
        if (isdigit(choice[0]) && (choice=="1")){
            logins();
            break;
        }
        else if (isdigit(choice[0]) && choice== "2"){
            registers();
            break;
        }
        else if (isdigit(choice[0]) && choice== "3"){
            cout <<" Good bye! "<<endl;
            exit(0);
            break;
        }
        
        else{
            cout << "Error: Enter a valid choice from th menu.\n\n" << endl;
        }
    }
}//done
static void logins(){
    while (1){
    string username;
    string password;
    vector<Password> inData;
    string hash_password;
    
    cout << " ┌──────────────────────────────────────────────────────┐"<< endl;
    cout << " |Please enter the username:                             |" << endl;
    cout << " └──────────────────────────────────────────────────────┘"<< endl;
    cin >> username;
    cout << " ┌──────────────────────────────────────────────────────┐"<< endl;
    cout << " |Please enter the password:                         |" << endl;
    cout << " └──────────────────────────────────────────────────────┘"<< endl;
    cin >> password;
    cin.ignore();
    if (username==""||password==""){
        cout<<"Error: The fields can't be empty.\n\n"<<endl;
    }
    
    if (username.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890_") != std::string::npos)
    {
    std::cerr << "Error: username cannot have special characters.\n\n";
    exit(0);
    }

    if (password.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890_") != std::string::npos)
    {
    std::cerr << "Error: password cannot have special characters.\n\n";
    exit(0);
    }
    
    
    string unameSquery="SELECT count(*) as count FROM users WHERE name='"+username+"' ;";
    char *sql1 = (char *)alloca(unameSquery.size() + 1);
    memcpy(sql1, unameSquery.c_str(), unameSquery.size() + 1);
    int i=search_in(sql1);
    if (i!=1){
            cout<<"Error: username is incorrect."<<endl;
    }
    else{
    
    string query="SELECT password , salt  FROM users WHERE name='"+username+"';";
    char *sql0 = (char *)alloca(query.size() + 1);
    memcpy(sql0, query.c_str(), query.size() + 1);
    string saltTest,passTest;
    inData=searchForPassword(sql0);
    saltTest=inData[0].passSalt;
    passTest=inData[0].passHex;
    //cout << "## the pass from the DB. => "<<passTest<<endl;
    hash_password=HexOfPass(password,stoi(saltTest));

    if(hash_password==passTest)
        app_menu(username);
    else{
        cout<<"Error: password is incorrect."<<endl;
    }
    }
    }
}//done
static void app_menu(string username){
    
string choice;
    while (1){

        cout << "║───────────────────────────────────────────────────────────────║" << endl;
        cout << "║  1- Send a messsage.                                          ║" << endl;
        cout << "║  2- Check inbox.                                         ║" << endl;
        cout << "║  3- Check outbox.                                        ║" << endl;
        cout << "║  4- Go to main menu.                                          ║" << endl;
        cout << "║  5- Exit.                                                     ║" << endl;
        cout << "║                                                               ║" << endl;
        cout << "║                                                               ║" << endl;
        cout << "║                                                               ║" << endl;
        cout << "║                                                               ║" << endl;
        cout << " ┌──────────────────────────────────────────────────────────────┐"<< endl;
        cout << "  "+username+" Enter one of the options:"<< endl;
        cout << " └──────────────────────────────────────────────────────────────┘"<< endl;
        cin >> choice;
        cin.ignore();
        if (isdigit(choice[0]) && (choice=="1")){
            send_message(username);
            break;
        }
        else if (isdigit(choice[0]) && choice== "2"){
            string unameSquery="SELECT count(*) as count FROM emails WHERE rname='"+username+"';";
            char *sql1 = (char *)alloca(unameSquery.size() + 1);
            memcpy(sql1, unameSquery.c_str(), unameSquery.size() + 1);
            int i=search_in(sql1);
            if (i==0){
                cout<<"You have no messages in your inbox."<<endl;
                app_menu(username);
            }
  
            else{
                show_inbox(username);
            }
            break;
        }
        else if (isdigit(choice[0]) && choice== "3"){
            string unameSquery="SELECT count(*) as count FROM emails WHERE sname='"+username+"';";
            char *sql1 = (char *)alloca(unameSquery.size() + 1);
            memcpy(sql1, unameSquery.c_str(), unameSquery.size() + 1);
            int i=search_in(sql1);
            if (i==0){
                cout<<"You have no messages in your outbox."<<endl;
                app_menu(username);
            }
         
            else{
            show_outbox(username);
            }
            break;
        }
        else if (isdigit(choice[0]) && choice== "4"){
            menu();
            break;
        }
        else if (isdigit(choice[0]) && choice== "5"){
            cout <<"._.o0o( Good bye! )o0o._."<<endl;
            exit(0);
            break;
        }
        
        else{
            cout << "Enter a valid choice.\n\n" << endl;
        }
    }
    
    
}//done
static void send_message(string username){
    string subject;
    string content;
    string to;
    string password;
    string hash_password;
    string sSalt;
    int iSalt;
    string iquery;
    string encContent,hexEncContent;
    
    while (1){
 
    cout << "║                   - SEND A MESSAGE -                   ║" << endl;
    cout << "╚════════════════════════════════════════════════════════╝" << endl;
 
    cout << " ┌──────────────────────────────────────────────────────┐"<< endl;
    cout << "  "+username+" Subject:" << endl;
    cout << " └──────────────────────────────────────────────────────┘"<< endl;
    getline (cin,subject);
    if (subject.find_first_not_of(" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890_,.?!") != std::string::npos)
    {
    std::cerr << "Error: subject cannot have special characters.\n\n";
    exit(0);
    }
    cout << " ┌──────────────────────────────────────────────────────┐"<< endl;
    cout << "  "+username+" Enter the message:" << endl;
    cout << " └──────────────────────────────────────────────────────┘"<< endl;
    //cin.ignore();
    getline(cin,content);
    if (content.find_first_not_of(" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.,?!_") != std::string::npos)
    {
    std::cerr << "Error: message can't have special characters.\n\n";
    exit(0);
    }
    cout << " ┌──────────────────────────────────────────────────────┐"<< endl;
    cout << "  "+username+" Enter the receiver's name:" << endl;
    cout << " └──────────────────────────────────────────────────────┘"<< endl;
    cin >> to;
    if (to.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.,?!_") != std::string::npos)
    {
    std::cerr << "Error: receiver's name can't have special characters.\n\n";
    exit(0);
    }
    
    cout << " ┌──────────────────────────────────────────────────────┐"<< endl;
    cout << "  "+username+" Enter the shared key:" << endl;
    cout << " └──────────────────────────────────────────────────────┘"<< endl;
    cin >> password;
    if (password.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.,?!_") != std::string::npos)
    {
    std::cerr << "Error: Key can't have special characters.\n\n";
    exit(0);
    }
    
    transform(to.begin(), to.end(), to.begin(), ::tolower);
    
    string unameSquery="SELECT count(*) as count FROM users WHERE name='"+to+"';";
    char *sql1 = (char *)alloca(unameSquery.size() + 1);
    memcpy(sql1, unameSquery.c_str(), unameSquery.size() + 1);
    int i=search_in(sql1);
    
    if (i==0){
        cout<<"\nError: Sorry we couldn't find that username in our database. You can only send messages to a registed user."<<endl;
    
        app_menu(username);
    }
    else{

        iSalt=r_salt();
        sSalt=to_string(abs(iSalt));//default right now
        sSalt.substr (0,8);
        sSalt[8]='\n';
        hash_password=HexOfPass(password,stoi(sSalt));
        string passToStr=hex_to_string(hash_password);
        
        //##### DO THE ENCRYPT HERE
        encContent=encryptEmail(content, passToStr, sSalt);
        hexEncContent=string_to_hex(encContent);
        
        iquery="insert into EMAILS ('sname','rname','subject','body','spassword','salt','date') VALUES ('"+username+"','"+to+"','"+subject+"','"+hexEncContent+"','"+hash_password+"','"+sSalt+"',julianday('now','localtime'));";
        char *sql = (char *)alloca(iquery.size() + 1);
        memcpy(sql, iquery.c_str(), iquery.size() + 1);
        i=insert_query(sql);
        cout<<"("+username+" Your email has been sent to "+to+" !)\n"<<endl;
        app_menu(username);
        
    }
    }//while end
}
static void show_inbox(string username){
    string choice;
    int  page=0;
    vector<MyData> inData;
    string password;
    //SELECT id, sname ,rname  , subject ,body , spassword , date(date) as date,time(date) as time FROM emails WHERE sname='"+username+"';"
    string query="SELECT id, sname ,rname  , subject ,body , spassword ,salt , date(date) as date,time(date) as time FROM emails WHERE rname='"+username+"';";
    char *sql1 = (char *)alloca(query.size() + 1);
    memcpy(sql1, query.c_str(), query.size() + 1);
    inData=searchForEmails(sql1);
    while (1){
        


        cout << "║                          - INBOX -                            ║" << endl;
        cout << "╚═══════════════════════════════════════════════════════════════╝" << endl;
for (int index = 0; index < inData.size(); ++index)
{
    cout << (index+1)<<"- SUBJECT:"<<inData[index].subject<<"\tFROM:"<<inData[index].sname<<"\tDATE:"<<inData[index].date<<"\tTIME:"<<inData[index].stime<<endl; 
}
        
 
        cout << " ┌──────────────────────────────────────────────────────────────┐"<< endl;
        cout << " |Please enter the number of the message to read or E to exit   | "<< endl;
        cout << " └──────────────────────────────────────────────────────────────┘"<< endl;
        cin >> choice;
        
        if (all_of(choice.begin(), choice.end(), ::isdigit)){
            if((stoi(choice)<=inData.size()) && (stoi(choice)>0)){
                while(1){
                cout << " ┌──────────────────────────────────────────────────────┐"<< endl;
                cout << "  "+username+" please enter the shared key:" << endl;
                cout << " └──────────────────────────────────────────────────────┘"<< endl;
                cin >> password;
                if (password.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.,?!_") != std::string::npos){
                    std::cerr << "Error: encryption key can't have special characters.\n\n";
                    exit(0);
                }
                
                string saltTest=inData[stoi(choice)-1].salt;//default right now
                string passTest=inData[stoi(choice)-1].spassword;
                string hash_password=HexOfPass(password,stoi(saltTest));
                
      
                if(hash_password==passTest){
                    //Do decrypt
                    string passToStr=hex_to_string(hash_password);
                    string bodyEnc=inData[stoi(choice)-1].body;
                    string bodyDec=decryptEmail(hex_to_string(bodyEnc),passToStr,inData[stoi(choice)-1].salt);
                    
                    cout<<"\nSUBJECT:"<<inData[stoi(choice)-1].subject<<"\tTO:"<<inData[stoi(choice)-1].rname<<"\nDATE:"<<inData[stoi(choice)-1].date<<"\t\t\tTIME:"<<inData[stoi(choice)-1].stime<<endl; 
                    cout<<"\n\ncontent: \n"<<bodyDec<<"\n\n"<<endl;
                    app_menu(username);
                }
                else{
                    cout<<"Error: shared key is incorrect."<<endl;
                }
            }
            }
            else
                cout<<"Alert: Invalid message id."<<endl;
        }
        else if (isalpha(choice[0]) && choice== "E"){
            cout <<"._.o0o( Good bye! )o0o._."<<endl;
            exit(0);
            break;
        }

        else{
            cout << "Error: Enter a valid choice from th menu.\n\n" << endl;
        }
    }
}
static void show_outbox(string username){
    string choice;
    int  page=0;
    vector<MyData> inData;
    string password;
    //SELECT id, sname ,rname  , subject ,body , spassword , date(date) as date,time(date) as time FROM emails WHERE sname='"+username+"';"
    string query="SELECT id, sname ,rname  , subject ,body , spassword , salt, date(date) as date,time(date) as time FROM emails WHERE sname='"+username+"';";
    char *sql1 = (char *)alloca(query.size() + 1);
    memcpy(sql1, query.c_str(), query.size() + 1);
    inData=searchForEmails(sql1);
    while (1){
        


        cout << "║                          - OUTBOX -                           ║" << endl;
        cout << "╚═══════════════════════════════════════════════════════════════╝" << endl;
for (int index = 0; index < inData.size(); ++index)
{
    cout << (index+1)<<"- SUBJECT:"<<inData[index].subject<<"\tTO:"<<inData[index].rname<<"\tDATE:"<<inData[index].date<<"\tTIME:"<<inData[index].stime<<endl; 
}
        
  
        cout << " ┌──────────────────────────────────────────────────────────────┐"<< endl;
        cout << " |Please enter the number of the message to read or E to exit   | "<< endl;
        cout << " └──────────────────────────────────────────────────────────────┘"<< endl;
        cin >> choice;
        
       if (all_of(choice.begin(), choice.end(), ::isdigit)){
            if((stoi(choice)<=inData.size()) && (stoi(choice)>0)){
                
                while(1){
                cout << " ┌──────────────────────────────────────────────────────┐"<< endl;
                cout << "  "+username+" please enter the shared key:" << endl;
                cout << " └──────────────────────────────────────────────────────┘"<< endl;
                cin >> password;
                if (password.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.,?!_") != std::string::npos){
                    std::cerr << "Error: encryption key can't have special characters.\n\n";
                    exit(0);
                }
                
                string saltTest=inData[stoi(choice)-1].salt;//default right now
                string passTest=inData[stoi(choice)-1].spassword;
                string hash_password=HexOfPass(password,stoi(saltTest));
                
                //cout << "## the pass from the Function with the salt . => "<<hash_password<<endl;
                if(hash_password==passTest){
                    //Do decrypt
                    string passToStr=hex_to_string(hash_password);
                    string bodyEnc=inData[stoi(choice)-1].body;
                    string bodyDec=decryptEmail(hex_to_string(bodyEnc),passToStr,inData[stoi(choice)-1].salt);
                    
                    cout<<"\nSUBJECT:"<<inData[stoi(choice)-1].subject<<"\tFROM:"<<inData[stoi(choice)-1].sname<<"\nDATE:"<<inData[stoi(choice)-1].date<<"\t\t\tTIME:"<<inData[stoi(choice)-1].stime<<endl; 
                    cout<<"\n\ncontent: \n"<<bodyDec<<"\n\n"<<endl;
                    app_menu(username);
                }
                else{
                    cout<<"Error: shared key is incorrect."<<endl;
                }
                
                }
                
            }
            else
                cout<<"Alert: Invalid message id."<<endl;
        }
       else if (isalpha(choice[0]) && choice== "E"){
            cout <<"Good bye! "<<endl;
            exit(0);
            break;
        }
        
        else{
            cout << "Error: Enter a valid choice from th menu.\n\n" << endl;
        }
    }
}
static void registers(){
    string username="";
    string password="";
    string hash_password;
    string sSalt;
    int iSalt;
    string iquery;
    
     while (1){
    
    cout << "║                     - Register -                       ║" << endl;
 
    cout << " ┌──────────────────────────────────────────────────────┐"<< endl;
    cout << " |Please enter a username:                             |" << endl;
    cout << " └──────────────────────────────────────────────────────┘"<< endl;
    cin >> username;
    cout << " ┌──────────────────────────────────────────────────────┐"<< endl;
    cout << " |Please enter the password:                         |" << endl;
    cout << " └──────────────────────────────────────────────────────┘"<< endl;
    cin >> password;
    //converting to lowercase all usernames
    transform(username.begin(), username.end(), username.begin(),::tolower);
    if (username==""||password==""){
        cout<<"Error: username and password  can't be empty.\n\n"<<endl;
    }
    if(username.length()<6){
        cout<<"Error: username can't be less than 6 characters.\n\n"<<endl;
    }
    if (username.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890_") != std::string::npos)
    {
    std::cerr << "Error: username can't have special characters.\n\n";
    exit(0);
    }
    if(password.length()<6){
        cout<<"Error: password can't be less than 6 characters.\n\n"<<endl;
    }
    if (password.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890_") != std::string::npos)
    {
    std::cerr << "Error: password can't has special characters.\n\n";
    exit(0);
    }
    
    string unameSquery="SELECT count(*) as count FROM users WHERE name='"+username+"';";
    char *sql1 = (char *)alloca(unameSquery.size() + 1);
    memcpy(sql1, unameSquery.c_str(), unameSquery.size() + 1);
    int i=search_in(sql1);
    if (i>0){
            cout<<"Error: The username is already registered. Please pick another username."<<endl;
    }
  
    else{
         iSalt=r_salt();
         sSalt=to_string(abs(iSalt));//default right now
         hash_password=HexOfPass(password,iSalt);
         //cout<<salt<<endl;
         //password=hasedpass();
        //hash_password = hashed(password);
        iquery="insert into USERS ('name','password','salt')  values ('"+username+"','"+hash_password+"','"+sSalt+"');";
        char *sql = (char *)alloca(iquery.size() + 1);
        memcpy(sql, iquery.c_str(), iquery.size() + 1);
        i=insert_query(sql);
        cout<<"._.o0o(Thank you for signing up "+username+" !)o0o._."<<endl;
        menu();
        break;
    }
    }
   


    
}






static char * encryptDecrypt(char *input, char *key1) {
	int i=0;
	int len1 = strlen(input);
	int len2 = strlen(key1);
	char * result = (char*)malloc(len1);
	char * key = (char*)malloc(len2);
	for(i = 0; i< len2; i++){
	    if(key1[i]>='a' && key1[i]<='z'){
            key[i]=key1[i]-32;
        } else key[i] = key1[i];
	}
	for (i=0;i<len1;i++){
	    //printf("%c",key[i % len2]);
	    //printf("%c",input[i]);
	    result[i] = input[i] ^ key[i % len2];
	    //printf("%c",result[i]);
	}
	return result;
	free(result);
	free(key);
}


int main(){

    menu();
    return 0;
}
