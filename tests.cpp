#include <string>
#include <iostream>
#include <cstdlib>
#include <windows.h>
#include <cstring>
#include <locale>
#include <clocale>
#include <fstream>
#include <vector>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <direct.h>
#include <cmath>
#include <stdio.h>
#include <cstdio>

using namespace std ;
using std::filesystem::directory_iterator;



///function definetion

	//function for entering the password manager
	bool login();

	//function to show the main menu choises
	int menu();
		//change function changes the password for the login
		void change();
		//add function adds one more platform's data (platform's name , platform's username , platform's password)
		void add();
		//del function deletes a specified row(platform's data) if that exists
		void del();
		//show function shows all the platform's and their data
		void show();
		//copy function asks for a platform's name and shows it's own data and copies password on clipboard
		void copy();


///end of function declaration
class Login
{
public:
	string encrypt(string s);
	string decrypt(string s);
};

        ///string encryption
        string Login::encrypt(string s)
        {
                int l = s.length();
            int b = ceil(sqrt(l));
            int a = floor(sqrt(l));
            string encrypted;
            if (b * a < l) {
                if (min(b, a) == b) {
                    b = b + 1;
                }
                else {
                    a = a + 1;
                }
            }

            // Matrix to generate the
            // Encrypted String
            char arr[a][b];
            memset(arr, ' ', sizeof(arr));
            int k = 0;

            // Fill the matrix row-wise
            for (int j = 0; j < a; j++) {
                for (int i = 0; i < b; i++) {
                    if (k < l){
                        arr[j][i] = s[k];
                    }
                    k++;
                }
            }

            // Loop to generate
            // encrypted string
            for (int j = 0; j < b; j++) {
                for (int i = 0; i < a; i++) {
                    encrypted = encrypted +
                                arr[i][j];
                }
            }
            return encrypted;
        }

        ///string decryption
        string Login::decrypt(string s)
        {
            int l = s.length();
            int b = ceil(sqrt(l));
            int a = floor(sqrt(l));
            string decrypted;
        
            // Matrix to generate the
            // Encrypted String
            char arr[a][b];
            memset(arr, ' ', sizeof(arr));
            int k = 0;
            
            // Fill the matrix column-wise
            for (int j = 0; j < b; j++) {
                for (int i = 0; i < a; i++) {
                    if (k < l){
                        arr[j][i] = s[k];
                    }
                    k++;
                }
            }
        
            // Loop to generate
            // decrypted string
            for (int j = 0; j < a; j++) {
                for (int i = 0; i < b; i++) {
                    decrypted = decrypted +
                                arr[i][j];
                }
            }
            return decrypted;
        }




int main(int argc , char* argv[])
{
	if (login())
	{

	    int menu_choise ;
        cout<<"Welcome!!!\n\n";
        menu_choise = menu();
        do
        {
            switch (menu_choise)
            {
            	case 1 :
            		change();
            		break;
            	case 2 :

            		add();
             		break;
            	case 3 :
            		copy();
            		break;
            	case 4 :
					del();
					break ;
				case 5 :
					show();
					break;

			}
			system("CLS");
            menu_choise = menu();

        }while (menu_choise!=0);

	}
    system("pause");
	system("CLS");
	return 0;
}


int menu()
{
	int choise ;
    cout <<"1) Change login password\n\n2)Add username/password\n\n3)Copy username/password to clipboard\n\n4)Delete username/password\n\n5)Show all\n\nEnter 0 to exit\n\n:: ";
    cin>>choise;
    return choise ;
}

bool login()
{
    Login log;

    int count = 0;
    bool done = false;
    string value , password , correct;

    fstream fin ; 
    fin.open("enter.txt");

    ///decryption of text of the file with the login password
    getline(fin,value);
    
    do
    {
        cout<<"Enter login password";
        cin>>password;
        
        correct = log.decrypt(value);
        correct.erase(remove(correct.begin(),correct.end(),' '),correct.end());
        
        if(password.compare(correct)==0)
        {
            done = true ;
            count = 4 ;
        }
        else 
        {
            cout<<"Wrong password\nTry again\n";
            count+=1;
        }
    }while(count<3);

    fin.close();
    return done;
}

void change()
{
    Login dec;

    string value;

    fstream fin;
    cin >>value;
    cout<<"Enter the new login pasword\nPress 0 to exit";
    if (value!= "0")
        {
            fstream fin;
            ///empty the login password file 
            fin.open("enter.txt", std::ofstream::out | std::ofstream::trunc);
            value = dec.encrypt(value);
            fin<<value;
            fin.close();
        }

    fin.close();

}

void add()
{


    Login data;
    

    string name, check , username, password;

    cout<<"Enter platform's name";
    cin>> name;
    check = name; 
    check+=".txt"; 
    if (std::filesystem::exists(check))
    {
        cout <<"File exists";
        cout<< "Unable to create this new file";
         
    }
    else if (name!= "0")
    {
        cout<<"Enter platform's username";
        cin>> username;
        cout<<"Enter platform's password"; 
        cin>> password;
        
        username = data.encrypt(username);
        password = data.encrypt(password);
        std::ofstream {name+".txt"};
        fstream fin;
        fin.open(name+".txt");
        fin<<username<<"\n"<<password;
        
        fin.close();
        name = name+".txt";

        int n = name.length();
            char nam[n+1];
            strcpy(nam,name.c_str());
        
        DWORD attributes = GetFileAttributes(nam);
        SetFileAttributes(nam, attributes + FILE_ATTRIBUTE_HIDDEN);
    }
}

void del()
{
    ifstream fin ;

    string name;
    int done;

    cout<<"Enter platform's name you want to delete";
    cin>>name;
    name = name+".txt";
    ///check if file exists
    fin.open(name);
    if(fin)
    {
        fin.close();
        ///convert file's name string to char array
        int n = name.length();
        char page[n+1];
        strcpy(page,name.c_str());

        remove(page);
        cout<<"Record Deleted";
    }
    else 
    {
        fin.close();
        cout<<"Record does not exist";
    }

}

void copy()
{
    Login dec ;
    ifstream fin ;
    fstream fout ;

    string name , value;
    char char_array;
    cout<<"Enter platform's name you want to copy";
    cin>>name;

    ///check if file exists
    fin.open(name+".txt");
    if(fin)
    {   
        fin.close();
        fout.open(name+".txt");
        while(getline(fout,value))
        {
            ///get value from text file
            /// first show it to user and then copy it to clipboard 
            value = dec.decrypt(value);
            cout<<value<<"\n";
            
            ///convert text's record string to char array in order to copy it to clipboard
            int n = value.length();
            char char_array[n+1];
            strcpy(char_array,value.c_str());

            ///copy text value to the clipboard 
            HGLOBAL global = GlobalAlloc(GMEM_FIXED,strlen(char_array) + 1); //text size + \0 character
            memcpy(global,char_array,strlen(char_array));  //text size + \0 character
            if (OpenClipboard(NULL))
                {            
                    EmptyClipboard();
                    SetClipboardData(CF_TEXT,global);
                    CloseClipboard();   
                }
        }
    }
    else 
    {
        fin.close();
        cout<<"Record does not exist";
    }
    system("pause");
}


void show()
{
    string path = ""; //enter path 

    for (const auto & file : directory_iterator(path))
    {
       
        cout << file<< endl;
    }
    system("pause");
}