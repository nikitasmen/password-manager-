
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

std::vector<int> taps= {0,3, 5};  // Taps for a 3-bit LFSR (x^3 + x^1 + 1)
std::vector<int> init_state = {1, 0,1};  // Initial state [1, 0, 0]

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
    private:
    std::vector<int> taps;
    std::vector<int> state;
    
public:
    Login(const std::vector<int>& taps, const std::vector<int>& init_state) {
        this->taps = taps;
        this->state = init_state;
    }
    
    std::string encrypt(const std::string& plaintext) {
        std::string encrypted;
        
        for (char c : plaintext) {
            int keystream_bit = state[0];  // Output the first bit of the LFSR state
            char encrypted_char = c ^ keystream_bit;  // XOR the character with the keystream bit
            
            encrypted.push_back(encrypted_char);
            
            int feedback_bit = 0;
            for (int tap : taps) {
                feedback_bit ^= state[tap];  // Calculate the feedback bit using the specified taps
            }
            
            state.pop_back();
            state.insert(state.begin(), feedback_bit);  // Shift the LFSR state to the left and insert the feedback bit at the beginning
        }
        
        return encrypted;
    }
    
    std::string decrypt(const std::string& encrypted_text) {
        return encrypt(encrypted_text);  // Decryption is the same as encryption
    }
    
};





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
    Login log(taps,init_state);

    int count = 0;
    bool done = false;
    string value , password , correct;

    if (std::filesystem::exists("enter.txt"))
    {
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
    }
    else 
    {
        string psw,psw2 ;
        int tries=0 ;
        cout<<"You are not registered yet\nEnter your Login password : \n";
        cin>>psw;
        if(psw!="\0")
        {
            do
            { 
                cout<<"Please enter again the password";
                cin>> psw2;
                if(psw2==psw)
                {
                    cout<<"hello";
                    psw= log.encrypt(psw);
                    std::ofstream enterf("enter.txt"); 
                    enterf << psw; 
                    enterf.close();
                    DWORD attributes = GetFileAttributes("enter.txt");
                    SetFileAttributes("enter.txt", attributes + FILE_ATTRIBUTE_HIDDEN);
                    done = true ; 
                    break ; 
                }
                else 
                {   
                    tries+=1 ;
                    cout<<"\n";
                }
            }while(tries<3 && psw2!=psw);
            cout<<"You are NOT registered yet";
        }

    }
    cout<<"\n";

    return done;
}

void change()
{
    Login dec(taps,init_state);

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


    Login data(taps,init_state);
    

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
    Login dec(taps,init_state) ;
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
        value = dec.encrypt(value);
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
    string path = "C:/Users/menou/Desktop/pass_man"; //enter path 

    for (const auto & file : directory_iterator(path))
    {
       
        cout << file<< endl;
    }
    system("pause");
}
