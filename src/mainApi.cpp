#include "cli/cli_api.h"
#include <iostream>
#include <exception>

/*
    options: 
            -h (help) //Show manual 
            -a (add) //Add password
            -s (show) //Retrun all records 
            -c (copy) //Return and copy record specified by platform's name 

    --Required 
            arg1 --userPassword 
            arg2 option 
            arg2-3 --values for option
*/

int main(int argc, char **argv){ 
    try {
        // The main functionality is implemented in cli_api.h
        return cli_main(argc, argv);
    } catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
