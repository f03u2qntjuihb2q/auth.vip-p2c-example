#include <iostream>
#include <conio.h>

#include "api/AuthVIP.hpp"
#include "XorStr.hpp"
#include "util.h"
#include "kdmapper/kdmapper.hpp"

/* All can be found in your panel */
AuthVIP::API AuthInstance("ProgramVersion", "ProgramKey", "APIKey");

std::string tm_to_readable_time(tm ctx) {
    char buffer[25];

    strftime(buffer, sizeof(buffer), "%m/%d/%y", &ctx);

    return std::string(buffer);
}
int initialization()
{
    /* ignore if you dont know what this is */

    bool free = false;
    bool mdlMode = false; // map in mdl (recommended however can cause issues)
    bool passAllocationPtr = false;

    util::Null();
    util::ColorTo(LIGHTCYAN);
    std::cout << xorstr("\n \n \n    [!] Prepairing the product \n");
    util::ColorTo(RED);
    std::cout << xorstr("\n    [!] Please wait\n");

    Sleep(2500);
    util::hide();

    /* Download your driver */
    std::vector<uint8_t> bytes = AuthInstance.file(xorstr("file name"));

    /* KDMAPPER https://github.com/TheCruZ/kdmapper */

    HANDLE iqvw64e_device_handle = intel_driver::Load();

    if (iqvw64e_device_handle == INVALID_HANDLE_VALUE)
    {
        util::Null();
        util::show();
        util::ColorTo(RED);
        std::cout << xorstr("\n    [!] Failed to create vulnerable driver. Error Code: 0x1455\n");
        Sleep(6000);
        exit(-1);
    }

    NTSTATUS exitCode = 0;
    if (!kdmapper::MapDriver(iqvw64e_device_handle, bytes.data(), 0, 0, free, true, mdlMode, passAllocationPtr, &exitCode)) {
        intel_driver::Unload(iqvw64e_device_handle); /* VERY IMPORTANT KEEP THIS*/

        util::Null();
        util::show();
        util::ColorTo(RED);
        std::cout << xorstr("\n    [!] Failed to start driver. Error Code: 0x1465\n");
        Sleep(6000);
        exit(-1);
        return -1;
    }

    /* VERY IMPORTANT KEEP THIS*/
    intel_driver::Unload(iqvw64e_device_handle); 

    util::show();

    /* Call cheat main */
    util::ColorTo(GREEN);
    std::cout << xorstr("\n    [!] Rest is all you, make sure to join https://discord.gg/authvip if you need any help. \n");
    Sleep(-1);

    return 0;
}
int main() {
    int option = 0;

    std::string user{}, email{}, pass{}, token{};

    /* Change Console Text*/
    util::ColorTo(LIGHTCYAN); 

    /* IMPORTANT: DO NOT DELETE THIS */
    AuthInstance.Initialize();

   std::cout << xorstr("\n \n \n    [+] License: ");
   std::cin >> token;

   if (AuthInstance.AllInOne(token)) {
       util::Null();
       util::ColorTo(GREEN);
       std::cout << xorstr("\n \n \n    [!] Log in successful, Key Expiry: ");
       std::cout << tm_to_readable_time(AuthInstance.user_data.expires) << std::endl;
       Sleep(3000);
       initialization();

   }
   else {
       util::ColorTo(RED);
       std::cout << xorstr(" \n    [-] Something went wrong a reason shouldve been provided. Exiting!") << std::endl;
       Sleep(5000);
       exit(-1);
   }

    return 0;
}