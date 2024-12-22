// Command & Control Interface (CCI) V1 Revision 1
// Author: hvictor
// Github: https://github.com/hvictor/osed

#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "cci.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    cci_exec();

    while (true)
    {
        Sleep(1000);
    }

    return 0;
}

