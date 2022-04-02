#pragma once
#include <windows.h>
#include <string>
#include <ctime>
#include <vector>


#define BLACK 0
#define BLUE 1
#define GREEN 2
#define CYAN 3
#define RED 4
#define MAGENTA 5
#define BROWN 6
#define LIGHTGRAY 7
#define DARKGRAY 8
#define LIGHTBLUE 9
#define LIGHTGREEN 10
#define LIGHTCYAN 11
#define LUGHTRED 12
#define LIGHTMAGENTA 13
#define YELLOW 14
#define WHITE 15

namespace util
{

    void ColorTo(unsigned short color)
    {
        HANDLE con = 0;
        con = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(con, color);
    }
	void Null()
	{
		COORD topLeft = { 0, 0 };
		HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
		CONSOLE_SCREEN_BUFFER_INFO screen;
		DWORD written;
		GetConsoleScreenBufferInfo(console, &screen);
		FillConsoleOutputCharacterA(console, ' ', screen.dwSize.X * screen.dwSize.Y, topLeft, &written);
		FillConsoleOutputAttribute(console, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE, screen.dwSize.X * screen.dwSize.Y, topLeft, &written);
		SetConsoleCursorPosition(console, topLeft);
		return;
	}
	void show()
	{
		ShowWindow(GetConsoleWindow(), SW_SHOW);
	}
	void hide()
	{
		ShowWindow(GetConsoleWindow(), SW_HIDE);
	}
}
