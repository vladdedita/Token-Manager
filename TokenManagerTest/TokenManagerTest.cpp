// TokenManagerTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "TokenManagerLibrary.h"

int main()
{
	incarcaLibrarie("eTPKCS11.dll");
	asteaptaToken();
	getchar();
	return 0;
}

