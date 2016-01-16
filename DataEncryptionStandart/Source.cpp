#pragma once

#include "Headers.h"
#include "MD4.h"
#include "DES.h"
#include <string>

void ListFiles(vector<string> &files, vector<string> &folders, string source)  {
	// Маска файлов
	WIN32_FIND_DATA ffd;
	memset( &ffd, 0, sizeof(WIN32_FIND_DATA) );
	HANDLE hFind = FindFirstFile((source + "\\*.*").c_str(), &ffd); 	
	if (INVALID_HANDLE_VALUE == hFind) return;   
	// Получаем информацию о всех файлах и папках
	do
	{
		// Пропускаем служебные папки ".", ".."
		if(strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) continue;
		// Если директория
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			// Заносим в список папок
			string dirPath( ffd.cFileName );
			folders.push_back( source + "\\" + dirPath );
			// Вызываемся рекурсивно для найденной папки
			ListFiles( files, folders, source + "\\" + dirPath );
		}
		// Иначе это файл
		else
		{
			// Заносим в список файлов
			files.push_back( source + "\\" + ffd.cFileName );
		}
	}
	// Двигаем к след. файлу
	while (FindNextFile(hFind, &ffd) != 0);
	// Закрываем идентификатор перечислителя 
	FindClose(hFind);
}

int main(int argc, char *argv[]) {
	setlocale(LC_ALL, "Russian");

	cout << "1.   Encrypt" << endl;
	cout << "2.   Decrypt" << endl;
	cout << "ESC. Exit"	<< endl;

	char choice = _getch();
	string input	= "";
	string key		= "";
	string IV		= "Синхропосылка, Вектор Инициализации IV";	
	// Режим шифрования
	if(choice == '1') {
		cout << "[Encryption]" << endl;
		cout << "InputPath: ";
		SetConsoleCP(1251);//временно меняем кодировку ввода            
		getline(cin, input);
		SetConsoleCP(866);
		cin.clear();
		cin.sync();
		// Получаем информацию о файле/директории
		WIN32_FIND_DATAA FileInformation;
		ZeroMemory( &FileInformation, sizeof(FileInformation) );
		HANDLE hFile = FindFirstFile(input.c_str(), &FileInformation); 
		FindClose(hFile);
		// Если информация получена успешно
		if(hFile == INVALID_HANDLE_VALUE) {
			cout << "File [" << input << "] not found." << endl;
			return -1;
		}
		cout << "Key: ";
		SetConsoleCP(1251);//временно меняем кодировку ввода            
		getline(cin, key);
		SetConsoleCP(866);
		cin.clear();
		cin.sync();
		// Создаем объект для работы с DES
		DES des( key, IV, input );
		// Выводим параметры
		cout << des << endl;
		// Проверяем передан файл или директория 
		if(FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			bool success = true;
			// Получаем список всех директорий и файлов
			vector<string> files, folders;
			ListFiles(files, folders, input);
			// Выводим информацию о количестве найденных файлов и каталогов
			cout << "[Folder encryption]"	<< endl;
			cout << "Total files: "		<< files.size()		<< endl;
			cout << "Total folders: "		<< folders.size()	<< endl;
			// Делаем замер времени
			clock_t start = clock();			
			// Шифруем корневой каталог в файл без режима "дозапись"
			des.Encrypt(input, false);
			// Шифруем все каталоги ( Запись в файл в режиме "добавление" )
			for(size_t i = 0; i < folders.size() && success; ++i) {
				cout << "-----------------------------------" << endl;
				cout << "Process folder=" << folders[i] << endl;
				
				success = des.Encrypt( folders[i] );
			}
			// Шифруем все файлы ( Запись в файл в режиме "добавление" )
			for(size_t i = 0; i < files.size() && success; ++i) {
				cout << "-----------------------------------" << endl;
				cout << "Process file=" << files[i] << endl;
				success = des.Encrypt( files[i] );
			}
			// Успешно зашифровали ?
			if(success) {
				// Покажем затраченное время 
				cout << "Elapsed time=" << double(clock() - start) / CLOCKS_PER_SEC << endl;
			} else {
				cout << "=================================" << endl;
				cout << "Encrypt [" << input << "] folder failure." << endl;
			}
		}
		else  {
			cout << "[File encryption]"	<< endl;
			// Замеряем время шифрования
			clock_t start = clock();
			// Шифруем без режима "добавление"
			if(!des.Encrypt(input, false)) {
				cout << "Encrypt failure" << endl;
			} else {
				cout << "Encrypt successful" << endl;
				// Покажем затраченное время 
				cout << "=================================" << endl;
				cout << "Elapsed time=" << double(clock() - start) / CLOCKS_PER_SEC << endl;
			}			
		}
		
	}
	// Режим расшифровки
	else if(choice == '2') {
		cout << "[Decryption]" << endl;
		cout << "InputPath: ";
		SetConsoleCP(1251);//временно меняем кодировку ввода            
		getline(cin, input);
		SetConsoleCP(866);
		cin.clear();
		cin.sync();
		// Получаем информацию о файле
		WIN32_FIND_DATA FileInformation;
		ZeroMemory( &FileInformation, sizeof(FileInformation) );
		HANDLE hFile = FindFirstFile(input.c_str(), &FileInformation); 
		FindClose(hFile);
		// Если информация получена успешно
		if(hFile == INVALID_HANDLE_VALUE) {
			cout << "File [" << input << "] not found." << endl;
			return -1;
		}
		// Читаем ключ
		cout << "Key: ";
		SetConsoleCP(1251);//временно меняем кодировку ввода            
		getline(cin, key);
		SetConsoleCP(866);
		cin.clear();
		cin.sync();
		// Создаем объект для работы с DES
		DES des(key, IV, input);
		// Выводим параметры
		cout << des << endl;
		// Делаем замер времени
		clock_t start = clock();
		// Шифруем
		if(!des.Decrypt(input) ) {
			cout << "Decrypt failure" << endl;
		} else {
			cout << "Decrypt successful" << endl;
			cout << "=================================" << endl;
			cout << "Elapsed time=" << double(clock() - start) / CLOCKS_PER_SEC << endl;
		}
	}
	system("pause");
	return 0;
}