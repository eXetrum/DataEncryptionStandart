#pragma once

#include "Headers.h"

class DES {
private:
	////////////////////////////////////////////////////////////////////////////
	// Размер блока	входных/выходных данных
	static const size_t BLOCK_SIZE = 64;
	// Размер половины блока
	static const size_t HALF_BLOCK_SIZE = 32;
	// Количество раундов
	static const size_t ROUND_SIZE = 16;
	// Размер начальных векторов используемых в формировании раундовых ключей
	static const size_t VEC_C0_D0_SIZE = 28;
	// Размер раундового ключа
	static const size_t ROUND_KEY_SIZE = 48;
	// Размер вектора после расширения (Ri)
	static const size_t EXPAND_VEC_SIZE = 48;
	// Размеры таблицы S преобразований
	static const size_t S_ROWS = 4;
	static const size_t S_COLS = 16;
	static const size_t S_BLOCKS = 8;
	// Размер в байтах файлового заголовка
	static const size_t HEADER_SIZE = 280;
	// Размер в байтах имени файла или имени дирректории
	static const size_t FILE_NAME_SIZE = 264;	
	////////////////////////////////////////////////////////////////////////////
	// Начальная таблица перестановки
	static const size_t IP[];
	// Начальные таблицы для векторов участвующих в формировании раундовых ключей	
	static const size_t VEC_C0[];
	static const size_t VEC_D0[];
	// Таблица свдигов расширенного ключа
	static const size_t ROUND_KEY_SHIFT[];
	// Таблица для получения раундовых ключей
	static const size_t ROUND_KEY_MASK[];
	// Таблица расширения Ri части блока в функции преобразований Фейстеля
	static const size_t E[];
	// Таблица для S преобразований
	static const size_t S[];
	// P перестановка
	static const size_t P[]; 
	// Таблица конечной перестановки
	static const size_t invIP[];
	////////////////////////////////////////////////////////////////////////////
	// 64 битный ключ 
	bitset<BLOCK_SIZE> Key;
	// 64 битный инициализирующий вектор
	bitset<BLOCK_SIZE> IV;
	// Сюда сохраним раундовые ключи
	bitset<ROUND_KEY_SIZE> Keys[ROUND_SIZE]; 
	// Путь куда сохраняем выходной файл
	string savedToFolder;
	// Имя выходного файла
	string outputFileName;
	////////////////////////////////////////////////////////////////////////////
	// Файловый заголовок
	struct FileHeader {
		// 264 байт => Имя файла относительно корневого каталога
		byte filename[FILE_NAME_SIZE];
		// 8 байт	=> Размер файла (заголовок не входит)
		byte fileSize[8];
		// и завершающий блок в 8 байт, предпоследний байт - тип файла, и последний байт - количество байт выравнивания
		byte paddingBlock[8];	
		// Итого: 264 + 8 + 8 = 280 байт заголовок
	};
	// Тип файла: файл, каталог, или не найден
	enum EntryType {
		NOTFOUND  = -1,
		FILE	  =  0,
		DIRECTORY =  1
	};
	////////////////////////////////////////////////////////////////////////////
	// Служебные функции
	////////////////////////////////////////////////////////////////////////////
	// Сжимающая хеш функция для получения 64 битного ключа 
	long64 quickhash64(const char *str, long64 mix = 0)
	{
		const long64 mulp = 2654435789;

		mix ^= 104395301;

		while(str && *str)
			mix += (*str++ * mulp) ^ (mix >> 23);

		return mix ^ (mix << 37);
	}
	unsigned int HashRot13(const char * str)
	{
		unsigned int hash = 0;

		for(; *str; str++)
		{
			hash += (byte)(*str);
			hash -= (hash << 13) | (hash >> 19);
		}

		return hash;
	}
	long64 Md4Hash(string message) {
		MD4 md4;
		// 128 бит
		byte raw[16];
		memset(&raw[0], 0, sizeof(byte) * 16);
		// Получаем Md4 хеш
		cout << "Message :" << message << endl;
		cout << "MD4 hash:" << md4.GetHash(message, raw) << endl;
		// Выделяем старшые и младшие 64 бит
		bitset<BLOCK_SIZE> LOW, HI;
		MakeBlock(&raw[0], LOW);
		MakeBlock(&raw[8], HI);
		// Затем применяем к половинкам операцию XOR для сжатия 128 -> 64
		return LOW.to_ullong() ^ HI.to_ullong();
	}
	// Циклический сдвиг
	template <std::size_t N> 
	inline void 
		rotate(std::bitset<N>& b, unsigned m) 
	{ 
		m %= N;
		b = b << m | b >> (N-m); 
	}
	// Формируем 64 битный блок из массива байт
	inline void MakeBlock(byte *chunk, bitset<64> &block)
	{
		 block = static_cast<long64>(chunk[0])
			| static_cast<long64> (chunk[1]) << 8
			| static_cast<long64> (chunk[2]) << 16
			| static_cast<long64> (chunk[3]) << 24
			| static_cast<long64> (chunk[4]) << 32
			| static_cast<long64> (chunk[5]) << 40
			| static_cast<long64> (chunk[6]) << 48
			| static_cast<long64> (chunk[7]) << 56;
	}
	// Выбираем куски по 8 бит из 64 битного блока	
	inline void MakeChunk(bitset<64> &block, byte *chunk) 
	{
		long64 b = block.to_ullong();
		long64 mask = 255;

		for(size_t i = 0; i < 8; ++i) {
			chunk[i] = static_cast<byte>( ( b & ( mask << (8 * i) ) ) >> ( 8 * i ) );
		}
	}
	// Инициализация раундовых ключей
	void Initialize() {
		/////////////////////////////////////////////////
		// Формируем раундовые ключи
		/////////////////////////////////////////////////
		// Создаем копию ключа
		bitset<BLOCK_SIZE> ExpandedKey(Key.to_ullong());
		// Проверяем чтобы каждый байт ключа содержал нечетное количество единиц
		size_t bitCount = 0;
		for(size_t i = 0; i < BLOCK_SIZE; ++i) {
			if(ExpandedKey[i]) ++bitCount;
			if((i + 1) % 8 == 0) {
				bitCount -= ExpandedKey[i];
				ExpandedKey.set(i, bitCount % 2 == 0);
				bitCount = 0;
				continue;
			}
		}
		// Формируем начальные векторы
		bitset<VEC_C0_D0_SIZE> C0(0), D0(0);
		for(size_t i = 0; i < VEC_C0_D0_SIZE; ++i) {
			C0[i] = ExpandedKey[VEC_C0[i] - 1];
			D0[i] = ExpandedKey[VEC_D0[i] - 1];
		}		
		// Формируем 16 раундовых ключей
		for(size_t i = 0; i < ROUND_SIZE; ++i) {
			// Делаем левый циклический сдвиг для векторов Ci, Di согласно таблице
			rotate(C0, ROUND_KEY_SHIFT[i]);
			rotate(D0, ROUND_KEY_SHIFT[i]);
			// Объединяем полученные векторы			
			bitset<VEC_C0_D0_SIZE * 2> C0D0( (C0.to_ullong() << VEC_C0_D0_SIZE) | D0.to_ullong());
			// Формируем ключ i раунда выбирая из полученного объединенного вектора биты используя таблицу
			bitset<ROUND_KEY_SIZE> k;
			for(size_t j = 0; j < ROUND_KEY_SIZE; ++j)
				k[j] = C0D0[ROUND_KEY_MASK[j] - 1];
			// Сохраняем ключ
			Keys[i] = k;
		}
	}
	// Шифрование блока
	inline void EncryptBlock(bitset<BLOCK_SIZE> &block) {		 
		/////////////////////////////////////////////////
		// Начальная перестановка
		/////////////////////////////////////////////////
		// Результирующий блок после применения начальной перестановки
		bitset<BLOCK_SIZE> temp( block );
		// Используя таблицу производим начальную перестановку
		for(size_t i = 0; i < BLOCK_SIZE; ++i) {
			// Берем индекс (номер бита - 1) из таблицы начальной перестановки 
			// Достаем из переданного блока нужный бит и выставляем в результирующий блок
			block.set(i, temp[ IP[i] - 1 ]);
		}
		/////////////////////////////////////////////////
		// Циклы шифрования (16 раундов преобразования Фейстеля)
		/////////////////////////////////////////////////
		// Разбиваем блок полученный после начальной перестановки
		// на два 32 битных блока L0 - старшая часть, R0 - младшая
		long64 mask = 4294967295L;
		long64 b = block.to_ullong();
		long64 L0 = (b & (mask << 32) ) >> 32;
		long64 R0 = b & mask;
		// Текущее и предыдущие значения половинок
		long64 Li, Ri, Li_prev( R0 ), Ri_prev( L0 );
		// 16 раундов
		for(size_t i = 0; i < ROUND_SIZE; ++i) {
			Li = Ri_prev;
			Ri = Li_prev ^ f(Ri_prev, Keys[i]);
			// Запоминаем предыдущие значения
			Li_prev = Li;
			Ri_prev = Ri;
		}
		// Объединяем половинки полученных 32 битных векторов после 16 раундов преобразований
		bitset<BLOCK_SIZE> L16R16 ( (Li << 32) | Ri );
		// Производим обратную перестановку
		for(size_t i = 0; i < BLOCK_SIZE; ++i) {
			block.set(i, L16R16[ invIP[i] - 1 ]);
		}
	}

	inline bitset<BLOCK_SIZE> DecryptBlock(bitset<BLOCK_SIZE> &block) { 
		/////////////////////////////////////////////////
		// Начальная перестановка
		/////////////////////////////////////////////////
		// Результирующий блок после применения начальной перестановки
		bitset<BLOCK_SIZE> IPblock;
		// Используя таблицу производим начальную перестановку
		for(size_t i = 0; i < BLOCK_SIZE; ++i) {
			// Берем индекс (номер бита - 1) из таблицы начальной перестановки 
			// Достаем из переданного блока нужный бит и выставляем в результирующий блок
			IPblock.set(i, block[IP[i] - 1]);
		}
		/////////////////////////////////////////////////
		// Циклы шифрования (16 раундов преобразования Фейстеля)
		/////////////////////////////////////////////////
		// Разбиваем блок полученный после начальной перестановки
		// на два 32 битных блока L0 - старшая часть, R0 - младшая
		bitset<HALF_BLOCK_SIZE> L0, R0;
		for(size_t i = 0; i < HALF_BLOCK_SIZE; ++i) {
			L0.set(i, IPblock[i + HALF_BLOCK_SIZE]);
			R0.set(i, IPblock[i]);
		}
		// Текущее и предыдущие значения половинок
		long64 Li, Li_prev, Ri, Ri_prev;
		Li_prev = R0.to_ullong();
		Ri_prev = L0.to_ullong();
		// Применяем ключи в обратном порядке
		for(int i = ROUND_SIZE - 1; i >= 0; --i) {
			// 
			Li = Ri_prev;
			Ri = Li_prev ^ f(Ri_prev, Keys[i]);
			// 
			Li_prev = Li;
			Ri_prev = Ri;
		}
		// Объединяем половинки полученных 32 битных векторов после 16 раундов преобразований
		bitset<BLOCK_SIZE> L16R16 ( (Li << 32) | Ri );
		// Производим обратную перестановку
		bitset<BLOCK_SIZE> invIPblock;
		for(size_t i = 0; i < BLOCK_SIZE; ++i) {
			invIPblock.set(i, L16R16[ invIP[i] - 1 ]);
		}

		return invIPblock;
	}

	inline long64 f(long64 &ri, bitset<ROUND_KEY_SIZE> &Ki) {
		bitset<HALF_BLOCK_SIZE> Ri(ri);
		bitset<EXPAND_VEC_SIZE> exRi(0);
		// Расширяем 32 битный Ri вектор до 48 бит
		for(size_t i = 0; i < EXPAND_VEC_SIZE; ++i) {
			exRi.set(i, Ri[ E[i] - 1 ]);
		}
		// Xor с текущим раундовым ключем
		exRi = exRi ^ Ki;
		// Представляем расширенный вектор exRi в виде восьми блоков по 6 бит каждый
		long64 bb = exRi.to_ullong();
		long64 chunk[8] = {0};
		long64 mask = 63;
		for(size_t i = 0; i < 8; ++i) {
			chunk[i] = static_cast<byte>( ( bb & ( mask << (6 * i) ) ) >> ( 6 * i ) );
		}
		// Трансформируем 6 битные блоки в 4 битные и используем S преобразования
		long64 Bj[8] = {0};
		for(size_t i = 0; i < 8; ++i) {
			size_t a, b;
			a = ( (chunk[i] & 32) >> 4) | (chunk[i] & 1);
			b = ( (chunk[i] & 16) >> 1) | ((chunk[i] & 8) >> 1) | ((chunk[i] & 4) >> 1) | ((chunk[i] & 2) >> 1);
			// Получаем данные из Si блока по координатам (a, b)
			Bj[i] = S[S_BLOCKS * i + a * S_COLS + b];
		}
		// Объединяем 4 битные блоки в один 32 битный
		bitset<HALF_BLOCK_SIZE> Bj_union
		(
			(Bj[0] << 28)
			| (Bj[1] << 24)
			| (Bj[2] << 20)
			| (Bj[3] << 16)
			| (Bj[4] << 12)
			| (Bj[5] << 8)
			| (Bj[6] << 4)
			| Bj[7]
		);
		// P Перестановка
		bitset<HALF_BLOCK_SIZE> result(0);
		for(size_t i = 0; i < HALF_BLOCK_SIZE; ++i) {
			result.set(i, Bj_union[P[i] - 1]);
		}

		return result.to_ullong();
	}

public:
	// Конструктор
	DES(string Key, string IV, string rootFolder) {
		srand((unsigned)time(0));
		// Получаем хеш ключа и сохраняем в битовый массив
		this->Key = bitset<BLOCK_SIZE>( Md4Hash( Key.c_str() ) );
		// Получаем хеш вектора инициализации
		this->IV  = bitset<BLOCK_SIZE>( Md4Hash( IV .c_str() ) );
		// Запоминаем путь к корневому каталогу в котором обрабатываем файл(ы)
		this->savedToFolder = GetParentFolder( rootFolder );
		// Имя обрабатываемого каталога/файла
		this->outputFileName = GetFilename( rootFolder );
		// Инициализация раундовых ключей
		Initialize();
	}
	// Метод получения размера файла
	std::streampos fileSize( string &filePath ){
		std::streampos fsize = 0;
		// Открываем файл на чтение
		std::ifstream file( filePath, std::ios::binary );
		// Получаем значение файлового указателя (только открылия файл - значение будет равно 0,
		fsize = file.tellg();
		// Передвигаем файловый указатель в конец
		file.seekg( 0, std::ios::end );
		// Получаем размер файла как разность между начальным значением указателя и текущим
		fsize = file.tellg() - fsize;
		// Не забываем закрыть файл
		file.close();
		// Вернем размер
		return fsize;
	}
	// Используя переданный путь к файлу/папке определяем с чем работаем: каталог или файл, и есть ли  что либо по указанному пути или там пусто
	EntryType CheckEntry(string filename) {
		WIN32_FIND_DATA FileInformation;
		ZeroMemory(&FileInformation, sizeof(FileInformation) );
		// Получаем информацию о файле в структуру
		HANDLE hFile = FindFirstFile(filename.c_str(), &FileInformation); 
		// Закрываем перечислитель
		FindClose(hFile);
		// Вернем тип с которым работаем
		if(hFile != INVALID_HANDLE_VALUE) {
			if(FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				return EntryType::DIRECTORY;
			else 
				return EntryType::FILE;
		} else {	
			return EntryType::NOTFOUND;
		}
	}
	// Вырезаем имя файла/каталога из переданного пути
	string GetFilename (const string &path) {
		size_t found = path.find_last_of("/\\");
		return path.substr(found + 1);
	}
	// Построить путь из каталогов
	bool CreatePath(std::string &wsPath)
	{
		DWORD attr;
		int pos;
		bool result = true;
		// Получаем позицию последго обратного слеша
		pos = wsPath.find_last_of("\\");
		if (wsPath.length() == pos + 1)
		{
			// Отсекаем лишнее
			wsPath.resize(pos);
		}
		// Получаем атрибуты каталога		
		attr = GetFileAttributes(wsPath.c_str());
		// Проверим существует ли каталог
		// Если нет - создаем каталог
		if (0xFFFFFFFF == attr)
		{
			pos = wsPath.find_last_of("\\");
			if (0 < pos)
			{
				// Вызываемся рекурсивно для подпути
				result = CreatePath(wsPath.substr(0, pos));
			}
			// Создаем новый каталог
			result = result && CreateDirectoryA(wsPath.c_str(), 0);
		}
		// Объект уже существует и атибут говорит что это не каталог
		else if (FILE_ATTRIBUTE_DIRECTORY != attr)
		{	
			SetLastError(ERROR_FILE_EXISTS);
			// Результат не удачен
			result = false;
		}
		return result;
	}
	// Получить из переданного пути родительский каталог (на уровень выше)
	string GetParentFolder( string & path ) {
		string name = GetFilename( path );
		return path.substr(0, path.find( name ) );
	}
	// Метод шифрования: inputFile - путь к файлу/каталогу, append - режим работы, добавления или создание нового файла
	bool Encrypt(string &inputFile, bool append = true) {
		// Начальный вектор инициализации
		static bitset<BLOCK_SIZE> Ci = IV;
		// Определяем тип: файл или директория
		EntryType entryType = CheckEntry(inputFile);
		// Проверяем размер имени файла и тип файла
		if(inputFile.size() > FILE_NAME_SIZE || entryType == EntryType::NOTFOUND) return false;
		// Получаем размер файла
		size_t len = (size_t)fileSize(inputFile);
		// Создаем заголовок
		FileHeader fh;
		// Обнуляем поля
		memset(&fh, 0, sizeof(FileHeader));
		// Если обрабатываем директорию
		if(entryType == EntryType::DIRECTORY) {			
			// Отделяем имя директории и собираем путь используя путь корневого каталога
			string relative = inputFile;
			if(relative.find(savedToFolder) == string::npos) return false;
			relative = "\\" + relative.substr( savedToFolder.size() );
			// Копируем имя директории
			memcpy(&fh.filename, relative.c_str(), sizeof(byte) * relative.size());
			// Заносим данные о размере файла
			bitset<BLOCK_SIZE> size( len );
			MakeChunk(size, fh.fileSize);// = len;
			// Блок выравнивания заполняем мусором
			for(size_t i = 0; i < 8; ++i)
				fh.paddingBlock[i] = rand() % 256;
			// Последние два байта важны
			fh.paddingBlock[6] = 1; // Тип файла: директория
			fh.paddingBlock[7] = 0; // Количествло байт выравнивания
			// Выделяем память для буфера
			byte *buff = new byte[HEADER_SIZE];
			// Обнуляем буфер
			memset( buff, 0, sizeof(byte) * HEADER_SIZE ); 
			// Заносим файловый заголовок
			memcpy( buff, &fh, sizeof(FileHeader));
			/////////////////////////////////////////////
			// Шифруем буфер
			/////////////////////////////////////////////			
			bitset<64> block(0);
			// Шифруем последовательно блоки
			for(size_t idx = 0; idx < HEADER_SIZE; idx += 8) {
				// Формируем битовый блок
				MakeBlock(&buff[idx], block);
				// Шифруем
				EncryptBlock(Ci);
				Ci = Ci ^ block;
				// Обновляем данные в буфере
				MakeChunk(Ci, &buff[idx]);
			}
			bool successful = false;
			// Если добавляем в уже существующий файл
			ofstream output;
			if(append) {
				output.open(savedToFolder + outputFileName + "_DES", ios::binary | ios::app);
			} else {
				output.open(savedToFolder + relative + "_DES", ios::binary);	
			}
			successful = output.is_open();
			// Сбрасываем буфер с зашифрованными блоками в файл
			output.write(reinterpret_cast<char *>( buff ), sizeof(byte) * HEADER_SIZE);
			output.close();
			// Освобождаем память
			delete buff;
			return true;
		}
		// Иначе работаем с файлом
		// Рассчитываем количество байт выравнивания
		size_t padding = (len % 8 == 0 ? 0 : 8 - len % 8);
		// Определяем количество "полезных" блоков файла
		size_t totalBlocks = (size_t)floor(len / 8);
		// Открываем входной файл
		ifstream input(inputFile, ios::binary);
		// Проверяем открытие входного файла
		if(!input.is_open()) {
			// Если файл не удалось открыть - прерываем задачу
			return false;
		}
		// Отделяем имя файла
		string relative = inputFile;
		if(relative.find(savedToFolder) == string::npos) return false;
		relative = "\\" + relative.substr( savedToFolder.size() );
		// Заносим имя файла в структуру
		memcpy(&fh.filename, relative.c_str(), sizeof(byte) * relative .size());
		bitset<BLOCK_SIZE> size( len + padding );
		MakeChunk(size, fh.fileSize);
		for(size_t i = 0; i < 8; ++i)
			fh.paddingBlock[i] = rand() % 256;
		fh.paddingBlock[6] = 0;// Тип файла: файл
		fh.paddingBlock[7] = padding;

		cout << "FileName=" << relative << endl;
		cout << "FileSize=" << len << endl;
		cout << "Type    =" << (fh.paddingBlock[6] == 0 ? "File" : "Directory") << endl;
		cout << "Padding =" << (int)fh.paddingBlock[7] << endl;
		cout << "Blocks  =" << totalBlocks << endl; 

		// Выделяем память = размер заголовка + размер входного файла + выравнивание
		byte *buff = new byte[HEADER_SIZE + len + padding];
		// Обнуляем буфер
		memset( buff, 0, sizeof(byte) * ( HEADER_SIZE + len + padding ) ); 
		// Заносим файловый заголовок
		memcpy( buff, &fh, sizeof(FileHeader));
		// Читаем файл в буфер (добавляем данные файла после заголовка)
		input.read(reinterpret_cast<char *>( &buff[HEADER_SIZE] ), sizeof(byte) * len);

		bitset<64> block(0);
		size_t blockID = 0;
		
		// Шифруем последовательно блоки
		for(size_t idx = 0; idx < totalBlocks * 8 + HEADER_SIZE; idx += 8) {
			// Формируем битовый блок
			MakeBlock(&buff[idx], block);
			// Шифруем
			EncryptBlock(Ci);
			Ci = Ci ^ block;
			// Обновляем данные в буфере
			MakeChunk(Ci, &buff[idx]);
		}
		// Возможно потребуется выровнять последний блок 
		// Так же запишем дополнительный блок в который поместим число байт выравнивания
		// Если размер данных в файле кратен 64 бит - дополнение не требуется
		// В противном случае дополняем блок до 64 бит
		if(padding != 0) {
			// Добавляем случ. значения
			for(size_t i = 0; i < padding; ++i)
				buff[HEADER_SIZE + len + i] = rand() % 256;
			// Формируем битовый блок
			bitset<64> block(0);
			MakeBlock(&buff[HEADER_SIZE + totalBlocks * 8], block);
			// Шифруем
			EncryptBlock(Ci);
			Ci = Ci ^ block;
			// Перезапишем данные в памяти новыми зашиврованными
			MakeChunk(Ci, &buff[HEADER_SIZE + totalBlocks * 8]);
		}

		bool successful = false;
		// Если добавляем в уже существующий файл
		ofstream output;
		if(append) {
			output.open(savedToFolder + outputFileName + "_DES", ios::binary | ios::app);
		} else {
			output.open(savedToFolder + relative + "_DES", ios::binary);			
		}	
		successful = output.is_open();
		// Сбрасываем буфер с зашифрованными блоками в файл
		output.write(reinterpret_cast<char *>( buff ), sizeof(byte) * (len + padding + HEADER_SIZE));
		// Освобождаем память
		delete buff;
		// Закрываем файлы
		input.close();
		output.close();
		
		return successful;
	}
	// Расшифровка
	bool Decrypt(string &inputFile) {		
		// Открываем входной и выходной файлы
		ifstream input(inputFile, ios::binary);			
		// Проверяем открытие входного файла
		if( !input.is_open() ) {
			// Если входной файл не удалось открыть - прерываем задачу
			return false;
		}
		// Начальный вектор инициализации
		bitset<BLOCK_SIZE> Ci ( IV );
		bitset<64> block(0);
		// Читаем входной файл
		while( input.peek() != EOF ) {
			// Создаем заголовок
			FileHeader fh;
			// Очищаем структуру
			memset(&fh, 0, sizeof(FileHeader));
			// Буфер для чтения файлового заголовка
			byte headerBytes[HEADER_SIZE]= {0};
			// Читаем заголовок
			input.read(reinterpret_cast<char *>( &headerBytes), sizeof(byte) * HEADER_SIZE);
			// Расшифровываем заголовок
			for(size_t i = 0; i < HEADER_SIZE; i += 8) {
				// Формируем битовый блок
				MakeBlock(&headerBytes[i], block);		
				// Шифруем
				EncryptBlock(Ci);
				bitset<64> message = Ci ^ block;
				Ci = block;
				// Обновляем данные в буфере
				MakeChunk(message, &headerBytes[i]);
			}
			memcpy(&fh, headerBytes, sizeof(FileHeader));
			char tmp[FILE_NAME_SIZE] = {0};
			memcpy(&tmp, fh.filename, sizeof(byte) * FILE_NAME_SIZE);
			string filename(tmp);
			// Получаем размер файла
			MakeBlock(fh.fileSize, block);
			size_t actualSize = 0;
			try {
				actualSize = block.to_ulong();
			}
			catch(exception &ex) {
				return false;
				//cout << ex.what() << endl;
			}
			cout << "FileName=" << filename << endl;
			cout << "FileSize=" << actualSize << endl;
			cout << "Type    =" << (fh.paddingBlock[6] == 0 ? "File" : "Directory") << endl;
			cout << "Padding =" << (int)fh.paddingBlock[7] << endl;
			// Директория ?
			if(fh.paddingBlock[6] == 1) {
				cout << savedToFolder + filename << endl;	
				if(!CreatePath(savedToFolder + filename) )
				{
					cout << "Error path create" << endl;
				}
				// След. кусок
				continue;
			}
			
			// Определяем количество блоков
			size_t totalBlocks = (size_t)floor(actualSize / 8);
			//cout << "padding=" << padding << endl;		
			cout << "Blocks  =" << totalBlocks << endl;
			// Выделяем память
			byte *buff = new byte[actualSize];
			// Очищаем буфер
			memset(buff, 0, sizeof(byte) * actualSize);
			// Читаем кусок из файла в буфер
			input.read(reinterpret_cast<char *>( buff ), sizeof(byte) * actualSize);
			// Расшифровываем последовательно блоки
			for(size_t idx = 0; idx < actualSize; idx += 8) {
				// Формируем битовый блок
				MakeBlock(&buff[idx], block);		
				// Расшифровка
				EncryptBlock(Ci);
				bitset<64> message = Ci ^ block;
				Ci = block;
				// Обновляем данные в буфере
				MakeChunk(message, &buff[idx]);
			}
			size_t padding = fh.paddingBlock[7];
			// Сбрасываем буфер с расшифрованными блоками в файл
			//string path = GetParentFolder(savedToFolder);
			ofstream output( savedToFolder + filename, ios::binary);
			output.write(reinterpret_cast<char *>( buff ), sizeof(byte) * (actualSize - padding));
			output.close();
			// Освобождаем память
			delete buff;
		}
		// Закрываем входной файл
		input.close();
		// Операция завершилась успешно		
		return true;
	} 

	friend ostream & operator << (ostream & os, const DES &that) {
		os << "-------------------------------------------------------------"		<< endl;
		cout.setf(ios::hex, ios::basefield);
		os << "KEY       =" << that.Key.to_ullong()									<< endl;
		os << "IV        =" << that.IV .to_ullong()									<< endl;
		cout.unsetf(ios::hex);
		os << "RootFolder=" << (that.savedToFolder == "" ? "null" : that.savedToFolder)	<< endl;
		os << "-------------------------------------------------------------"		<< endl;
		return os;
	}
};
/////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////// Заполнение таблиц ///////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////
// Таблица начальной перестановки
const size_t DES::IP[BLOCK_SIZE] = 
{
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54,	46,	38,	30,	22,	14,	6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49,	41,	33,	25,	17,	9, 	1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53,	45,	37,	29,	21,	13,	5, 63, 55, 47, 39, 31, 23, 15, 7
};
// Таблица начального вектора C0
const size_t DES::VEC_C0[VEC_C0_D0_SIZE] = 
{
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36
};
// Таблица начального вектора D0
const size_t DES::VEC_D0[VEC_C0_D0_SIZE] = 
{
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};
// Таблица сдвига расширенного ключа для получения раундовых
const size_t DES::ROUND_KEY_SHIFT[ROUND_SIZE] = 
{
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};
// Таблица - маска, позволяющая получить очередной раундовый ключ
const size_t DES::ROUND_KEY_MASK[ROUND_KEY_SIZE] = 
{
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10, 23, 19, 12,  4,
	26,  8, 16,  7, 27, 20, 13,  2, 41, 52, 31, 37, 47, 55, 30, 40,
	51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};
// Таблица расширения (функция E)
const size_t DES::E[EXPAND_VEC_SIZE] = 
{
	32,	1,   2,  3,  4,  5,
	4,  5,   6,  7,  8,  9,
	8,  9,  10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1
};
//////////////////////////////////////////
//////// Таблицы S преобразований ////////
//////////////////////////////////////////
const size_t DES::S[S_BLOCKS * S_ROWS * S_COLS] = 
{
	// S1
	14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7, 
	0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
 	 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
 	15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
	// S2
	15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
 	 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
 	 0, 14,  7, 11,	10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
 	13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
	// S3
	10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8, 	
	13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
	 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
	// S4
	 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
 	13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
 	10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
 	 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
	// S5
	 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
 	14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
 	 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
 	11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
	// S6
	12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11, 
	10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
	 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6, 
	 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
	// S7
	 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
	 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
	 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
	// S8
	13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
	 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
	 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
	 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 	
};
//////////////////////////////////////////
// Таблица P перестановки
const size_t DES::P[HALF_BLOCK_SIZE] = 
{
	16,  7, 20, 21, 29, 12, 28, 17,
	 1, 15, 23, 26,  5, 18, 31, 10,
	 2,  8, 24, 14, 32, 27,  3,  9,
	19, 13, 30,  6, 22, 11,  4, 25
};
// Таблица обратной перестановки
const size_t DES::invIP[BLOCK_SIZE] = 
{
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};
/////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////