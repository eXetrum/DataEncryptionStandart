#pragma once

#include "Headers.h"

class DES {
private:
	////////////////////////////////////////////////////////////////////////////
	// ������ �����	�������/�������� ������
	static const size_t BLOCK_SIZE = 64;
	// ������ �������� �����
	static const size_t HALF_BLOCK_SIZE = 32;
	// ���������� �������
	static const size_t ROUND_SIZE = 16;
	// ������ ��������� �������� ������������ � ������������ ��������� ������
	static const size_t VEC_C0_D0_SIZE = 28;
	// ������ ���������� �����
	static const size_t ROUND_KEY_SIZE = 48;
	// ������ ������� ����� ���������� (Ri)
	static const size_t EXPAND_VEC_SIZE = 48;
	// ������� ������� S ��������������
	static const size_t S_ROWS = 4;
	static const size_t S_COLS = 16;
	static const size_t S_BLOCKS = 8;
	// ������ � ������ ��������� ���������
	static const size_t HEADER_SIZE = 280;
	// ������ � ������ ����� ����� ��� ����� �����������
	static const size_t FILE_NAME_SIZE = 264;	
	////////////////////////////////////////////////////////////////////////////
	// ��������� ������� ������������
	static const size_t IP[];
	// ��������� ������� ��� �������� ����������� � ������������ ��������� ������	
	static const size_t VEC_C0[];
	static const size_t VEC_D0[];
	// ������� ������� ������������ �����
	static const size_t ROUND_KEY_SHIFT[];
	// ������� ��� ��������� ��������� ������
	static const size_t ROUND_KEY_MASK[];
	// ������� ���������� Ri ����� ����� � ������� �������������� ��������
	static const size_t E[];
	// ������� ��� S ��������������
	static const size_t S[];
	// P ������������
	static const size_t P[]; 
	// ������� �������� ������������
	static const size_t invIP[];
	////////////////////////////////////////////////////////////////////////////
	// 64 ������ ���� 
	bitset<BLOCK_SIZE> Key;
	// 64 ������ ���������������� ������
	bitset<BLOCK_SIZE> IV;
	// ���� �������� ��������� �����
	bitset<ROUND_KEY_SIZE> Keys[ROUND_SIZE]; 
	// ���� ���� ��������� �������� ����
	string savedToFolder;
	// ��� ��������� �����
	string outputFileName;
	////////////////////////////////////////////////////////////////////////////
	// �������� ���������
	struct FileHeader {
		// 264 ���� => ��� ����� ������������ ��������� ��������
		byte filename[FILE_NAME_SIZE];
		// 8 ����	=> ������ ����� (��������� �� ������)
		byte fileSize[8];
		// � ����������� ���� � 8 ����, ������������� ���� - ��� �����, � ��������� ���� - ���������� ���� ������������
		byte paddingBlock[8];	
		// �����: 264 + 8 + 8 = 280 ���� ���������
	};
	// ��� �����: ����, �������, ��� �� ������
	enum EntryType {
		NOTFOUND  = -1,
		FILE	  =  0,
		DIRECTORY =  1
	};
	////////////////////////////////////////////////////////////////////////////
	// ��������� �������
	////////////////////////////////////////////////////////////////////////////
	// ��������� ��� ������� ��� ��������� 64 ������� ����� 
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
		// 128 ���
		byte raw[16];
		memset(&raw[0], 0, sizeof(byte) * 16);
		// �������� Md4 ���
		cout << "Message :" << message << endl;
		cout << "MD4 hash:" << md4.GetHash(message, raw) << endl;
		// �������� ������� � ������� 64 ���
		bitset<BLOCK_SIZE> LOW, HI;
		MakeBlock(&raw[0], LOW);
		MakeBlock(&raw[8], HI);
		// ����� ��������� � ���������� �������� XOR ��� ������ 128 -> 64
		return LOW.to_ullong() ^ HI.to_ullong();
	}
	// ����������� �����
	template <std::size_t N> 
	inline void 
		rotate(std::bitset<N>& b, unsigned m) 
	{ 
		m %= N;
		b = b << m | b >> (N-m); 
	}
	// ��������� 64 ������ ���� �� ������� ����
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
	// �������� ����� �� 8 ��� �� 64 ������� �����	
	inline void MakeChunk(bitset<64> &block, byte *chunk) 
	{
		long64 b = block.to_ullong();
		long64 mask = 255;

		for(size_t i = 0; i < 8; ++i) {
			chunk[i] = static_cast<byte>( ( b & ( mask << (8 * i) ) ) >> ( 8 * i ) );
		}
	}
	// ������������� ��������� ������
	void Initialize() {
		/////////////////////////////////////////////////
		// ��������� ��������� �����
		/////////////////////////////////////////////////
		// ������� ����� �����
		bitset<BLOCK_SIZE> ExpandedKey(Key.to_ullong());
		// ��������� ����� ������ ���� ����� �������� �������� ���������� ������
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
		// ��������� ��������� �������
		bitset<VEC_C0_D0_SIZE> C0(0), D0(0);
		for(size_t i = 0; i < VEC_C0_D0_SIZE; ++i) {
			C0[i] = ExpandedKey[VEC_C0[i] - 1];
			D0[i] = ExpandedKey[VEC_D0[i] - 1];
		}		
		// ��������� 16 ��������� ������
		for(size_t i = 0; i < ROUND_SIZE; ++i) {
			// ������ ����� ����������� ����� ��� �������� Ci, Di �������� �������
			rotate(C0, ROUND_KEY_SHIFT[i]);
			rotate(D0, ROUND_KEY_SHIFT[i]);
			// ���������� ���������� �������			
			bitset<VEC_C0_D0_SIZE * 2> C0D0( (C0.to_ullong() << VEC_C0_D0_SIZE) | D0.to_ullong());
			// ��������� ���� i ������ ������� �� ����������� ������������� ������� ���� ��������� �������
			bitset<ROUND_KEY_SIZE> k;
			for(size_t j = 0; j < ROUND_KEY_SIZE; ++j)
				k[j] = C0D0[ROUND_KEY_MASK[j] - 1];
			// ��������� ����
			Keys[i] = k;
		}
	}
	// ���������� �����
	inline void EncryptBlock(bitset<BLOCK_SIZE> &block) {		 
		/////////////////////////////////////////////////
		// ��������� ������������
		/////////////////////////////////////////////////
		// �������������� ���� ����� ���������� ��������� ������������
		bitset<BLOCK_SIZE> temp( block );
		// ��������� ������� ���������� ��������� ������������
		for(size_t i = 0; i < BLOCK_SIZE; ++i) {
			// ����� ������ (����� ���� - 1) �� ������� ��������� ������������ 
			// ������� �� ����������� ����� ������ ��� � ���������� � �������������� ����
			block.set(i, temp[ IP[i] - 1 ]);
		}
		/////////////////////////////////////////////////
		// ����� ���������� (16 ������� �������������� ��������)
		/////////////////////////////////////////////////
		// ��������� ���� ���������� ����� ��������� ������������
		// �� ��� 32 ������ ����� L0 - ������� �����, R0 - �������
		long64 mask = 4294967295L;
		long64 b = block.to_ullong();
		long64 L0 = (b & (mask << 32) ) >> 32;
		long64 R0 = b & mask;
		// ������� � ���������� �������� ���������
		long64 Li, Ri, Li_prev( R0 ), Ri_prev( L0 );
		// 16 �������
		for(size_t i = 0; i < ROUND_SIZE; ++i) {
			Li = Ri_prev;
			Ri = Li_prev ^ f(Ri_prev, Keys[i]);
			// ���������� ���������� ��������
			Li_prev = Li;
			Ri_prev = Ri;
		}
		// ���������� ��������� ���������� 32 ������ �������� ����� 16 ������� ��������������
		bitset<BLOCK_SIZE> L16R16 ( (Li << 32) | Ri );
		// ���������� �������� ������������
		for(size_t i = 0; i < BLOCK_SIZE; ++i) {
			block.set(i, L16R16[ invIP[i] - 1 ]);
		}
	}

	inline bitset<BLOCK_SIZE> DecryptBlock(bitset<BLOCK_SIZE> &block) { 
		/////////////////////////////////////////////////
		// ��������� ������������
		/////////////////////////////////////////////////
		// �������������� ���� ����� ���������� ��������� ������������
		bitset<BLOCK_SIZE> IPblock;
		// ��������� ������� ���������� ��������� ������������
		for(size_t i = 0; i < BLOCK_SIZE; ++i) {
			// ����� ������ (����� ���� - 1) �� ������� ��������� ������������ 
			// ������� �� ����������� ����� ������ ��� � ���������� � �������������� ����
			IPblock.set(i, block[IP[i] - 1]);
		}
		/////////////////////////////////////////////////
		// ����� ���������� (16 ������� �������������� ��������)
		/////////////////////////////////////////////////
		// ��������� ���� ���������� ����� ��������� ������������
		// �� ��� 32 ������ ����� L0 - ������� �����, R0 - �������
		bitset<HALF_BLOCK_SIZE> L0, R0;
		for(size_t i = 0; i < HALF_BLOCK_SIZE; ++i) {
			L0.set(i, IPblock[i + HALF_BLOCK_SIZE]);
			R0.set(i, IPblock[i]);
		}
		// ������� � ���������� �������� ���������
		long64 Li, Li_prev, Ri, Ri_prev;
		Li_prev = R0.to_ullong();
		Ri_prev = L0.to_ullong();
		// ��������� ����� � �������� �������
		for(int i = ROUND_SIZE - 1; i >= 0; --i) {
			// 
			Li = Ri_prev;
			Ri = Li_prev ^ f(Ri_prev, Keys[i]);
			// 
			Li_prev = Li;
			Ri_prev = Ri;
		}
		// ���������� ��������� ���������� 32 ������ �������� ����� 16 ������� ��������������
		bitset<BLOCK_SIZE> L16R16 ( (Li << 32) | Ri );
		// ���������� �������� ������������
		bitset<BLOCK_SIZE> invIPblock;
		for(size_t i = 0; i < BLOCK_SIZE; ++i) {
			invIPblock.set(i, L16R16[ invIP[i] - 1 ]);
		}

		return invIPblock;
	}

	inline long64 f(long64 &ri, bitset<ROUND_KEY_SIZE> &Ki) {
		bitset<HALF_BLOCK_SIZE> Ri(ri);
		bitset<EXPAND_VEC_SIZE> exRi(0);
		// ��������� 32 ������ Ri ������ �� 48 ���
		for(size_t i = 0; i < EXPAND_VEC_SIZE; ++i) {
			exRi.set(i, Ri[ E[i] - 1 ]);
		}
		// Xor � ������� ��������� ������
		exRi = exRi ^ Ki;
		// ������������ ����������� ������ exRi � ���� ������ ������ �� 6 ��� ������
		long64 bb = exRi.to_ullong();
		long64 chunk[8] = {0};
		long64 mask = 63;
		for(size_t i = 0; i < 8; ++i) {
			chunk[i] = static_cast<byte>( ( bb & ( mask << (6 * i) ) ) >> ( 6 * i ) );
		}
		// �������������� 6 ������ ����� � 4 ������ � ���������� S ��������������
		long64 Bj[8] = {0};
		for(size_t i = 0; i < 8; ++i) {
			size_t a, b;
			a = ( (chunk[i] & 32) >> 4) | (chunk[i] & 1);
			b = ( (chunk[i] & 16) >> 1) | ((chunk[i] & 8) >> 1) | ((chunk[i] & 4) >> 1) | ((chunk[i] & 2) >> 1);
			// �������� ������ �� Si ����� �� ����������� (a, b)
			Bj[i] = S[S_BLOCKS * i + a * S_COLS + b];
		}
		// ���������� 4 ������ ����� � ���� 32 ������
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
		// P ������������
		bitset<HALF_BLOCK_SIZE> result(0);
		for(size_t i = 0; i < HALF_BLOCK_SIZE; ++i) {
			result.set(i, Bj_union[P[i] - 1]);
		}

		return result.to_ullong();
	}

public:
	// �����������
	DES(string Key, string IV, string rootFolder) {
		srand((unsigned)time(0));
		// �������� ��� ����� � ��������� � ������� ������
		this->Key = bitset<BLOCK_SIZE>( Md4Hash( Key.c_str() ) );
		// �������� ��� ������� �������������
		this->IV  = bitset<BLOCK_SIZE>( Md4Hash( IV .c_str() ) );
		// ���������� ���� � ��������� �������� � ������� ������������ ����(�)
		this->savedToFolder = GetParentFolder( rootFolder );
		// ��� ��������������� ��������/�����
		this->outputFileName = GetFilename( rootFolder );
		// ������������� ��������� ������
		Initialize();
	}
	// ����� ��������� ������� �����
	std::streampos fileSize( string &filePath ){
		std::streampos fsize = 0;
		// ��������� ���� �� ������
		std::ifstream file( filePath, std::ios::binary );
		// �������� �������� ��������� ��������� (������ �������� ���� - �������� ����� ����� 0,
		fsize = file.tellg();
		// ����������� �������� ��������� � �����
		file.seekg( 0, std::ios::end );
		// �������� ������ ����� ��� �������� ����� ��������� ��������� ��������� � �������
		fsize = file.tellg() - fsize;
		// �� �������� ������� ����
		file.close();
		// ������ ������
		return fsize;
	}
	// ��������� ���������� ���� � �����/����� ���������� � ��� ��������: ������� ��� ����, � ���� ��  ��� ���� �� ���������� ���� ��� ��� �����
	EntryType CheckEntry(string filename) {
		WIN32_FIND_DATA FileInformation;
		ZeroMemory(&FileInformation, sizeof(FileInformation) );
		// �������� ���������� � ����� � ���������
		HANDLE hFile = FindFirstFile(filename.c_str(), &FileInformation); 
		// ��������� �������������
		FindClose(hFile);
		// ������ ��� � ������� ��������
		if(hFile != INVALID_HANDLE_VALUE) {
			if(FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				return EntryType::DIRECTORY;
			else 
				return EntryType::FILE;
		} else {	
			return EntryType::NOTFOUND;
		}
	}
	// �������� ��� �����/�������� �� ����������� ����
	string GetFilename (const string &path) {
		size_t found = path.find_last_of("/\\");
		return path.substr(found + 1);
	}
	// ��������� ���� �� ���������
	bool CreatePath(std::string &wsPath)
	{
		DWORD attr;
		int pos;
		bool result = true;
		// �������� ������� �������� ��������� �����
		pos = wsPath.find_last_of("\\");
		if (wsPath.length() == pos + 1)
		{
			// �������� ������
			wsPath.resize(pos);
		}
		// �������� �������� ��������		
		attr = GetFileAttributes(wsPath.c_str());
		// �������� ���������� �� �������
		// ���� ��� - ������� �������
		if (0xFFFFFFFF == attr)
		{
			pos = wsPath.find_last_of("\\");
			if (0 < pos)
			{
				// ���������� ���������� ��� �������
				result = CreatePath(wsPath.substr(0, pos));
			}
			// ������� ����� �������
			result = result && CreateDirectoryA(wsPath.c_str(), 0);
		}
		// ������ ��� ���������� � ������ ������� ��� ��� �� �������
		else if (FILE_ATTRIBUTE_DIRECTORY != attr)
		{	
			SetLastError(ERROR_FILE_EXISTS);
			// ��������� �� ������
			result = false;
		}
		return result;
	}
	// �������� �� ����������� ���� ������������ ������� (�� ������� ����)
	string GetParentFolder( string & path ) {
		string name = GetFilename( path );
		return path.substr(0, path.find( name ) );
	}
	// ����� ����������: inputFile - ���� � �����/��������, append - ����� ������, ���������� ��� �������� ������ �����
	bool Encrypt(string &inputFile, bool append = true) {
		// ��������� ������ �������������
		static bitset<BLOCK_SIZE> Ci = IV;
		// ���������� ���: ���� ��� ����������
		EntryType entryType = CheckEntry(inputFile);
		// ��������� ������ ����� ����� � ��� �����
		if(inputFile.size() > FILE_NAME_SIZE || entryType == EntryType::NOTFOUND) return false;
		// �������� ������ �����
		size_t len = (size_t)fileSize(inputFile);
		// ������� ���������
		FileHeader fh;
		// �������� ����
		memset(&fh, 0, sizeof(FileHeader));
		// ���� ������������ ����������
		if(entryType == EntryType::DIRECTORY) {			
			// �������� ��� ���������� � �������� ���� ��������� ���� ��������� ��������
			string relative = inputFile;
			if(relative.find(savedToFolder) == string::npos) return false;
			relative = "\\" + relative.substr( savedToFolder.size() );
			// �������� ��� ����������
			memcpy(&fh.filename, relative.c_str(), sizeof(byte) * relative.size());
			// ������� ������ � ������� �����
			bitset<BLOCK_SIZE> size( len );
			MakeChunk(size, fh.fileSize);// = len;
			// ���� ������������ ��������� �������
			for(size_t i = 0; i < 8; ++i)
				fh.paddingBlock[i] = rand() % 256;
			// ��������� ��� ����� �����
			fh.paddingBlock[6] = 1; // ��� �����: ����������
			fh.paddingBlock[7] = 0; // ����������� ���� ������������
			// �������� ������ ��� ������
			byte *buff = new byte[HEADER_SIZE];
			// �������� �����
			memset( buff, 0, sizeof(byte) * HEADER_SIZE ); 
			// ������� �������� ���������
			memcpy( buff, &fh, sizeof(FileHeader));
			/////////////////////////////////////////////
			// ������� �����
			/////////////////////////////////////////////			
			bitset<64> block(0);
			// ������� ��������������� �����
			for(size_t idx = 0; idx < HEADER_SIZE; idx += 8) {
				// ��������� ������� ����
				MakeBlock(&buff[idx], block);
				// �������
				EncryptBlock(Ci);
				Ci = Ci ^ block;
				// ��������� ������ � ������
				MakeChunk(Ci, &buff[idx]);
			}
			bool successful = false;
			// ���� ��������� � ��� ������������ ����
			ofstream output;
			if(append) {
				output.open(savedToFolder + outputFileName + "_DES", ios::binary | ios::app);
			} else {
				output.open(savedToFolder + relative + "_DES", ios::binary);	
			}
			successful = output.is_open();
			// ���������� ����� � �������������� ������� � ����
			output.write(reinterpret_cast<char *>( buff ), sizeof(byte) * HEADER_SIZE);
			output.close();
			// ����������� ������
			delete buff;
			return true;
		}
		// ����� �������� � ������
		// ������������ ���������� ���� ������������
		size_t padding = (len % 8 == 0 ? 0 : 8 - len % 8);
		// ���������� ���������� "��������" ������ �����
		size_t totalBlocks = (size_t)floor(len / 8);
		// ��������� ������� ����
		ifstream input(inputFile, ios::binary);
		// ��������� �������� �������� �����
		if(!input.is_open()) {
			// ���� ���� �� ������� ������� - ��������� ������
			return false;
		}
		// �������� ��� �����
		string relative = inputFile;
		if(relative.find(savedToFolder) == string::npos) return false;
		relative = "\\" + relative.substr( savedToFolder.size() );
		// ������� ��� ����� � ���������
		memcpy(&fh.filename, relative.c_str(), sizeof(byte) * relative .size());
		bitset<BLOCK_SIZE> size( len + padding );
		MakeChunk(size, fh.fileSize);
		for(size_t i = 0; i < 8; ++i)
			fh.paddingBlock[i] = rand() % 256;
		fh.paddingBlock[6] = 0;// ��� �����: ����
		fh.paddingBlock[7] = padding;

		cout << "FileName=" << relative << endl;
		cout << "FileSize=" << len << endl;
		cout << "Type    =" << (fh.paddingBlock[6] == 0 ? "File" : "Directory") << endl;
		cout << "Padding =" << (int)fh.paddingBlock[7] << endl;
		cout << "Blocks  =" << totalBlocks << endl; 

		// �������� ������ = ������ ��������� + ������ �������� ����� + ������������
		byte *buff = new byte[HEADER_SIZE + len + padding];
		// �������� �����
		memset( buff, 0, sizeof(byte) * ( HEADER_SIZE + len + padding ) ); 
		// ������� �������� ���������
		memcpy( buff, &fh, sizeof(FileHeader));
		// ������ ���� � ����� (��������� ������ ����� ����� ���������)
		input.read(reinterpret_cast<char *>( &buff[HEADER_SIZE] ), sizeof(byte) * len);

		bitset<64> block(0);
		size_t blockID = 0;
		
		// ������� ��������������� �����
		for(size_t idx = 0; idx < totalBlocks * 8 + HEADER_SIZE; idx += 8) {
			// ��������� ������� ����
			MakeBlock(&buff[idx], block);
			// �������
			EncryptBlock(Ci);
			Ci = Ci ^ block;
			// ��������� ������ � ������
			MakeChunk(Ci, &buff[idx]);
		}
		// �������� ����������� ��������� ��������� ���� 
		// ��� �� ������� �������������� ���� � ������� �������� ����� ���� ������������
		// ���� ������ ������ � ����� ������ 64 ��� - ���������� �� ���������
		// � ��������� ������ ��������� ���� �� 64 ���
		if(padding != 0) {
			// ��������� ����. ��������
			for(size_t i = 0; i < padding; ++i)
				buff[HEADER_SIZE + len + i] = rand() % 256;
			// ��������� ������� ����
			bitset<64> block(0);
			MakeBlock(&buff[HEADER_SIZE + totalBlocks * 8], block);
			// �������
			EncryptBlock(Ci);
			Ci = Ci ^ block;
			// ����������� ������ � ������ ������ ��������������
			MakeChunk(Ci, &buff[HEADER_SIZE + totalBlocks * 8]);
		}

		bool successful = false;
		// ���� ��������� � ��� ������������ ����
		ofstream output;
		if(append) {
			output.open(savedToFolder + outputFileName + "_DES", ios::binary | ios::app);
		} else {
			output.open(savedToFolder + relative + "_DES", ios::binary);			
		}	
		successful = output.is_open();
		// ���������� ����� � �������������� ������� � ����
		output.write(reinterpret_cast<char *>( buff ), sizeof(byte) * (len + padding + HEADER_SIZE));
		// ����������� ������
		delete buff;
		// ��������� �����
		input.close();
		output.close();
		
		return successful;
	}
	// �����������
	bool Decrypt(string &inputFile) {		
		// ��������� ������� � �������� �����
		ifstream input(inputFile, ios::binary);			
		// ��������� �������� �������� �����
		if( !input.is_open() ) {
			// ���� ������� ���� �� ������� ������� - ��������� ������
			return false;
		}
		// ��������� ������ �������������
		bitset<BLOCK_SIZE> Ci ( IV );
		bitset<64> block(0);
		// ������ ������� ����
		while( input.peek() != EOF ) {
			// ������� ���������
			FileHeader fh;
			// ������� ���������
			memset(&fh, 0, sizeof(FileHeader));
			// ����� ��� ������ ��������� ���������
			byte headerBytes[HEADER_SIZE]= {0};
			// ������ ���������
			input.read(reinterpret_cast<char *>( &headerBytes), sizeof(byte) * HEADER_SIZE);
			// �������������� ���������
			for(size_t i = 0; i < HEADER_SIZE; i += 8) {
				// ��������� ������� ����
				MakeBlock(&headerBytes[i], block);		
				// �������
				EncryptBlock(Ci);
				bitset<64> message = Ci ^ block;
				Ci = block;
				// ��������� ������ � ������
				MakeChunk(message, &headerBytes[i]);
			}
			memcpy(&fh, headerBytes, sizeof(FileHeader));
			char tmp[FILE_NAME_SIZE] = {0};
			memcpy(&tmp, fh.filename, sizeof(byte) * FILE_NAME_SIZE);
			string filename(tmp);
			// �������� ������ �����
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
			// ���������� ?
			if(fh.paddingBlock[6] == 1) {
				cout << savedToFolder + filename << endl;	
				if(!CreatePath(savedToFolder + filename) )
				{
					cout << "Error path create" << endl;
				}
				// ����. �����
				continue;
			}
			
			// ���������� ���������� ������
			size_t totalBlocks = (size_t)floor(actualSize / 8);
			//cout << "padding=" << padding << endl;		
			cout << "Blocks  =" << totalBlocks << endl;
			// �������� ������
			byte *buff = new byte[actualSize];
			// ������� �����
			memset(buff, 0, sizeof(byte) * actualSize);
			// ������ ����� �� ����� � �����
			input.read(reinterpret_cast<char *>( buff ), sizeof(byte) * actualSize);
			// �������������� ��������������� �����
			for(size_t idx = 0; idx < actualSize; idx += 8) {
				// ��������� ������� ����
				MakeBlock(&buff[idx], block);		
				// �����������
				EncryptBlock(Ci);
				bitset<64> message = Ci ^ block;
				Ci = block;
				// ��������� ������ � ������
				MakeChunk(message, &buff[idx]);
			}
			size_t padding = fh.paddingBlock[7];
			// ���������� ����� � ��������������� ������� � ����
			//string path = GetParentFolder(savedToFolder);
			ofstream output( savedToFolder + filename, ios::binary);
			output.write(reinterpret_cast<char *>( buff ), sizeof(byte) * (actualSize - padding));
			output.close();
			// ����������� ������
			delete buff;
		}
		// ��������� ������� ����
		input.close();
		// �������� ����������� �������		
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
/////////////////////////////////////// ���������� ������ ///////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////
// ������� ��������� ������������
const size_t DES::IP[BLOCK_SIZE] = 
{
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54,	46,	38,	30,	22,	14,	6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49,	41,	33,	25,	17,	9, 	1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53,	45,	37,	29,	21,	13,	5, 63, 55, 47, 39, 31, 23, 15, 7
};
// ������� ���������� ������� C0
const size_t DES::VEC_C0[VEC_C0_D0_SIZE] = 
{
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36
};
// ������� ���������� ������� D0
const size_t DES::VEC_D0[VEC_C0_D0_SIZE] = 
{
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};
// ������� ������ ������������ ����� ��� ��������� ���������
const size_t DES::ROUND_KEY_SHIFT[ROUND_SIZE] = 
{
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};
// ������� - �����, ����������� �������� ��������� ��������� ����
const size_t DES::ROUND_KEY_MASK[ROUND_KEY_SIZE] = 
{
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10, 23, 19, 12,  4,
	26,  8, 16,  7, 27, 20, 13,  2, 41, 52, 31, 37, 47, 55, 30, 40,
	51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};
// ������� ���������� (������� E)
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
//////// ������� S �������������� ////////
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
// ������� P ������������
const size_t DES::P[HALF_BLOCK_SIZE] = 
{
	16,  7, 20, 21, 29, 12, 28, 17,
	 1, 15, 23, 26,  5, 18, 31, 10,
	 2,  8, 24, 14, 32, 27,  3,  9,
	19, 13, 30,  6, 22, 11,  4, 25
};
// ������� �������� ������������
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