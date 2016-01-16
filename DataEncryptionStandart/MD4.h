#pragma once

#include "Headers.h"

/////////////////////////////////////////////////////////////////////////////////////////////////
// Описание спецификации алгоритма: http://www.faqs.org/rfcs/rfc1320.html
/////////////////////////////////////////////////////////////////////////////////////////////////

// Опишем класс для работы с алгоритмом
class MD4 {
private:
	// Контекст
	struct MD4Context {
		// Младшая и старшая части 64 битного блока
		uint lo, hi;
		// Начальные данные
		uint a, b, c, d;
		// Буфер сообщения: 8 символов или 64 * 8 = 512 бит
		unsigned char buffer[64];
		// 32 битные слова
		uint block[16];
	} ;
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
// Базофые функции преобразований
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			(((x) & ((y) | (z))) | ((y) & (z)))
#define H(x, y, z)			((x) ^ (y) ^ (z))
// MD4 преобразования для всех трех шагов 
#define STEP(f, a, b, c, d, x, s) \
	(a) += f((b), (c), (d)) + (x); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));
// Коррктная обработка порядка бит, Big endian или Little-endian.
#if defined(__i386__) || defined(__x86_64__) || defined(__vax__)
#define SET(n) \
	(*(uint *)&ptr[(n) * 4])
#define GET(n) \
	SET(n)
#else
#define SET(n) \
	(ctx->block[(n)] = \
	(uint)ptr[(n) * 4] | \
	((uint)ptr[(n) * 4 + 1] << 8) | \
	((uint)ptr[(n) * 4 + 2] << 16) | \
	((uint)ptr[(n) * 4 + 3] << 24))
#define GET(n) \
	(ctx->block[(n)])
#endif
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
	// Указатель на контекст
	MD4Context *ctx;
public:
	// Конструктор
	MD4() {
		// Начальная инициализация 
		ctx = new MD4Context;
		memset( ctx, 0, sizeof(MD4Context) );
		// Заносим константы описанные в спецификации
		ctx->a = 0x67452301;
		ctx->b = 0xefcdab89;
		ctx->c = 0x98badcfe;
		ctx->d = 0x10325476;
		// Обнуляем старшую и младшую часть
		ctx->lo = 0;
		ctx->hi = 0;
	}
	// Деструктор
	~MD4() { 
		// Освобождаем память выделенную под структуру
		delete ctx;
	}
	// Получить цифровую подпись сообщения. Результат будет продублирован в массив raw
	string GetHash(string message, byte *raw) {			
		// Дробим сообщение на части по 8 байт
		for(size_t i = 0; i < message.size(); i += 8) {
			string chunk = "";
			if(i + 8 < message.size())
				chunk = message.substr(i, 8);
			else
				chunk = message.substr(i);
			// Обрабатываем следующий кусок сообщения
			ProcessChunk( chunk.c_str(), chunk.size() );
		}
		// Получаем результат в виде массива байт
		RawResult(raw);
		// Собираем строку с помощю строкового потока
		stringstream hash;
		hash << hex;
		for(size_t i = 0; i < 16; ++i)
			hash << setfill('0') << setw(2) << (int) raw[i];
		// Вернем результат в виде строки
		return hash.str();
	}	
private:
	// Обработка блока
	static const void *ProcessBlock(MD4Context *ctx, const void *block, unsigned long size)
	{
		const unsigned char *ptr;
		// Текущие значение констант
		uint a, b, c, d;
		// Предыдущее значение
		uint saved_a, saved_b, saved_c, saved_d;
		// Получаем указатель на начало блока данных
		ptr = (const unsigned char *)block;
		// Из контекста получаем данные о текущих константах
		a = ctx->a;
		b = ctx->b;
		c = ctx->c;
		d = ctx->d;
		// 16 туров по 3 раунда
		do {
			// Запоминаем предыдущие значения констант
			saved_a = a;
			saved_b = b;
			saved_c = c;
			saved_d = d;
			/* Первый раунд */
			STEP(F, a, b, c, d, SET(0), 3)
			STEP(F, d, a, b, c, SET(1), 7)
			STEP(F, c, d, a, b, SET(2), 11)
			STEP(F, b, c, d, a, SET(3), 19)
			STEP(F, a, b, c, d, SET(4), 3)
			STEP(F, d, a, b, c, SET(5), 7)
			STEP(F, c, d, a, b, SET(6), 11)
			STEP(F, b, c, d, a, SET(7), 19)
			STEP(F, a, b, c, d, SET(8), 3)
			STEP(F, d, a, b, c, SET(9), 7)
			STEP(F, c, d, a, b, SET(10), 11)
			STEP(F, b, c, d, a, SET(11), 19)
			STEP(F, a, b, c, d, SET(12), 3)
			STEP(F, d, a, b, c, SET(13), 7)
			STEP(F, c, d, a, b, SET(14), 11)
			STEP(F, b, c, d, a, SET(15), 19)
			/* Второй раунд */
			STEP(G, a, b, c, d, GET(0) + 0x5a827999, 3)
			STEP(G, d, a, b, c, GET(4) + 0x5a827999, 5)
			STEP(G, c, d, a, b, GET(8) + 0x5a827999, 9)
			STEP(G, b, c, d, a, GET(12) + 0x5a827999, 13)
			STEP(G, a, b, c, d, GET(1) + 0x5a827999, 3)
			STEP(G, d, a, b, c, GET(5) + 0x5a827999, 5)
			STEP(G, c, d, a, b, GET(9) + 0x5a827999, 9)
			STEP(G, b, c, d, a, GET(13) + 0x5a827999, 13)
			STEP(G, a, b, c, d, GET(2) + 0x5a827999, 3)
			STEP(G, d, a, b, c, GET(6) + 0x5a827999, 5)
			STEP(G, c, d, a, b, GET(10) + 0x5a827999, 9)
			STEP(G, b, c, d, a, GET(14) + 0x5a827999, 13)
			STEP(G, a, b, c, d, GET(3) + 0x5a827999, 3)
			STEP(G, d, a, b, c, GET(7) + 0x5a827999, 5)
			STEP(G, c, d, a, b, GET(11) + 0x5a827999, 9)
			STEP(G, b, c, d, a, GET(15) + 0x5a827999, 13)
			/* Третий раунд */
			STEP(H, a, b, c, d, GET(0) + 0x6ed9eba1, 3)
			STEP(H, d, a, b, c, GET(8) + 0x6ed9eba1, 9)
			STEP(H, c, d, a, b, GET(4) + 0x6ed9eba1, 11)
			STEP(H, b, c, d, a, GET(12) + 0x6ed9eba1, 15)
			STEP(H, a, b, c, d, GET(2) + 0x6ed9eba1, 3)
			STEP(H, d, a, b, c, GET(10) + 0x6ed9eba1, 9)
			STEP(H, c, d, a, b, GET(6) + 0x6ed9eba1, 11)
			STEP(H, b, c, d, a, GET(14) + 0x6ed9eba1, 15)
			STEP(H, a, b, c, d, GET(1) + 0x6ed9eba1, 3)
			STEP(H, d, a, b, c, GET(9) + 0x6ed9eba1, 9)
			STEP(H, c, d, a, b, GET(5) + 0x6ed9eba1, 11)
			STEP(H, b, c, d, a, GET(13) + 0x6ed9eba1, 15)
			STEP(H, a, b, c, d, GET(3) + 0x6ed9eba1, 3)
			STEP(H, d, a, b, c, GET(11) + 0x6ed9eba1, 9)
			STEP(H, c, d, a, b, GET(7) + 0x6ed9eba1, 11)
			STEP(H, b, c, d, a, GET(15) + 0x6ed9eba1, 15)
 			// Обновляем константы
			a += saved_a;
			b += saved_b;
			c += saved_c;
			d += saved_d;
			// Двигаемся к следующему куску в блоке 
			ptr += 64;
			// Цикл пока не пройдем все 512 байт
		} while (size -= 64);
		// Обновим табличные значения в контексте
		ctx->a = a;
		ctx->b = b;
		ctx->c = c;
		ctx->d = d;
		// Возвращаем результат
		return ptr;
	}
	// Обработка куска сообщения длиной в 8 байт
	void ProcessChunk(const void *chunk, unsigned long size)
	{
		uint saved_lo = 0;
		unsigned long used = 0, available = 0;
 
		saved_lo = ctx->lo;
		if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
			ctx->hi++;
		ctx->hi += size >> 29;
 
		used = saved_lo & 0x3f;
 
		if (used) {
			available = 64 - used;
 
			if (size < available) {
				memcpy(&ctx->buffer[used], chunk, size);
				return;
			}
 
			memcpy(&ctx->buffer[used], chunk, available);
			chunk = (const unsigned char *)chunk + available;
			size -= available;
			ProcessBlock(ctx, ctx->buffer, 64);
		}
 
		if (size >= 64) {
			chunk = ProcessBlock(ctx, chunk, size & ~(unsigned long)0x3f);
			size &= 0x3f;
		}
 
		memcpy(ctx->buffer, chunk, size);
	}
	// Метод получения результирующей подписи
	void RawResult(unsigned char *result)
	{
		unsigned long used, available;
 
		used = ctx->lo & 0x3f;
 
		ctx->buffer[used++] = 0x80;
 
		available = 64 - used;
 
		if (available < 8) {
			memset(&ctx->buffer[used], 0, available);
			ProcessBlock(ctx, ctx->buffer, 64);
			used = 0;
			available = 64;
		}
 
		memset(&ctx->buffer[used], 0, available - 8);
 
		ctx->lo <<= 3;
		ctx->buffer[56] = ctx->lo;
		ctx->buffer[57] = ctx->lo >> 8;
		ctx->buffer[58] = ctx->lo >> 16;
		ctx->buffer[59] = ctx->lo >> 24;
		ctx->buffer[60] = ctx->hi;
		ctx->buffer[61] = ctx->hi >> 8;
		ctx->buffer[62] = ctx->hi >> 16;
		ctx->buffer[63] = ctx->hi >> 24;
 
		ProcessBlock(ctx, ctx->buffer, 64);
 
		result[0] = ctx->a;
		result[1] = ctx->a >> 8;
		result[2] = ctx->a >> 16;
		result[3] = ctx->a >> 24;
		result[4] = ctx->b;
		result[5] = ctx->b >> 8;
		result[6] = ctx->b >> 16;
		result[7] = ctx->b >> 24;
		result[8] = ctx->c;
		result[9] = ctx->c >> 8;
		result[10] = ctx->c >> 16;
		result[11] = ctx->c >> 24;
		result[12] = ctx->d;
		result[13] = ctx->d >> 8;
		result[14] = ctx->d >> 16;
		result[15] = ctx->d >> 24;
 
		memset(ctx, 0, sizeof(*ctx));
	}
};