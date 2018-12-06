#pragma once
#include <streambuf>
namespace ReusableClasses {
	class char_array_buffer : public std::streambuf {
	public:
		char_array_buffer(const char *data, unsigned int len);

	protected:
		int_type underflow();
		int_type uflow();
		int_type pbackfail(int_type ch);
		std::streamsize showmanyc();
		int sync();
		std::streambuf * setbuf(char* s, std::streamsize n);
		std::streamsize xsgetn(char* s, std::streamsize n);

	private:
		const char * const begin_;
		const char * const end_;
		const char * current_;
	};
}

