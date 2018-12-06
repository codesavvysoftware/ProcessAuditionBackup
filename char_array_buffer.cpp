#include "char_array_buffer.hpp"

namespace ReusableClasses {
	char_array_buffer::char_array_buffer(const char *data, unsigned int len)
		: begin_(data), end_(data + len), current_(data) { 
		setg(const_cast<char *>(begin_), const_cast<char *>(current_), const_cast<char *>(end_));

	}

	char_array_buffer::int_type char_array_buffer::underflow() {
		if (current_ == end_) {
			return traits_type::eof();
		}
		return traits_type::to_int_type(*current_);     // HERE!
	}

	char_array_buffer::int_type char_array_buffer::uflow() {
		if (current_ == end_) {
			return traits_type::eof();
		}
		return traits_type::to_int_type(*current_++);   // HERE!
	}

	char_array_buffer::int_type char_array_buffer::pbackfail(int_type ch) {
		if (current_ == begin_ || (ch != traits_type::eof() && ch != current_[-1])) {
			return traits_type::eof();
		}
		return traits_type::to_int_type(*--current_);   // HERE!
	}

	std::streamsize char_array_buffer::showmanyc() {
		return end_ - current_;
	}
	int char_array_buffer::sync() {
		if (current_ == end_) {
			return -1;
		}
		return 0;   // HERE!

	}
	std::streambuf* char_array_buffer::setbuf(char* s, std::streamsize n)
	{
		return this;
	}
	std::streamsize char_array_buffer::xsgetn(char* s, std::streamsize n)
	{
		for (unsigned int ui = 0; ui < 5; ui++)
		{
			s[ui] = ui;
		}

		return 5;
	}

}