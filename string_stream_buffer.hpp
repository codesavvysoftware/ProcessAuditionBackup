#pragma once
#include <streambuf>
#include <vector>
#include <string>
namespace ReusableClasses {
	class string_stream_buffer : public std::streambuf 
	{
	public:
		explicit string_stream_buffer(std::string str);
		string_stream_buffer & string_stream_buffer::operator= (std::string str);

	private:
		std::streambuf::int_type  underflow();
		std::streambuf::int_type  uflow();
		std::streambuf::int_type  pbackfail(std::streambuf::int_type);
		std::streamsize           showmanyc();
		void                      PutStringInBuffer(const std::string str);

		string_stream_buffer(const string_stream_buffer &);
		string_stream_buffer & operator= (string_stream_buffer);

		std::vector<char> buffer_;
		char * begin_;
		char * end_;
		char * current_;
		std::size_t put_back_;
	};

}