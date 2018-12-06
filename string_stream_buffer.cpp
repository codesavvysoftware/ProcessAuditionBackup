#include "string_stream_buffer.hpp"

namespace ReusableClasses {
	string_stream_buffer::string_stream_buffer(std::string str) : put_back_(std::size_t(1))
	{
		PutStringInBuffer(str);
	}
	ReusableClasses::string_stream_buffer & string_stream_buffer::operator= (std::string str)
	{
		PutStringInBuffer(str);

		return *this;
	}

	void string_stream_buffer::PutStringInBuffer(std::string str)
	{
		buffer_.clear();

		std::copy(str.begin(), str.end(), std::back_inserter(buffer_));

		end_ = &buffer_.front() + buffer_.size();

		begin_ = &buffer_.front();

		current_ = &buffer_.front();

		//setg(begin_, end_, end_);
	}
	std::streambuf::int_type string_stream_buffer::underflow()
	{
		if (current_ == end_)
			return traits_type::eof();

		return traits_type::to_int_type(*current_);
	}

	std::streambuf::int_type string_stream_buffer::uflow()
	{
		if (current_ == end_)
			return traits_type::eof();

		return traits_type::to_int_type(*current_++);
	}

	std::streambuf::int_type string_stream_buffer::pbackfail(std::streambuf::int_type ch)
	{
		if ((current_ == begin_) || (ch != traits_type::eof()) || (ch != current_[-1]))
			return traits_type::eof();

		return traits_type::to_int_type(*--current_);
	}

	std::streamsize string_stream_buffer::showmanyc()
	{
		return end_ - current_;
	}
}