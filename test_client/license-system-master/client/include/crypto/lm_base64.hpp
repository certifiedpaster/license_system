#ifndef BASE64_HPP
#define BASE64_HPP
#include "stdafx.hpp"

namespace crypto
{
	class base64
	{
		using binary_t = std::vector<uint8_t>;

	public:
		static std::string url_encode(const std::string& input);

		static std::string encode(const std::string& plain,
		                          bool encode_for_url = false);

		static std::string encode(const uint8_t* data,
		                          size_t length,
		                          bool encode_for_url = false);

		static std::string decode(const std::string& encoded);

		static binary_t decode_binary(const std::string& encoded);
	};
}
#endif // BASE64_HPP
