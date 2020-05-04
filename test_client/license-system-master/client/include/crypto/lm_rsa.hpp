#ifndef RSA_HPP
#define RSA_HPP
#include "stdafx.hpp"

namespace crypto
{
	class rsa
	{
	public:
		class key_pair
		{
		public:
			key_pair() = default;

			bool load_public(const std::string& key);
			bool load_private(const std::string& key);

			std::string get_private() const;
			std::string get_public() const;

			CryptoPP::SecByteBlock m_pub;
			CryptoPP::SecByteBlock m_priv;
		};

		static std::string encrypt(const std::string& plain, key_pair& kp);

		static std::string encrypt(const std::string& plain,
		                           const std::string& public_key,
		                           bool public_key_as_base64 = false);

		static std::string encrypt(const std::string& plain,
		                           const uint8_t* public_key,
		                           size_t public_key_size);

		static std::string decrypt(const std::string& cipher, key_pair& kp);

		static std::string decrypt(const std::string& cipher,
		                           const std::string& private_key,
		                           bool private_key_as_base64 = false);

		static std::string decrypt(const std::string& cipher,
		                           const uint8_t* private_key,
		                           size_t private_key_size);
	};
}
#endif // RSA_HPP
