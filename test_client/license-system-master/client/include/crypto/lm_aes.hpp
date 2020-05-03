#ifndef AES_HPP
#define AES_HPP
#include "stdafx.hpp"

namespace crypto
{
	class aes
	{
	public:
		class key_pair
		{
		public:
			key_pair();
			key_pair(const std::string& key, const std::string& iv);

			bool load_iv(const std::string& iv);
			bool load_key(const std::string& key);

			std::string get_key() const;

			std::string get_iv() const;

			void generate();

			CryptoPP::SecByteBlock m_key;

			CryptoPP::SecByteBlock m_iv;
		};

		static std::string encrypt(const std::string& plain,
		                           const std::string& key,
		                           const std::string& iv);
		static std::string encrypt(const std::string& plain,
		                           const uint8_t* key,
		                           size_t key_size,
		                           const uint8_t* iv,
		                           size_t iv_size);

		static std::string encrypt(const std::string& plain,
		                           key_pair& kp);
		static std::string decrypt(const std::string& cipher,
		                           const std::string& key,
		                           const std::string& iv);

		static std::string decrypt(const std::string& cipher,
		                           const uint8_t* key,
		                           size_t key_size,
		                           const uint8_t* iv,
		                           size_t iv_size);
		static std::string decrypt(const std::string& cipher,
		                           key_pair& kp);
	};
}
#endif // AES_HPP
