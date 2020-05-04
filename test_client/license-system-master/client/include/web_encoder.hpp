#ifndef WEBENCODER_HPP
#define WEBENCODER_HPP
#include "stdafx.hpp"
#if defined(WEB_ENCODER)
#include "crypto/lm_rsa.hpp"
#include "crypto/lm_aes.hpp"

class WebEncoder
{
public:
	WebEncoder();

	int32_t handle(int32_t argc, char** argv);

private:
	int32_t handle_encryption();
	int32_t handle_decryption();
	int32_t handle_generate_aes_key_pair();

	std::string encrypt(const std::string& data, const bool rsa);
	std::string decrypt(const std::string& cipher, const bool rsa);
	std::string generate_key_pair();

	template <int32_t exit_code = EXIT_FAILURE, typename ...Args>
	static int32_t leave_msg(const char* msg, const Args& ...args);

protected:
	cxxopts::Options m_Options;
	crypto::AES::KeyPair m_AES;
	crypto::RSA::KeyPair m_RSA;
};

#endif
#endif // WEBENCODER_HPP
