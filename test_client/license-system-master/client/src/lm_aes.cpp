#include "crypto/lm_aes.hpp"
#include "crypto/lm_base64.hpp"

using namespace crypto;

aes::key_pair::key_pair()
{
	generate();
}

aes::key_pair::key_pair(const std::string& key,
                        const std::string& iv)
{
	load_key(key);
	load_iv(iv);
}

bool aes::key_pair::load_iv(const std::string& iv)
{
	const auto encoded = base64::decode_binary(iv);
	if (encoded.empty())
	{
		return false;
	}

	m_iv = CryptoPP::SecByteBlock(encoded.data(), encoded.size());
	return true;
}

bool aes::key_pair::load_key(const std::string& key)
{
	const auto encoded = base64::decode_binary(key);
	if (encoded.empty())
	{
		return false;
	}

	m_key = CryptoPP::SecByteBlock(encoded.data(), encoded.size());
	return true;
}

std::string aes::key_pair::get_key() const
{
	return base64::encode(m_key.data(), m_key.size(), false);
}

std::string aes::key_pair::get_iv() const
{
	return base64::encode(m_iv.data(), m_iv.size(), false);
}

void aes::key_pair::generate()
{
	CryptoPP::AutoSeededRandomPool rng;
	m_key = CryptoPP::SecByteBlock(CryptoPP::AES::MAX_KEYLENGTH);
	m_iv = CryptoPP::SecByteBlock(CryptoPP::AES::BLOCKSIZE);

	rng.GenerateBlock(m_key, m_key.size());
	rng.GenerateBlock(m_iv, m_iv.size());
}

std::string aes::encrypt(const std::string& plain,
                         const std::string& key,
                         const std::string& iv)
{
	if (plain.empty() || key.empty() || iv.empty())
	{
		return "";
	}

	key_pair kp(key, iv);
	return encrypt(plain, kp);
}

std::string aes::encrypt(const std::string& plain,
                         const uint8_t* key,
                         const size_t key_size,
                         const uint8_t* iv,
                         const size_t iv_size)
{
	std::string cipher;
	if (!plain.empty() && key && key_size > 0 && iv && iv_size > 0)
	{
		try
		{
			CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
			enc.SetKeyWithIV(key, key_size, iv, iv_size);
			CryptoPP::AuthenticatedEncryptionFilter aef(enc,
			                                            new CryptoPP::StringSink(cipher));
			aef.Put(reinterpret_cast<const uint8_t*>(plain.data()), plain.size());
			aef.MessageEnd();
			return base64::encode(cipher);
		}
		catch (const CryptoPP::Exception& e)
		{
			tfm::printfln("AES::encrypt() throwed an exception from CryptoPP: %s", e.what());
		}
	}
	return cipher;
}

std::string aes::encrypt(const std::string& plain,
                         key_pair& kp)
{
	return encrypt(plain,
	               kp.m_key.data(),
	               kp.m_key.size(),
	               kp.m_iv.data(),
	               kp.m_iv.size());
}

std::string aes::decrypt(const std::string& cipher,
                         const std::string& key,
                         const std::string& iv)
{
	if (cipher.empty() || key.empty() || iv.empty())
	{
		return "";
	}

	key_pair kp(key, iv);
	return decrypt(cipher, kp);
}

std::string aes::decrypt(const std::string& cipher,
                         const uint8_t* key,
                         const size_t key_size,
                         const uint8_t* iv,
                         const size_t iv_size)
{
	std::string plain;
	if (!cipher.empty() && key && key_size > 0 && iv && iv_size > 0)
	{
		try
		{
			const auto decoded_cipher = base64::decode_binary(cipher);
			CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
			dec.SetKeyWithIV(key, key_size, iv, iv_size);
			CryptoPP::AuthenticatedDecryptionFilter adf(dec,
			                                            new CryptoPP::StringSink(
				                                            plain));
			adf.Put(decoded_cipher.data(), decoded_cipher.size());
			adf.MessageEnd();
		}
		catch (const CryptoPP::Exception& e)
		{
			tfm::printfln("AES::decrypt() throwed an exception from CryptoPP: %s", e.what());
		}
	}
	return plain;
}

std::string aes::decrypt(const std::string& cipher,
                         key_pair& kp)
{
	return decrypt(cipher,
	               kp.m_key.data(),
	               kp.m_key.size(),
	               kp.m_iv.data(),
	               kp.m_iv.size());
}
