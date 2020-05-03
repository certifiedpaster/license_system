#include "lm_licenser.hpp"
#ifndef WEB_ENCODER
#include "crypto/lm_base64.hpp"

lm_licenser::lm_licenser(const std::string& server_url)
{
	m_socket_.set_server_url(server_url);
}

bool lm_licenser::user_login(const std::string& username, const std::string& password)
{
	if (username.empty() || password.empty())
	{
		return false;
	}
	if (!m_hwid_.query())
	{
		return msg_box("failed to get the wmic hwid");
	}

	std::string response;
	if (!m_socket_.http_get(php_file, build_query(request::login, [&]
	{
		nlohmann::json j, hwid;

		hwid["cpu"] = m_hwid_.cpu();
		hwid["computer_name"] = m_hwid_.computer_name();
		hwid["physical_hdd_serial"] = m_hwid_.physical_hdd_serial();

		j["username"] = username;
		j["password"] = password;
		j["hwid"] = hwid;

		return j;
	}()), response))
	{
		return msg_box("failed to sent GET request");
	}
	if (response.empty() || !response.compare("forbidden"))
	{
		return msg_box("failed to parse response");
	}
	try
	{
		auto j = nlohmann::json::parse(decrypt(response));
		const auto code = j.at("code").get<size_t>();
		if (code != license_code::valid)
		{
			switch (code)
			{
			case license_code::invalid_user:
			case license_code::invalid_password:
				return msg_box("invalid username or password");

			case license_code::invalid_hwid:
				return msg_box("invalid hardware id");

			case license_code::banned:
				return msg_box("rekt m8, you're banned");

			default:
				// fuck %d / %lld(for x64) -> strings be St e
				return msg_box("operation failed, error: %s", std::to_string(code));
			}
		}
	}
	catch (const std::exception& e)
	{
		return msg_box("operation failed, error: %s\nException: %s",
		               std::to_string(license_code::exception),
		               e.what()
		);
	}
	return true;
}

bool lm_licenser::load_rsa_public_key(const std::string& key)
{
	return m_rsa_.load_public(key);
}

lm_licenser::licenser_t lm_licenser::create_licenser(const std::string& server_url, const std::string& rsa_public_key)
{
	if (server_url.empty() || rsa_public_key.empty())
	{
		return nullptr;
	}
	auto licenser = std::make_unique<lm_licenser>(server_url);
	return licenser->load_rsa_public_key(rsa_public_key)
		       ? std::move(licenser)
		       : nullptr;
}

std::string lm_licenser::build_query(const request request, const nlohmann::json& init_data)
{
	m_aes_.generate();

	auto j = init_data;
	j["request"] = std::to_string(static_cast<size_t>(request));
	encrypt_json(j);

	j["key"] = m_aes_.get_key();
	j["iv"] = m_aes_.get_iv();

	std::stringstream ss;
	ss << get_parameter
		<< "="
		<< crypto::base64::url_encode(encrypt(j.dump(), true));

	return ss.str();
}

std::string lm_licenser::encrypt(const std::string& data, const bool rsa)
{
	return rsa
		       ? crypto::rsa::encrypt(data, m_rsa_)
		       : crypto::aes::encrypt(data, m_aes_);
}

std::string lm_licenser::decrypt(const std::string& cipher, const bool rsa)
{
	return rsa
		       ? crypto::rsa::decrypt(cipher, m_rsa_)
		       : crypto::aes::decrypt(cipher, m_aes_);
}

void lm_licenser::encrypt_json(nlohmann::json& j)
{
	for (auto& j_data : j)
	{
		if (j_data.is_string())
		{
			j_data = encrypt(j_data.get<std::string>());
		}
		else if (j_data.is_object())
		{
			encrypt_json(j_data);
		}
	}
}

#endif
