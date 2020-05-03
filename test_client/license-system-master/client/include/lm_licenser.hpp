#ifndef LICENSER_HPP
#define LICENSER_HPP
#include "crypto/lm_aes.hpp"
#include "crypto/lm_rsa.hpp"

#ifndef WEB_ENCODER
#include "lm_socket.hpp"
#include "wmic_hwid.hpp"

enum license_code : size_t
{
	valid = 0,
	exception = 1,
	failed_to_send_request = 2,
	failed_to_parse_response = 3,
	invalid_hwid = 4,
	invalid_password = 5,
	invalid_user = 6,
	banned = 7,
	failed_to_build_hwid_hash = 8,
	server_failed_to_encrypt_data = 9,
	mysql_failed_to_update_password = 10,
	mysql_failed_to_incremet_counter = 11,
	mysql_failed_to_reset_counter = 12,
	mysql_failed_to_update_hwid = 13,
};

enum class request : size_t
{
	login = 0,
};

class lm_licenser
{
	static const constexpr char* php_file = "auth.php";

	static const constexpr char* get_parameter = "data";

	using aes_key_pair_t = crypto::aes::key_pair;
	using rsa_key_pair_t = crypto::rsa::key_pair;
	using licenser_t = std::unique_ptr<lm_licenser>;

public:
	lm_licenser() = delete;

	explicit lm_licenser(const std::string& server_url);

	bool user_login(const std::string& username,
	                const std::string& password);
	bool load_rsa_public_key(const std::string& key);

	static licenser_t create_licenser(const std::string& server_url,
	                                  const std::string& rsa_public_key);
	template <bool KillProcess = true, typename ...Args>
	static bool msg_box(const char* msg,
	                    const Args& ...args);

private:
	std::string encrypt(const std::string& data,
	                    const bool rsa = false);

	std::string decrypt(const std::string& cipher,
	                    const bool rsa = false);
	std::string build_query(const request request,
	                        const nlohmann::json& init_data = {});
	void encrypt_json(nlohmann::json& j);

protected:
	aes_key_pair_t m_aes_;
	rsa_key_pair_t m_rsa_;
	wmic_hwid m_hwid_;
	lm_socket m_socket_;
};

template <bool KillProcess, typename ...Args>
bool lm_licenser::msg_box(const char* msg,
                       const Args& ...args)
{
	MessageBoxA(nullptr, tfm::format(msg, args...).c_str(), "Error", MB_ICONERROR);
	if (KillProcess)
	{
		quick_exit(EXIT_FAILURE);
	}
	return false;
}

#endif
#endif // LICENSER_HPP
