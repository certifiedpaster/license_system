#ifndef SOCKET_HPP
#define SOCKET_HPP
#include "stdafx.hpp"

#ifndef WEB_ENCODER

class lm_socket
{
public:
	static constexpr uintptr_t socket_invalid = static_cast<uintptr_t>(~0);

private:
	using socket_t = uintptr_t;

public:
	lm_socket() = default;

	explicit lm_socket(const std::string& server_url);

	bool http_get(const std::string& file,
	              const std::string& data,
	              std::string& response);

	bool is_valid() const;

	inline const std::string& get_server_url() const;

	inline void set_server_url(const std::string& server_url);

private:
	template <bool Ret = false>
	bool free_socket_data(bool clear = true,
	                      bool disconnect = false,
	                      void** addr_info_data = nullptr);

protected:
	uintptr_t m_socket_ = socket_invalid;
	std::string m_server_url_;
};

inline const std::string& lm_socket::get_server_url() const
{
	return m_server_url_;
}

inline void lm_socket::set_server_url(const std::string& server_url)
{
	m_server_url_ = server_url;
}

#endif
#endif // SOCKET_HPP
