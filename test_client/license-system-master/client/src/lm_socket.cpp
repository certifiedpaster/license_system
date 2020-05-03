#include "lm_socket.hpp"

#ifndef WEB_ENCODER
lm_socket::lm_socket(const std::string& server_url) :
	m_server_url_(server_url)
{
}

bool lm_socket::http_get(const std::string& file,
                      const std::string& data,
                      std::string& response)
{
	if (file.empty() || data.empty())
	{
		return false;
	}

	auto query = file;
	if (query.back() != '?' || data.front() != '?')
	{
		query.append("?");
	}
	query.append(data);

	WSADATA win_socket_data;
	if (WSAStartup(MAKEWORD(2, 2), &win_socket_data) != 0)
	{
		return false;
	}

	addrinfo hints, *addr_info;
	RtlSecureZeroMemory(&hints, sizeof(hints));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (getaddrinfo(m_server_url_.c_str(), "80", &hints, &addr_info) != 0)
	{
		return free_socket_data();
	}

	m_socket_ = socket(addr_info->ai_family,
	                  addr_info->ai_socktype,
	                  addr_info->ai_protocol);
	if (m_socket_ == socket_invalid)
	{
		return free_socket_data(true, false, reinterpret_cast<void**>(&addr_info));
	}
	if (connect(m_socket_,
	            addr_info->ai_addr,
	            static_cast<int32_t>(addr_info->ai_addrlen)) != 0)
	{
		return free_socket_data(true, true, reinterpret_cast<void**>(&addr_info));
	}
	freeaddrinfo(addr_info);

	std::string http_header = "GET /";
	http_header.append(query).append(" HTTP/1.0\r\nHost: ").append(m_server_url_);

	// Append \r\n\r\n to our response to identfy the end of the http header inside the response
	http_header.append("\r\n\r\n");

	std::array<char, 512> buffer;
	if (send(m_socket_,
	         http_header.c_str(),
	         static_cast<int32_t>(http_header.size()), 0) == SOCKET_ERROR)
	{
		return free_socket_data(true, true);
	}

	size_t bytes_received;
	do
	{
		bytes_received = static_cast<size_t>(recv(m_socket_,
		                                          buffer.data(),
		                                          buffer.size(), 0));
		response.append(buffer.data(), bytes_received);
	}
	while (bytes_received > 0);
	for (size_t i = 0; i < response.length() - 4; ++i)
	{
		if (response.at(i) == '\r' &&
			response.at(i + 1) == '\n' &&
			response.at(i + 2) == '\r' &&
			response.at(i + 3) == '\n')
		{
			response = response.substr(i + 4, response.length());
			break;
		}
	}

	return free_socket_data<true>(true, true);
}

bool lm_socket::is_valid() const
{
	return m_socket_ != socket_invalid;
}

template <bool Ret>
bool lm_socket::free_socket_data(const bool clear,
                              const bool disconnect,
                              void** addr_info_data)
{
	if (addr_info_data && *addr_info_data)
	{
		freeaddrinfo(static_cast<addrinfo*>(*addr_info_data));
	}
	if (disconnect && is_valid())
	{
		closesocket(static_cast<SOCKET>(m_socket_));
		m_socket_ = socket_invalid;
	}
	if (clear)
	{
		WSACleanup();
	}
	return Ret;
}

#endif
