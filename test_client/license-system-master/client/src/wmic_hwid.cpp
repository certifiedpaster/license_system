#include "wmic_hwid.hpp"
#ifndef WEB_ENCODER

bool wmic_hwid::query()
{
	auto strip_keyword = [](std::string& buffer, const bool filter_digits = false)
	{
		std::string current, stripped;
		std::istringstream iss(buffer);

		buffer.clear();
		auto first_tick = false;
		while (std::getline(iss, current))
		{
			if (!first_tick)
			{
				first_tick = true;
				continue;
			}
			if (filter_digits && std::isdigit(current.at(0)))
			{
				continue;
			}

			buffer.append(current).append("\n");
		}
		if (buffer.back() == '\n')
		{
			buffer.pop_back();
		}
	};

	if (!query_wmic("wmic cpu get name", m_cpu_) ||
		!query_wmic("WMIC OS GET CSName", m_computer_name_) ||
		!query_wmic("WMIC diskdrive get SerialNumber", m_physical_))
	{
		return false;
	}

	strip_keyword(m_cpu_);
	strip_keyword(m_computer_name_);
	strip_keyword(m_physical_, true);

	return true;
}

bool wmic_hwid::query_wmic(const std::string& input, std::string& out)
{
	auto* shell_cmd = _popen(input.c_str(), "r");
	if (!shell_cmd)
	{
		return false;
	}

	static char buffer[1024] = {};
	while (fgets(buffer, 1024, shell_cmd))
	{
		out.append(buffer);
	}

	_pclose(shell_cmd);
	while (out.back() == '\n' ||
		out.back() == '\0' ||
		out.back() == ' ' ||
		out.back() == '\r' ||
		out.back() == '\t')
	{
		out.pop_back();
	}

	return !out.empty();
}

#endif
