#ifndef WMICHWID_HPP
#define WMICHWID_HPP
#include "stdafx.hpp"

#ifndef WEB_ENCODER

class wmic_hwid
{
public:
	wmic_hwid() = default;
	bool query();
	inline const std::string& cpu() const;

	inline const std::string& computer_name() const;

	inline const std::string& physical_hdd_serial() const;

private:
	static bool query_wmic(const std::string& input,
	                       std::string& out);

protected:
	std::string m_cpu_;
	std::string m_computer_name_;
	std::string m_physical_;
};

inline const std::string& wmic_hwid::cpu() const
{
	return m_cpu_;
}

inline const std::string& wmic_hwid::computer_name() const
{
	return m_computer_name_;
}

inline const std::string& wmic_hwid::physical_hdd_serial() const
{
	return m_physical_;
}

#endif
#endif // WMICHWID_HPP
