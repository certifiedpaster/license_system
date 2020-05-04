#include "license-system-master/client/include/lm_licenser.hpp"

static const constexpr char* rsa_public =
	""; // paste key

int main()
{
	auto licenser = lm_licenser::create_licenser("192.168.0.102", rsa_public);

	if (!licenser)
	{
		return EXIT_FAILURE;
	}

	if (!licenser->user_login("jiqwejadjdi", "@4M#zrt7uJKbR`t"))
	{
		return EXIT_FAILURE;
	}

	tfm::printfln("Logged in successfully.");

	std::cin.get();

	return EXIT_SUCCESS;
}
