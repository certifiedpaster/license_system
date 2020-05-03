#include "license-system-master/client/include/lm_licenser.hpp"

static const constexpr char* rsa_public =
	"MIICHDANBgkqhkiG9w0BAQEFAAOCAgkAMIICBAKCAfsAw2WwPyhgFXCHb7XPwzDbQ+y6Qq5b9fZkwhLI5AdTHq8l3646eKsmUMJr+/sUWSpGpOZwiYfkJTqA+fj3RtxK6zWEu3C/GCbPLD7gZc/WSE5GzLjqFCN9aTvlSwlTDtulzjPJ4aFxmAXoZjdnOfc9r1yDTBrEFamVTZeS9R0ydTZzTu27hr499E1epSzAWuOCd9/WD97BY0Ua7B18Hpgy7kz1eb/MXm38RxVIeZkf0CJXfhsLKlyelrD2YEUa+j4L8MpgsUytSrKZqEWfJgBjFa82KD8awMiYV+buoDI/1Pgf9P21u2azS0yYaKz3UhBu1myx6sV/zz1zz4qg4zcfAzyM01ZWqfTW0uwU1x38DJ/0WhUSrlL6WuhB0Y8e6MqFK2aqBzUsmR2va7FJdRQEx72x5KxRUBRZhZwGGOXFTU0fS8xR3P9Vm7NG59OEUoIjyhopcjihaczFCNCXT1cJTSUIMIy3bDpKKVulhOKDGcA/OWhoOww8J/aopHp1X5Rh/IVFEEu55x+KGsA309UZqZaHrVIvGhf6xxCvGqBM2iI/Ps8+7V851liPXC41z2RpP7QziSIO8sX1Bz0/bThSPgowmH34rboIeUmX3NVWfiHQ4qhCoDOEMuKN+ehsZkIz2mQXF9zVJ+AN+5UhSRIJgZNLmk+9m2IXMdsCAwEAAQ==";

int main()
{
	auto licenser = lm_licenser::create_licenser("192.168.0.102", rsa_public);

	if (!licenser)
	{
		return EXIT_FAILURE;
	}

	if (!licenser->user_login("ReactiioN", "very_strong_pass"))
	{
		return EXIT_FAILURE;
	}

	tfm::printfln("Logged in successfully.");

	std::cin.get();

	return EXIT_SUCCESS;
}
