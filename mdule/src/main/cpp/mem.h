#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <unistd.h> 
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>

uintptr_t getModuleBase(const char *module_name)
{
	FILE *fp;
	uintptr_t addr = 0;
	char buffer[1024];
	fp = fopen("/proc/self/maps", "rt");
	if (fp != nullptr)
	{
		while (fgets(buffer, sizeof(buffer), fp))
		{
			if (strstr(buffer, module_name))
			{
#if defined(__LP64__)
				sscanf(buffer, "%lx-%*s", &addr);
#else
				sscanf(buffer, "%x-%*s", &addr);
#endif
				break;
			}
		}
		fclose(fp);
	}
	return addr;
}
