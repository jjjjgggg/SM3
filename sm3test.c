#include "sm3.h"

int main(int argc, char *argv[])
{
	unsigned char Hash[32]={0};

//	unsigned char Hash[33]={0};
//	printf("%s\n",Hash);

	char* str="abc";
	//66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0
	int len;
	len=strlen(str);
	if(!SM3(str, len, Hash))
		printf("1 false\n");
	char *str2 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
	//debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732
	len=strlen(str2);
	if(!SM3(str2, len, Hash))
		printf("2 false\n");
	return 0;
}
