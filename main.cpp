#include <unistd.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <stdint.h>
#include "openssl/sha.h"
#include "SHA1.h"
#include "MD5ex.h"
#include "SHA256.h"
#include "SHA512ex.h"
#include "MD4ex.h"

using namespace std;

vector<unsigned char> StringToVector(unsigned char *str)
{
	vector<unsigned char> ret;
	for (unsigned int x = 0; x < strlen((char *)str); x++)
	{
		ret.push_back(str[x]);
	}
	return ret;
}

void DigestToRaw(string hash, unsigned char *raw)
{
	transform(hash.begin(), hash.end(), hash.begin(), ::tolower);
	string alpha("0123456789abcdef");
	for (unsigned int x = 0; x < (hash.length() / 2); x++)
	{
		raw[x] = (unsigned char)((alpha.find(hash.at((x * 2))) << 4));
		raw[x] |= (unsigned char)(alpha.find(hash.at((x * 2) + 1)));
	}
}

vector<unsigned char> *GenerateRandomData()
{
	vector<unsigned char> *ret = new vector<unsigned char>();
	int length = rand() % 128;
	for (int x = 0; x < length; x++)
	{
		ret->push_back((rand() % (126 - 32)) + 32);
	}
	return ret;
}

void TestExtender(Extender *sex)
{
	// First generate a signature, with randomly generated data
	vector<unsigned char> *vkey = GenerateRandomData();
	vector<unsigned char> *vmessage = GenerateRandomData();
	vector<unsigned char> *additionalData = GenerateRandomData();
	unsigned char *firstSig;
	unsigned char *secondSig;
	sex->GenerateSignature(*vkey, *vmessage, &firstSig);
	if (sex->ValidateSignature(*vkey, *vmessage, firstSig))
	{
		vector<unsigned char> *newData = sex->GenerateStretchedData(*vmessage, vkey->size(), firstSig, *additionalData, &secondSig);
		if (sex->ValidateSignature(*vkey, *newData, secondSig))
		{
			cout << "\tTest passed." << endl;
			delete vkey;
			delete vmessage;
			delete additionalData;
			delete newData;
			return;
		}
		else
		{
			cout << "\tGenerated data failed to be verified as correctly signed." << endl;
			delete vkey;
			delete vmessage;
			delete additionalData;
			delete newData;
			return;
		}
	}
	else
	{
		cout << "\tInitial signature check failed." << endl;
		delete vkey;
		delete vmessage;
		delete additionalData;
		return;
	}
}

Extender *GetExtenderForHash(string sig)
{
	if (sig.length() == 40)
	{
		return new SHA1ex();
	}
	else if (sig.length() == 64)
	{
		return new SHA256ex();
	}
	else if (sig.length() == 32)
	{
		return new MD5ex();
	}
	else if (sig.length() == 128)
	{
		return new SHA512ex();
	}
	return NULL;
}

void PrintHelp()
{
	cout << "HashPump [-h help] [-t test] [-s signature] [-d data] [-a additional] [-k keylength]" << endl;
	cout << "     HashPump generates strings to exploit signatures vulnerable to the Hash Length Extension Attack." << endl;
	cout << "     -h --help          Display this message." << endl;
	cout << "     -t --test          Run tests to verify each algorithm is operating properly." << endl;
	cout << "     -s --signature     The signature from known message." << endl;
	cout << "     -d --data          The data from the known message." << endl;
	cout << "     -a --additional    The information you would like to add to the known message." << endl;
	cout << "     -k --keylength     The length in bytes of the key being used to sign the original message with." << endl;
	cout << "     -u --unknown     number if leading hash bits unknown (EXPERIMENTAL HACK)" << endl;
	cout << "     -z --sig2     target signature (EXPERIMENTAL HACK)" << endl;
	cout << "     Version 1.0 with MD5, SHA1, SHA256 and SHA512 support." << endl;
	cout << "     <Developed by bwall(@bwallHatesTwits)>" << endl;
}

int main(int argc, char **argv)
{
	string sig, sig2;
	string data;
	int keylength = 0;
	int unknown = 0;
	string datatoadd;
	Extender *sex = NULL;
	bool run_tests = false;

	while (1)
	{
		int option_index = 0;
		static struct option long_options[] = {
			{"test", no_argument, 0, 0},
			{"signature", required_argument, 0, 0},
			{"data", required_argument, 0, 0},
			{"additional", required_argument, 0, 0},
			{"keylength", required_argument, 0, 0},
			{"unknown", required_argument, 0, 0},
			{"sig2", required_argument, 0, 0},
			{"help", no_argument, 0, 0},
			{0, 0, 0, 0}};

		int c = getopt_long(argc, argv, "ts:d:a:k:u:z:h", long_options, &option_index);
		if (c == -1)
			break;

		switch (c)
		{
		case 0:
			switch (option_index)
			{
			case 0:
			case 't':
				run_tests = true;
				break;
			case 1:
				sig.assign(optarg);
				break;
			case 2:
				data.assign(optarg);
				break;
			case 3:
				datatoadd.assign(optarg);
				break;
			case 4:
				keylength = atoi(optarg);
				break;
			case 5:
				unknown = atoi(optarg);
				break;
			case 6:
				sig2.assign(optarg);
				break;
			case 7:
				PrintHelp();
				return 0;
			}
			break;
			run_tests = true;
			break;
		case 's':
			sig.assign(optarg);
			break;
		case 'd':
			data.assign(optarg);
			break;
		case 'a':
			datatoadd.assign(optarg);
			break;
		case 'k':
			keylength = atoi(optarg);
			break;
		case 'u':
			unknown = atoi(optarg);
			break;
		case 'z':
			sig2.assign(optarg);
			break;
		case 'h':
			PrintHelp();
			return 0;
		}
	}

	if (run_tests)
	{
		// Just a simple way to force tests
		cout << "Testing SHA1" << endl;
		TestExtender(new SHA1ex());

		cout << "Testing SHA256" << endl;
		TestExtender(new SHA256ex());

		cout << "Testing SHA512" << endl;
		TestExtender(new SHA512ex());

		cout << "Testing MD5" << endl;
		TestExtender(new MD5ex());

		cout << "Testing MD4" << endl;
		TestExtender(new MD4ex());

		cout << "Testing concluded" << endl;
		return 0;
	}

	if (sig.size() == 0)
	{
		cout << "Input Signature: ";
		cin >> sig;
		sex = GetExtenderForHash(sig);
		if (sex == NULL)
		{
			cout << "Unsupported hash size." << endl;
			return 0;
		}
	}

	if (data.size() == 0)
	{
		cout << "Input Data: ";
		cin >> data;
	}

	if (keylength == 0)
	{
		cout << "Input Key Length: ";
		cin >> keylength;
	}

	if (datatoadd.size() == 0)
	{
		cout << "Input Data to Add: ";
		cin >> datatoadd;
	}

	vector<unsigned char> vmessage = StringToVector((unsigned char *)data.c_str());
	vector<unsigned char> vtoadd = StringToVector((unsigned char *)datatoadd.c_str());

	unsigned char firstSig[128];
	unsigned char targetSig[128];
	DigestToRaw(sig, firstSig);
	DigestToRaw(sig2, targetSig);
	unsigned char *secondSig = 0;

	sex = GetExtenderForHash(sig);
	if (sex == NULL)
	{
		cout << "Unsupported signature size." << endl;
		return 0;
	}
	uint32_t maxval = 1 << unknown;
	uint32_t mask = ~((1 << (unknown)) - 1);
	printf("mask: %x\n", mask);
	vector<unsigned char> *secondMessage = 0;
	uint32_t *sigStart = (uint32_t *)&firstSig;
	uint32_t part1 = htonl(*sigStart);
	for (uint32_t prefix = 0; prefix <= maxval; prefix++)
	{
		if (prefix % (1 << 20) == 0)
		{
			float part = (float)prefix / maxval;
			printf("progress: 0x%16x, %.4f: ", prefix, part);
#define WIDTH 40
			for (int i = 0; i < WIDTH; i++)
			{
				if (float(i) / WIDTH < part)
					printf("=");
				else
				{
					printf(" ");
				}
			}
			printf("|\r");
			fflush(stdout);
		}
		uint32_t shiftedPrefix = prefix << (32 - unknown);
		*sigStart = htonl(part1 | shiftedPrefix);

		// all this allocation and deallocation is a stupid idea
		if (secondSig)
			delete[] secondSig;
		if (secondMessage)
			delete secondMessage;
		secondMessage = sex->GenerateStretchedData(vmessage, keylength, firstSig, vtoadd, &secondSig);
		// cheating a bit: if the lower 96 bit match, we're probably lucky.
		if (memcmp(secondSig + 4, targetSig + 4, 12) == 0)
		{
			printf("\nsuccess with origHash = ");
			for (unsigned int x = 0; x < sig.size() / 2; x++)
			{
				printf("%02x", firstSig[x]);
			}
			printf("\n");
			printf("prefix: 0x%x\n", prefix);
			break;
		}
		else
		{
		}
	}
	printf("predicted sig: ");
	for (unsigned int x = 0; x < sig.size() / 2; x++)
	{
		printf("%02x", secondSig[x]);
	}
	cout << endl;
	for (unsigned int x = 0; x < secondMessage->size(); x++)
	{
		unsigned char c = secondMessage->at(x);
		if (c >= 32 && c <= 126)
		{
			cout << c;
		}
		else
		{
			printf("\\x%02x", c);
		}
	}
	delete secondMessage;
	cout << endl;
	return 0;
}
