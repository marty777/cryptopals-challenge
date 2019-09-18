#include "Set1.h"
#include "Set2.h"
#include "Set3.h"
#include <iostream>
#include <string>

#define MAX_CHALLENGE_INDEX 23;
using namespace std;


int main() {
	int maxChallenge = MAX_CHALLENGE_INDEX;
	cout << "Enter challenge number (1-" << maxChallenge << "):";
	string inputStr;
	int challenge = 1;
	getline(cin, inputStr);
	try {
		challenge = stoi(inputStr);
	}
	catch (std::invalid_argument) {
		cout << "Invalid entry" << endl;
		return 0;
	}
	catch (std::out_of_range) {
		cout << "Invalid entry" << endl;
		return 0;
	}
	if (challenge < 1 || challenge > maxChallenge) {
		cout << "Invalid entry" << endl;
		return 0;
	}

	int set = (challenge / 8) + 1;
	cout << "### SET " << set << " CHALLENGE " << challenge << " ###" << endl;

	switch (challenge) {
	case 1:
		Set1Challenge1();
		break;
	case 2:
		Set1Challenge2();
		break;
	case 3:
		Set1Challenge3();
		break;
	case 4:
		Set1Challenge4();
		break;
	case 5:
		Set1Challenge5();
		break;
	case 6:
		Set1Challenge6();
		break;
	case 7:
		Set1Challenge7();
		break;
	case 8:
		Set1Challenge8();
		break;
	case 9:
		Set2Challenge9();
		break;
	case 10:
		Set2Challenge10();
		break;
	case 11:
		Set2Challenge11();
		break;
	case 12:
		Set2Challenge12();
		break;
	case 13:
		Set2Challenge13();
		break;
	case 14:
		Set2Challenge14();
		break;
	case 15:
		Set2Challenge15();
		break;
	case 16:
		Set2Challenge16();
		break;
	case 17:
		Set3Challenge17();
		break;
	case 18:
		Set3Challenge18();
		break;
	case 19:
		Set3Challenge19();
		break;
	case 20:
		Set3Challenge20();
		break;
	case 21:
		Set3Challenge21();
		break;
	case 22:
		Set3Challenge22();
		break;
	case 23:
		Set3Challenge23();
		break;
	default:
		break;
	}
	cout << "Press enter to continue..." << endl;
	getchar();
}