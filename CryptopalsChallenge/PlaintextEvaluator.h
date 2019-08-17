#pragma once
#include <string>
class PlaintextEvaluator
{
public:
	PlaintextEvaluator();
	~PlaintextEvaluator();

	static float score(std::string input);
};

