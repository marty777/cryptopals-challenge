#pragma once
#include "ByteVector.h"
#include <string>
class PlaintextEvaluator
{
public:
	PlaintextEvaluator();
	~PlaintextEvaluator();

	static float score(std::string input);
	static float score(ByteVector *input);
};

