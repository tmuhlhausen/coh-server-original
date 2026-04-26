#include "validate_name.h"
#include "UnitTest++.h"

TEST(PromoteTargetNameRejectsQuotes)
{
	CHECK(!ValidateCommandSafePlayerName("Bad\"Name", 20));
}

TEST(PromoteTargetNameRejectsBackslashes)
{
	CHECK(!ValidateCommandSafePlayerName("Bad\\Name", 20));
}

TEST(PromoteTargetNameRejectsSeparators)
{
	CHECK(!ValidateCommandSafePlayerName("Bad;Name", 20));
	CHECK(!ValidateCommandSafePlayerName("Bad,Name", 20));
	CHECK(!ValidateCommandSafePlayerName("Bad|Name", 20));
}

TEST(PromoteTargetNameRejectsNewlines)
{
	CHECK(!ValidateCommandSafePlayerName("Bad\nName", 20));
	CHECK(!ValidateCommandSafePlayerName("Bad\rName", 20));
}

TEST(PromoteTargetNameAllowsNormalNames)
{
	CHECK(ValidateCommandSafePlayerName("Captain Alpha", 20));
}
