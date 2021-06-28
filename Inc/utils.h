#include <string>

#pragma once

void ExitWithMsg(const std::string& msg);

#define EXIT_WITH_MSG(str) \
    ExitWithMsg(std::string(str) + " " + __FILE__ + " " + std::to_string(__LINE__))

