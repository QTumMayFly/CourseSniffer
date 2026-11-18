#pragma once
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

struct TestSuite {
    int passed = 0;
    int failed = 0;
    void run(const std::string& name, const std::function<void()>& test) {
        try { test(); ++passed; std::cout << "[PASS] " << name << '\n'; }
        catch (const std::exception& error) { ++failed; std::cerr << "[FAIL] " << name << ": " << error.what() << '\n'; }
        catch (...) { ++failed; std::cerr << "[FAIL] " << name << ": unknown exception\n"; }
    }
};
#define CHECK(condition) do { if (!(condition)) throw std::runtime_error(std::string(__FILE__) + ":" + std::to_string(__LINE__) + " " #condition); } while (false)

void runParserTests(TestSuite& suite);
void runFilterTests(TestSuite& suite);
void runTcpTests(TestSuite& suite);
void runHttpTests(TestSuite& suite);
