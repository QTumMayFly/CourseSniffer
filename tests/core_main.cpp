#include "TestSupport.h"
int main() {
    TestSuite suite;
    runParserTests(suite);
    runDnsArpTests(suite);
    runFilterTests(suite);
    runTcpTests(suite);
    runHttpTests(suite);
    std::cout << "Passed: " << suite.passed << ", Failed: " << suite.failed << '\n';
    return suite.failed ? 1 : 0;
}
