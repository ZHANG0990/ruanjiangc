#ifndef A1_1_HPP
#define A1_1_HPP

#include <string>

class Thoroughbred {
private:
    // 私有属性：母亲、父亲、出生年份
    std::string mother;
    std::string father;
    int birthyear;

public:
    // 构造函数（可选，用于初始化属性）
    Thoroughbred(std::string m, std::string f, int year) : mother(m), father(f), birthyear(year) {}

    // 操作：获取当前年龄（假设当前年份为2025，可根据实际情况调整）
    int getCurrentAge() {
        const int CURRENT_YEAR = 2025;
        return CURRENT_YEAR - -birthyear;
    }

    // 操作：获取父亲信息
    std::string getFather() {
        return father;
    }

    // 操作：获取母亲信息
    std::string getMother() {
        return mother;
    }
};

#endif // A1_1_HPP