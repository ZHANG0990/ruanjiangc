#ifndef A1_2_HPP
#define A1_2_HPP

#include <string>
#include <vector>
#include <stdexcept>

// 前向声明，解决循环依赖
class Building;
class Course;

/**
 * 学院类（整体）
 * 与 Building 是聚合关系（建筑可独立存在）
 * 与 Course 是组合关系（课程依赖学院存在）
 */
class College {
private:
    std::string name;                     // 学院名称
    std::vector<Building*> buildings;     // 聚合：包含建筑（指针表示独立存在）
    std::vector<Course> courses;          // 组合：包含课程（对象表示依赖关系）

public:
    // 构造函数：初始化学院名称
    explicit College(std::string n) : name(std::move(n)) {}

    // 添加建筑（聚合关系操作）
    void addBuilding(Building* building);

    // 添加课程（组合关系操作）
    void addCourse(const Course& course);

    // 获取学院名称
    [[nodiscard]] std::string getName() const;

    // 获取所有建筑
    [[nodiscard]] const std::vector<Building*>& getBuildings() const;

    // 获取所有课程
    [[nodiscard]] const std::vector<Course>& getCourses() const;
};

/**
 * 建筑类（部分）
 * 与 College 是聚合关系
 * 与 Course 存在关联（课程在建筑中进行）
 */
class Building {
private:
    std::string name;                     // 建筑名称
    std::vector<Course*> courses;         // 关联：在此建筑进行的课程

public:
    // 构造函数：初始化建筑名称
    explicit Building(std::string n) : name(std::move(n)) {}

    // 添加在此建筑进行的课程
    void addCourse(Course* course);

    // 获取建筑名称
    [[nodiscard]] std::string getName() const;

    // 获取所有在此建筑的课程
    [[nodiscard]] const std::vector<Course*>& getCourses() const;
};

/**
 * 课程类（部分）
 * 与 College 是组合关系
 * 与 Building 存在约束：必须关联到某个建筑
 */
class Course {
private:
    std::string name;                     // 课程名称
    Building* location;                   // 约束：课程所在建筑（非空）

public:
    // 构造函数：必须指定课程名称和所在建筑（体现约束）
    Course(std::string n, Building* loc);

    // 获取课程名称
    [[nodiscard]] std::string getName() const;

    // 获取课程所在建筑
    [[nodiscard]] Building* getLocation() const;
};

// 类成员函数实现（头文件内实现需 inline 避免链接错误）
inline void College::addBuilding(Building* building) {
    if (building != nullptr) {
        buildings.push_back(building);
    }
}

inline void College::addCourse(const Course& course) {
    courses.push_back(course);
}

inline std::string College::getName() const {
    return name;
}

inline const std::vector<Building*>& College::getBuildings() const {
    return buildings;
}

inline const std::vector<Course>& College::getCourses() const {
    return courses;
}

inline void Building::addCourse(Course* course) {
    if (course != nullptr) {
        courses.push_back(course);
    }
}

inline std::string Building::getName() const {
    return name;
}

inline const std::vector<Course*>& Building::getCourses() const {
    return courses;
}

inline Course::Course(std::string n, Building* loc) : name(std::move(n)), location(loc) {
    if (location == nullptr) {
        throw std::invalid_argument("课程必须关联到有效的建筑"); // 强化约束：不允许空建筑
    }
    location->addCourse(this); // 自动将课程注册到所在建筑
}

inline std::string Course::getName() const {
    return name;
}

inline Building* Course::getLocation() const {
    return location;
}

#endif // A1_2_HPP