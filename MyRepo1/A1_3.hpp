#ifndef A1_3_HPP
#define A1_3_HPP

#include <string>
#include <vector>
#include <stdexcept>

// 前向声明，解决循环依赖
class Department;
class Instructor;
class Student;
class Subject;

class School {
private:
    std::string name;
    std::vector<Department> departments;  // 组合：School 由 Department 构成（Department 依赖 School 存在）
    std::vector<Student*> students;       // 聚合：School 包含 Student（Student 可独立存在）

public:
    explicit School(std::string n) : name(std::move(n)) {}

    void addDepartment(const Department& dept);
    void addStudent(Student* stu);

    [[nodiscard]] std::string getName() const;
    [[nodiscard]] const std::vector<Department>& getDepartments() const;
    [[nodiscard]] const std::vector<Student*>& getStudents() const;
};

class Department {
private:
    std::string name;
    School* school;  // 属于 1 个 School
    std::vector<Instructor*> instructors;  // 至少 1 位 Instructor
    std::vector<Subject> subjects;         // 至少 1 门 Subject

public:
    Department(std::string n, School* sch) : name(std::move(n)), school(sch) {
        if (school == nullptr) {
            throw std::invalid_argument("系必须属于一个学院");
        }
    }

    void addInstructor(Instructor* ins);
    void addSubject(const Subject& sub);

    [[nodiscard]] std::string getName() const;
    [[nodiscard]] School* getSchool() const;
    [[nodiscard]] const std::vector<Instructor*>& getInstructors() const;
    [[nodiscard]] const std::vector<Subject>& getSubjects() const;
};

class Instructor {
private:
    std::string name;
    std::vector<Department*> departments;  // 至少 1 个 Department
    std::vector<Subject*> subjects;        // 1-3 门 Subject

public:
    explicit Instructor(std::string n) : name(std::move(n)) {}

    void addDepartment(Department* dept);
    void addSubject(Subject* sub);

    [[nodiscard]] std::string getName() const;
    [[nodiscard]] const std::vector<Department*>& getDepartments() const;
    [[nodiscard]] const std::vector<Subject*>& getSubjects() const;
};

class Student {
private:
    std::string name;
    School* school;  // 属于 1 个 School
    std::vector<Subject*> subjects;  // 1-5 门 Subject

public:
    Student(std::string n, School* sch) : name(std::move(n)), school(sch) {
        if (school == nullptr) {
            throw std::invalid_argument("学生必须属于一个学院");
        }
    }

    void addSubject(Subject* sub);

    [[nodiscard]] std::string getName() const;
    [[nodiscard]] School* getSchool() const;
    [[nodiscard]] const std::vector<Subject*>& getSubjects() const;
};

class Subject {
private:
    std::string name;
    Department* department;  // 属于 1 个 Department
    std::vector<Instructor*> instructors;  // 1-3 位 Instructor
    std::vector<Student*> students;        // 1-5 名 Student

public:
    Subject(std::string n, Department* dept) : name(std::move(n)), department(dept) {
        if (department == nullptr) {
            throw std::invalid_argument("课程必须属于一个系");
        }
    }

    void addInstructor(Instructor* ins);
    void addStudent(Student* stu);

    [[nodiscard]] std::string getName() const;
    [[nodiscard]] Department* getDepartment() const;
    [[nodiscard]] const std::vector<Instructor*>& getInstructors() const;
    [[nodiscard]] const std::vector<Student*>& getStudents() const;
};

// 成员函数实现（头文件内实现需 inline）
inline void School::addDepartment(const Department& dept) {
    departments.push_back(dept);
}

inline void School::addStudent(Student* stu) {
    if (stu != nullptr) {
        students.push_back(stu);
    }
}

inline std::string School::getName() const {
    return name;
}

inline const std::vector<Department>& School::getDepartments() const {
    return departments;
}

inline const std::vector<Student*>& School::getStudents() const {
    return students;
}

inline void Department::addInstructor(Instructor* ins) {
    if (ins != nullptr) {
        instructors.push_back(ins);
    }
}

inline void Department::addSubject(const Subject& sub) {
    subjects.push_back(sub);
}

inline std::string Department::getName() const {
    return name;
}

inline School* Department::getSchool() const {
    return school;
}

inline const std::vector<Instructor*>& Department::getInstructors() const {
    return instructors;
}

inline const std::vector<Subject>& Department::getSubjects() const {
    return subjects;
}

inline void Instructor::addDepartment(Department* dept) {
    if (dept != nullptr) {
        departments.push_back(dept);
    }
}

inline void Instructor::addSubject(Subject* sub) {
    if (sub != nullptr && subjects.size() < 3) {  // 限制 1-3 门课
        subjects.push_back(sub);
    }
}

inline std::string Instructor::getName() const {
    return name;
}

inline const std::vector<Department*>& Instructor::getDepartments() const {
    return departments;
}

inline const std::vector<Subject*>& Instructor::getSubjects() const {
    return subjects;
}

inline void Student::addSubject(Subject* sub) {
    if (sub != nullptr && subjects.size() < 5) {  // 限制 1-5 门课
        subjects.push_back(sub);
    }
}

inline std::string Student::getName() const {
    return name;
}

inline School* Student::getSchool() const {
    return school;
}

inline const std::vector<Subject*>& Student::getSubjects() const {
    return subjects;
}

inline void Subject::addInstructor(Instructor* ins) {
    if (ins != nullptr && instructors.size() < 3) {  // 限制 1-3 位教师
        instructors.push_back(ins);
    }
}

inline void Subject::addStudent(Student* stu) {
    if (stu != nullptr && students.size() < 5) {  // 限制 1-5 名学生
        students.push_back(stu);
    }
}

inline std::string Subject::getName() const {
    return name;
}

inline Department* Subject::getDepartment() const {
    return department;
}

inline const std::vector<Instructor*>& Subject::getInstructors() const {
    return instructors;
}

inline const std::vector<Student*>& Subject::getStudents() const {
    return students;
}

#endif // A1_3_HPP