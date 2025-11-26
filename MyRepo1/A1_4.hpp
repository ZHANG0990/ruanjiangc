#ifndef A1_4_HPP
#define A1_4_HPP

#include <string>
#include <vector>
#include <ctime>
#include <stdexcept>

// 前向声明
class Customer;
class Order;
class OrderDetail;
class Product;

// 订单状态枚举
enum class OrderStatus {
    CREATE,   // 创建
    PAID,     // 已支付
    SHIPPING, // 配送中
    DELIVERED,// 已送达
    CANCEL    // 已取消
};

// 支付方式基类（抽象类）
class Payment {
protected:
    double amount; // 支付金额
public:
    explicit Payment(double amt) : amount(amt) {}
    virtual ~Payment() = default;
    [[nodiscard]] double getAmount() const { return amount; }
};

// 信用卡支付（继承自 Payment）
class Credit : public Payment {
private:
    std::string number;    // 卡号
    std::string type;      // 卡类型（如 Visa、Master）
    std::string expireDate;// 过期日期
public:
    Credit(double amt, std::string num, std::string typ, std::string exp)
        : Payment(amt), number(std::move(num)), type(std::move(typ)), expireDate(std::move(exp)) {}
    [[nodiscard]] std::string getNumber() const { return number; }
    [[nodiscard]] std::string getType() const { return type; }
    [[nodiscard]] std::string getExpireDate() const { return expireDate; }
};

// 现金支付（继承自 Payment）
class Cash : public Payment {
private:
    double cashTendered; // 支付金额
public:
    Cash(double amt, double tendered) : Payment(amt), cashTendered(tendered) {}
    [[nodiscard]] double getCashTendered() const { return cashTendered; }
};

// 在线转账（继承自 Payment）
class WireTransfer : public Payment {
private:
    std::string bankID;   // 银行ID
    std::string bankName; // 银行名称
public:
    WireTransfer(double amt, std::string id, std::string name)
        : Payment(amt), bankID(std::move(id)), bankName(std::move(name)) {}
    [[nodiscard]] std::string getBankID() const { return bankID; }
    [[nodiscard]] std::string getBankName() const { return bankName; }
};

// 支付宝支付（继承自 Payment）
class AliPay : public Payment {
private:
    std::string number; // 卡号（支付宝账号）
public:
    AliPay(double amt, std::string num) : Payment(amt), number(std::move(num)) {}
    [[nodiscard]] std::string getNumber() const { return number; }
};

// 微信支付（继承自 Payment）
class WeixinPay : public Payment {
private:
    std::string number; // 卡号（微信账号）
public:
    WeixinPay(double amt, std::string num) : Payment(amt), number(std::move(num)) {}
    [[nodiscard]] std::string getNumber() const { return number; }
};

// 商品类
class Product {
private:
    std::string title;       // 名称
    double weight;           // 重量
    std::string description; // 描述
    double unitPrice;        // 单价（可根据业务补充，用于计算价格）
public:
    Product(std::string t, double w, std::string desc, double price)
        : title(std::move(t)), weight(w), description(std::move(desc)), unitPrice(price) {}
    [[nodiscard]] double getPriceForQuantity(int quantity) const { return unitPrice * quantity; }
    [[nodiscard]] double getWeight() const { return weight; }
    [[nodiscard]] std::string getTitle() const { return title; }
    [[nodiscard]] std::string getDescription() const { return description; }
};

// 订单详情类
class OrderDetail {
private:
    int quantity;         // 数量
    Product* product;     // 关联的商品
public:
    OrderDetail(int qty, Product* prod) : quantity(qty), product(prod) {
        if (product == nullptr) {
            throw std::invalid_argument("订单详情必须关联商品");
        }
    }
    [[nodiscard]] double calculateSubTotal() const { return product->getPriceForQuantity(quantity); }
    [[nodiscard]] double calculateWeight() const { return product->getWeight() * quantity; }
    [[nodiscard]] int getQuantity() const { return quantity; }
    [[nodiscard]] Product* getProduct() const { return product; }
};

// 客户类
class Customer {
private:
    std::string name;            // 姓名
    std::string contact;         // 联系电话
    std::string deliveryAddress; // 邮寄地址
    bool active;                 // 是否激活
    std::vector<Order*> orders;  // 关联的订单
public:
    Customer(std::string n, std::string cont, std::string addr, bool act)
        : name(std::move(n)), contact(std::move(cont)), deliveryAddress(std::move(addr)), active(act) {}
    void addOrder(Order* order);
    [[nodiscard]] std::string getName() const { return name; }
    [[nodiscard]] std::string getContact() const { return contact; }
    [[nodiscard]] std::string getDeliveryAddress() const { return deliveryAddress; }
    [[nodiscard]] bool isActive() const { return active; }
    [[nodiscard]] const std::vector<Order*>& getOrders() const { return orders; }
};

// 订单类
class Order {
private:
    std::time_t createDate;      // 创建日期（使用时间戳）
    OrderStatus status;          // 订单状态
    Customer* customer;          // 关联的客户
    std::vector<OrderDetail> details; // 订单详情
    Payment* payment;            // 关联的支付方式
public:
    Order(Customer* cust, Payment* pay) : customer(cust), payment(pay), status(OrderStatus::CREATE) {
        createDate = std::time(nullptr); // 初始化创建时间为当前时间
        if (customer == nullptr || payment == nullptr) {
            throw std::invalid_argument("订单必须关联客户和支付方式");
        }
        customer->addOrder(this);
    }
    void addDetail(const OrderDetail& detail);
    [[nodiscard]] std::time_t getCreateDate() const { return createDate; }
    [[nodiscard]] OrderStatus getStatus() const { return status; }
    void setStatus(OrderStatus stat) { status = stat; }
    [[nodiscard]] Customer* getCustomer() const { return customer; }
    [[nodiscard]] const std::vector<OrderDetail>& getDetails() const { return details; }
    [[nodiscard]] Payment* getPayment() const { return payment; }
};

// 成员函数实现（头文件内需 inline）
inline void Customer::addOrder(Order* order) {
    if (order != nullptr) {
        orders.push_back(order);
    }
}

inline void Order::addDetail(const OrderDetail& detail) {
    details.push_back(detail);
}

#endif // A1_4_HPP