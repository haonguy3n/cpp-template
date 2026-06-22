#ifndef SE051_CORE_ERROR_HPP
#define SE051_CORE_ERROR_HPP

#include <string>
#include <string_view>

// Value-based error model: category + code + message. A null category means
// "no error".
namespace se051::error {

using Code = int;

// Groups related error codes, like std::error_category but trivial. A category
// is a static object; errors hold a pointer to it.
struct Category {
    const char* name = "";
};

struct Error {
    const Category* category = nullptr;  // nullptr means NoError
    Code            code     = 0;
    std::string     message;

    // True when this represents success (no error).
    bool ok() const { return category == nullptr; }

    // Truthy when there IS an error, so callers can write `if (err) { ... }`.
    explicit operator bool() const { return !ok(); }
};

// The canonical "no error" value.
inline const Error NoError{};

// Builds an Error from category/code/message.
inline Error Make(const Category& cat, Code code, std::string_view msg) {
    Error e;
    e.category = &cat;
    e.code     = code;
    e.message.assign(msg.data(), msg.size());
    return e;
}

} // namespace se051::error

#endif // SE051_CORE_ERROR_HPP
