#ifndef SE051_CORE_RESULT_HPP
#define SE051_CORE_RESULT_HPP

#include "se051/core/error.hpp"

#include <optional>
#include <string_view>
#include <utility>

namespace se051 {

// Wraps an error so it can be returned where a Result/Status is expected:
//   return se051::Unexpected{se051::error::Make(cat, code, "msg")};
template <typename E = error::Error>
struct Unexpected {
    E error;
};

// Holds a T on success or an error::Error on failure.
template <typename T>
class Result {
public:
    Result(T value) : value_(std::move(value)) {}          // success
    Result(Unexpected<> u) : error_(std::move(u.error)) {} // failure

    Result(Result&&) = default;
    Result(const Result&) = default;

    // Assignment via reset+emplace so T only needs to be move-constructible
    // (move-only types like RsaKey delete operator=).
    Result& operator=(Result&& o) {
        value_.reset();
        if (o.value_) value_.emplace(std::move(*o.value_));
        error_ = std::move(o.error_);
        return *this;
    }

    bool has_value() const { return value_.has_value(); }
    explicit operator bool() const { return has_value(); }

    T&       value()       { return *value_; }
    const T& value() const { return *value_; }

    error::Error&       error()       { return error_; }
    const error::Error& error() const { return error_; }

private:
    std::optional<T> value_;
    error::Error     error_;
};

// Holds nothing on success or an error::Error on failure (void operations).
class Status {
public:
    Status() = default;                                    // success
    Status(Unexpected<> u) : ok_(false), error_(std::move(u.error)) {}

    bool has_value() const { return ok_; }
    explicit operator bool() const { return ok_; }

    error::Error&       error()       { return error_; }
    const error::Error& error() const { return error_; }

private:
    bool         ok_ = true;
    error::Error error_;
};

// Convenience: a successful Status.
inline Status Ok() { return Status{}; }

// Convenience: build a failed Result/Status from category/code/message.
inline Unexpected<> Fail(const error::Category& cat, error::Code code,
                         std::string_view msg) {
    return Unexpected<>{error::Make(cat, code, msg)};
}

} // namespace se051

#endif // SE051_CORE_RESULT_HPP
