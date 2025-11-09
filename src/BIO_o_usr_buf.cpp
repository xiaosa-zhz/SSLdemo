/*
    User buffer BIO that can be write to.
    'Read' operation will bind to the user buffer without copying.
    'Write' operation is normal data write.
*/

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <memory>
#include <cstring>
#include <span>
#include <algorithm>

#include "BIO_usr_buf.hpp"

#ifdef ENABLE_DEBUG
#include <print>
#define LOG(arg) std::println("{} {} {} {}", arg, __FILE__, __LINE__, __func__)
#else
#define LOG(...) void(0)
#endif

constexpr static const char* BIO_O_USR_BUF_NAME = "usr_buf_bio";

struct BIO_o_usr_buf_control_block {
    char* head = nullptr;
    char* curr = nullptr;
    char* tail = nullptr;

    void set_usr_buf(std::span<char> ub) noexcept {
        head = ub.data();
        curr = ub.data();
        tail = ub.data() + ub.size();
    }

    std::span<char> get_usr_buf() noexcept {
        return std::span<char>(head, tail);
    }

    std::span<char> get_cur_buf() noexcept {
        return std::span<char>(curr, tail);
    }

    void set_cur(char* new_curr) noexcept {
        curr = new_curr;
    }
};

static BIO_o_usr_buf_control_block& control_block(::BIO* bio) noexcept {
    return *static_cast<BIO_o_usr_buf_control_block*>(::BIO_get_data(bio));
}

static int o_usr_buf_create(::BIO* bio) noexcept {
    BIO_o_usr_buf_control_block* cb = static_cast<BIO_o_usr_buf_control_block*>(
        OPENSSL_zalloc(sizeof(BIO_o_usr_buf_control_block))
    );
    if (!cb) return 0;
    ::BIO_set_data(bio, cb);
    ::BIO_set_init(bio, 1);
    return 1;
}

static int o_usr_buf_destroy(::BIO* bio) noexcept {
    if (!bio) return 0;
    BIO_o_usr_buf_control_block* cb
        = static_cast<BIO_o_usr_buf_control_block*>(::BIO_get_data(bio));
    OPENSSL_free(cb);
    ::BIO_set_data(bio, nullptr);
    ::BIO_set_init(bio, 0);
    return 1;
}

static int o_usr_buf_write_ex(::BIO* bio,
    const char* data, std::size_t dlen, std::size_t* written) noexcept {
    LOG(dlen);
    if (dlen == 0) {
        if (written) *written = 0;
        return 1;
    }
    BIO_o_usr_buf_control_block& cb = control_block(bio);
    std::span<char> buffer = cb.get_cur_buf();
    std::size_t to_write = std::ranges::min(dlen, buffer.size());
    if (to_write == 0) {
        BIO_set_retry_write(bio);
        return 0;
    }
    std::memcpy(buffer.data(), data, to_write);
    cb.set_cur(buffer.data() + to_write);
    if (written) *written = to_write;
    BIO_clear_retry_flags(bio);
    return 1;
}

static int o_usr_buf_write(::BIO* bio, const char* data, int dlen) noexcept {
    std::size_t written = 0;
    int ret = o_usr_buf_write_ex(bio, data, static_cast<std::size_t>(dlen), &written);
    if (ret != 1) return ret;
    return static_cast<int>(written);
}

static long o_usr_buf_ctrl(::BIO* bio, int cmd, long larg, void* parg) noexcept {
    BIO_o_usr_buf_control_block& cb = control_block(bio);
    switch (cmd) {
        case BIO_CTRL_RESET:
            cb.set_cur(cb.head);
            return 1;
        case BIO_CTRL_EOF:
            return cb.get_cur_buf().empty() ? 1 : 0;
        case BIO_CTRL_GET_CLOSE:
            return ::BIO_get_shutdown(bio);
        case BIO_CTRL_SET_CLOSE:
            ::BIO_set_shutdown(bio, static_cast<int>(larg));
            return 1;
        case BIO_CTRL_FLUSH:
            return 1;
        case BIO_CTRL_WPENDING:
            return 0;
        default:
            return 0;
    }
}

struct BIO_METHOD_deleter {
    static void operator()(::BIO_METHOD* method) noexcept {
        ::BIO_meth_free(method);
    }
};

using BIO_METHOD_handle = std::unique_ptr<::BIO_METHOD, BIO_METHOD_deleter>;

#define TRY_SET_METHOD(biomh, func) do { \
    if (::BIO_meth_set_##func(biomh.get(), o_usr_buf_##func) == 0) { \
        throw 0; \
    } \
} while (false)

extern "C"
::BIO_METHOD* BIO_s_o_usr_buf() noexcept {
    try {
        static BIO_METHOD_handle method = [] static -> BIO_METHOD_handle {
            static const int o_usr_buf_method_index = [] static -> int {
                const int index =::BIO_get_new_index();
                if (index < 0) throw 0;
                return index;
            }();
            BIO_METHOD_handle method(::BIO_meth_new(
                BIO_TYPE_SOURCE_SINK | o_usr_buf_method_index,
                BIO_O_USR_BUF_NAME));
            if (!method) throw 0;
            TRY_SET_METHOD(method, create);
            TRY_SET_METHOD(method, destroy);
            TRY_SET_METHOD(method, write);
            TRY_SET_METHOD(method, write_ex);
            TRY_SET_METHOD(method, ctrl);
            return method;
        }();
        return method.get();
    } catch (...) {
        return nullptr;
    }
}

extern "C"
void BIO_set_o_usr_buf(::BIO* bio, void* data, std::size_t size) noexcept {
    BIO_o_usr_buf_control_block& cb = control_block(bio);
    cb.set_usr_buf({ static_cast<char*>(data), size });
}

extern "C"
std::size_t BIO_o_usr_buf_cur_off(::BIO* bio) noexcept {
    BIO_o_usr_buf_control_block& cb = control_block(bio);
    return static_cast<std::size_t>(cb.curr - cb.head);
}
