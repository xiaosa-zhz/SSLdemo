#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <memory>
#include <print>
#include <string>
#include <string_view>
#include <format>

#include "BIO_usr_buf.hpp"

struct ssl_ctx_deleter {
    void operator()(::SSL_CTX* ctx) const noexcept {
        ::SSL_CTX_free(ctx);
    }
};

using ssl_ctx_handle = std::unique_ptr<::SSL_CTX, ssl_ctx_deleter>;

struct ssl_deleter {
    void operator()(::SSL* ssl) const noexcept {
        ::SSL_free(ssl);
    }
};

using ssl_handle = std::unique_ptr<::SSL, ssl_deleter>;

constexpr std::string_view message = "Hello, BIO user buffer!";

void test_usr_bio() noexcept {
    ::BIO* ibio = ::BIO_new(::BIO_s_i_usr_buf());
    ::BIO* obio = ::BIO_new(::BIO_s_o_usr_buf());
    ::BIO* cbio = ::BIO_new(::BIO_f_base64());
    ::BIO_set_flags(cbio, BIO_FLAGS_BASE64_NO_NL);
    std::string encoded(2048, '\0');
    ::BIO_set_o_usr_buf(obio, encoded.data(), encoded.size());
    ::BIO_set_next(cbio, obio);
    std::size_t write_bytes = 0;
    if (::BIO_write_ex(cbio, message.data(), message.size(), &write_bytes) != 1) {
        std::println("BIO_write_ex failed");
    } else {
        (void) BIO_flush(cbio); // flush means finalize for base64 encoding
        encoded.resize(::BIO_o_usr_buf_cur_off(obio));
        std::println("Received message: {}", encoded);
    }
    std::string decoded(2048, '\0');
    ::BIO_set_i_usr_buf(ibio, encoded.data(), encoded.size());
    ::BIO_set_next(cbio, ibio);
    std::size_t read_bytes = 0;
    if (::BIO_read_ex(cbio, decoded.data(), decoded.size(), &read_bytes) != 1) {
        std::println("BIO_read_ex failed");
    } else {
        decoded.resize(read_bytes);
        std::println("Decoded message: {}", decoded);
    }
    ::BIO_free(cbio);
    ::BIO_free(obio);
    ::BIO_free(ibio);
}

// vvv Written by AI

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <vector>
#include <poll.h>

namespace {

// Minimal RAII for raw socket
struct fd_holder {
    int fd{-1};
    fd_holder() = default;
    explicit fd_holder(int f): fd(f) {}
    ~fd_holder(){ if(fd>=0) ::close(fd); }
    fd_holder(const fd_holder&) = delete;
    fd_holder& operator=(const fd_holder&) = delete;
    fd_holder(fd_holder&& o) noexcept : fd(o.fd){ o.fd=-1; }
    fd_holder& operator=(fd_holder&& o) noexcept { if(this!=&o){ if(fd>=0) ::close(fd); fd=o.fd; o.fd=-1;} return *this; }
    int get() const noexcept { return fd; }
    int release() noexcept { int t=fd; fd=-1; return t; }
    explicit operator bool() const noexcept { return fd>=0; }
};

static int connect_tcp(const char* host, const char* port){
    struct addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    struct addrinfo* res=nullptr;
    int rc = ::getaddrinfo(host, port, &hints, &res);
    if(rc!=0) { std::println("getaddrinfo: {}", gai_strerror(rc)); return -1; }
    fd_holder sock;
    for(auto* p=res; p; p=p->ai_next){
        int fd = ::socket(p->ai_family, p->ai_socktype | SOCK_NONBLOCK, p->ai_protocol);
        if(fd<0) continue;
        // Enable SO_REUSEADDR to ease rapid restart/debug cycles (harmless for client sockets).
        int reuse = 1;
        (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        if(::connect(fd, p->ai_addr, p->ai_addrlen)==0 || errno==EINPROGRESS){
            sock = fd_holder(fd);
            break;
        }
        ::close(fd);
    }
    ::freeaddrinfo(res);
    if(!sock){ std::println("connect failed"); return -1; }
    // Wait for connection completion
    struct pollfd pfd{sock.get(), POLLOUT, 0};
    (void)::poll(&pfd, 1, 3000);
    int soerr = 0; socklen_t slen = sizeof(soerr);
    (void)::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, &soerr, &slen);
    if(soerr != 0){ std::println("connect error after poll: {}", soerr); return -1; }
    return sock.release();
}
// Wait until fd is readable/writable
static bool wait_fd(int fd, bool want_read, bool want_write, int timeout_ms){
    short ev = 0; if(want_read) ev |= POLLIN; if(want_write) ev |= POLLOUT;
    struct pollfd pfd{fd, ev, 0};
    int r = ::poll(&pfd, 1, timeout_ms);
    return r>0 && (pfd.revents & ev);
}

// Drive handshake using custom user buffer BIOs.
struct tls_io_buffers {
    std::vector<unsigned char> in_buf;
    std::vector<unsigned char> out_buf;
};

static bool drain_wbio_to_socket(SSL* ssl, int fd, tls_io_buffers& bufs){
    ::BIO* obio = SSL_get_wbio(ssl);
    for(;;){
        std::size_t produced = ::BIO_o_usr_buf_cur_off(obio);
        if(produced==0) break;
        std::size_t sent_total = 0;
        const unsigned char* p = bufs.out_buf.data();
        while(sent_total < produced){
            ssize_t s = ::send(fd, p+sent_total, produced - sent_total, 0);
            if(s<0){ if(errno==EAGAIN || errno==EWOULDBLOCK) continue; std::println("send error: {}", errno); return false; }
            sent_total += static_cast<std::size_t>(s);
        }
        // Reset output window for next production
        ::BIO_set_o_usr_buf(obio, bufs.out_buf.data(), bufs.out_buf.size());
    }
    return true;
}

static bool fill_rbio_from_socket(SSL* ssl, int fd, tls_io_buffers& bufs){
    ::BIO* ibio = SSL_get_rbio(ssl);
    ssize_t recvd = ::recv(fd, bufs.in_buf.data(), bufs.in_buf.size(), 0);
    if(recvd<0){
        if(errno==EAGAIN || errno==EWOULDBLOCK) return true; // nothing yet
        std::println("recv error: {}", errno); return false;
    } else if(recvd==0){
        return false; // closed
    }
    ::BIO_set_i_usr_buf(ibio, bufs.in_buf.data(), static_cast<std::size_t>(recvd));
    return true;
}

static bool tls_handshake_user_bio(SSL* ssl, int fd){
    tls_io_buffers bufs{std::vector<unsigned char>(16*1024), std::vector<unsigned char>(17*1024)};
    ::BIO* ibio = ::BIO_new(::BIO_s_i_usr_buf());
    ::BIO* obio = ::BIO_new(::BIO_s_o_usr_buf());
    if(!ibio || !obio){ std::println("BIO_new failed"); return false; }
    ::BIO_set_i_usr_buf(ibio, bufs.in_buf.data(), 0); // empty initially
    ::BIO_set_o_usr_buf(obio, bufs.out_buf.data(), bufs.out_buf.size());
    SSL_set_bio(ssl, ibio, obio); // SSL owns BIOs now
    SSL_set_connect_state(ssl);

    for(int iter=0; iter<4000 && !SSL_is_init_finished(ssl); ++iter){
        int r = SSL_do_handshake(ssl);
        if(r==1) break; // done
        int err = SSL_get_error(ssl, r);
        if(!drain_wbio_to_socket(ssl, fd, bufs)) return false;
        if(err == SSL_ERROR_WANT_READ){
            (void)wait_fd(fd, true, false, 3000);
            if(!fill_rbio_from_socket(ssl, fd, bufs)) { std::println("peer closed during handshake"); return false; }
            continue;
        } else if(err == SSL_ERROR_WANT_WRITE){
            (void)wait_fd(fd, false, true, 3000);
            continue;
        } else if(err == SSL_ERROR_ZERO_RETURN){
            std::println("stream closed early"); return false;
        } else if(err == SSL_ERROR_SYSCALL){
            std::println("syscall error during handshake"); return false;
        } else if(err == SSL_ERROR_SSL){
            std::println("TLS protocol error during handshake"); return false;
        }
    }
    // final drain (NewSessionTicket/finished flight, if any)
    if(!drain_wbio_to_socket(ssl, fd, bufs)) return false;
    return SSL_is_init_finished(ssl);
}

static bool tls_send_user_bio(SSL* ssl, int fd, std::string_view data){
    tls_io_buffers bufs{std::vector<unsigned char>(16*1024), std::vector<unsigned char>(17*1024)};
    ::BIO* obio = SSL_get_wbio(ssl);
    ::BIO* ibio = SSL_get_rbio(ssl);
    ::BIO_set_o_usr_buf(obio, bufs.out_buf.data(), bufs.out_buf.size());
    std::size_t total = 0;
    while(total < data.size()){
        int r = SSL_write(ssl, data.data()+total, static_cast<int>(data.size()-total));
        if(r<=0){
            int err = SSL_get_error(ssl, r);
            if(err==SSL_ERROR_WANT_WRITE){
                (void)wait_fd(fd, false, true, 3000);
            } else if(err==SSL_ERROR_WANT_READ){
                // TLS 1.3 may require reading peer post-handshake data (e.g., tickets)
                (void)wait_fd(fd, true, false, 3000);
                if(!fill_rbio_from_socket(ssl, fd, bufs)) return false;
            } else { std::println("SSL_write error {}", err); return false; }
        } else {
            total += static_cast<std::size_t>(r);
        }
        if(!drain_wbio_to_socket(ssl, fd, bufs)) return false;
    }
    // Final flush if any left
    if(!drain_wbio_to_socket(ssl, fd, bufs)) return false;
    return true;
}

static bool tls_recv_user_bio(SSL* ssl, int fd){
    ::BIO* ibio = SSL_get_rbio(ssl);
    std::vector<unsigned char> in_buf(16*1024);
    std::string plain;
    for(int loops=0; loops<10'000; ++loops){
        ssize_t recvd = ::recv(fd, in_buf.data(), in_buf.size(), 0);
        if(recvd<0){
            if(errno==EAGAIN || errno==EWOULDBLOCK){
                struct timespec ts{0, 20'000'000}; ::nanosleep(&ts, nullptr);
                continue;
            }
            std::println("recv error: {}", errno); break;
        } else if(recvd==0){
            break; // peer closed
        }
        ::BIO_set_i_usr_buf(ibio, in_buf.data(), static_cast<std::size_t>(recvd));
        for(;;){
            unsigned char buf[4096];
            int r = SSL_read(ssl, buf, sizeof(buf));
            if(r>0){ plain.append(reinterpret_cast<char*>(buf), r); continue; }
            int err = SSL_get_error(ssl, r);
            if(err==SSL_ERROR_WANT_READ){
                // ensure no unconsumed bytes remain before next recv
                if(BIO_ctrl_pending(ibio) > 0) continue;
                break;
            }
            if(err==SSL_ERROR_ZERO_RETURN){ loops = 10'000; break; }
            if(err==SSL_ERROR_WANT_WRITE){ continue; }
            if(err==SSL_ERROR_SYSCALL || err==SSL_ERROR_SSL){ std::println("SSL_read error {}", err); loops=10'000; break; }
            break;
        }
    }
    std::println("Received plaintext ({} bytes):\n{}", plain.size(), plain);
    return true;
}

constexpr std::string_view test_msg_template =
    "GET / HTTP/1.1\r\nHost: {}\r\n"
    "Connection: close\r\n"
    "User-Agent: usr-bio-demo\r\n\r\n";

void test_tls_client_usr_bio(){
    const char* host = "127.0.0.1"; const char* port = "4433";
    int fd = connect_tcp(host, port);
    if(fd<0){ return; }
    ssl_ctx_handle ctx{ SSL_CTX_new(TLS_client_method()) };
    if(!ctx){ std::println("SSL_CTX_new failed"); ::close(fd); return; }
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr); // demo only
    ssl_handle ssl{ SSL_new(ctx.get()) };
    if(!ssl){ std::println("SSL_new failed"); ::close(fd); return; }
    SSL_set_tlsext_host_name(ssl.get(), host);
    if(!tls_handshake_user_bio(ssl.get(), fd)){ std::println("handshake failed"); ::close(fd); return; }
    std::println("Handshake success using user buffer BIOs");
    std::println("TLS version: {}", SSL_get_version(ssl.get()));  // 期望打印 TLSv1.3
    std::string req = std::format(test_msg_template, host);
    if(!tls_send_user_bio(ssl.get(), fd, req)){ std::println("send failed"); ::close(fd); return; }
    tls_recv_user_bio(ssl.get(), fd);
    ::close(fd);
}

} // namespace


int main() {
    // test_usr_bio();
    // Uncomment to run live TLS client demo (network required)
    test_tls_client_usr_bio();
}
