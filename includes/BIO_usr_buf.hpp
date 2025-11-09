#pragma once
#ifndef MYLIB_BIO_USER_BUF_HPP
#define MYLIB_BIO_USER_BUF_HPP 1

/**
    * @file BIO_usr_buf.hpp
    * @brief Custom OpenSSL BIO for user-provided buffers.
    * This header defines the interface for a BIO that operates on
    * user-provided buffers, allowing for efficient data handling
    * without unnecessary copying.
    * All user buffers should outlive the BIO that uses them. 
 */

#include <openssl/bio.h>
#include <cstddef>

extern "C" ::BIO_METHOD* BIO_s_i_usr_buf() noexcept;
extern "C" ::BIO_METHOD* BIO_s_o_usr_buf() noexcept;
extern "C" void BIO_set_i_usr_buf(::BIO* bio, const void* data, std::size_t size) noexcept;
extern "C" void BIO_set_o_usr_buf(::BIO* bio, void* data, std::size_t size) noexcept;
extern "C" std::size_t BIO_i_usr_buf_cur_off(::BIO* bio) noexcept;
extern "C" std::size_t BIO_o_usr_buf_cur_off(::BIO* bio) noexcept;

#endif // MYLIB_BIO_USER_BUF_HPP
