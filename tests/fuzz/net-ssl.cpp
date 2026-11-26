// Copyright (c) 2026, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of
//    conditions and the following disclaimer in the documentation and/or other materials
//    provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific prior
//    written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
// OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
// TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Fuzzes the epee TLS/SSL configuration surface (net_ssl.cpp): ssl_options_t
// construction from attacker-controlled fingerprints and authentication blobs,
// SSL context creation (PEM/cert option handling via OpenSSL), the on-wire
// is_ssl() detection, verification-mode selection per host, and the
// ssl_support_t option-string parser. No sockets are opened.

#include <string>
#include <vector>

#include "include_base_utils.h"
#include "net/net_ssl.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzzer.h"

BEGIN_INIT_SIMPLE_FUZZER()
END_INIT_SIMPLE_FUZZER()

BEGIN_SIMPLE_FUZZER()
  FuzzedDataProvider fdp(buf, len);

  // Attacker-controlled certificate/authority blobs (PEM-ish bytes).
  std::vector<std::vector<uint8_t>> certs;
  const std::size_t n_certs = fdp.ConsumeIntegralInRange<std::size_t>(0, 3);
  for (std::size_t i = 0; i < n_certs; ++i)
    certs.push_back(fdp.ConsumeBytes<uint8_t>(
        std::min<std::size_t>(fdp.remaining_bytes() / 3 + 1, 256)));

  const std::string ca_path; // empty: no file access

  // Option selection from fuzz bytes (support mode + authentication mode).
  const bool any_cert = fdp.ConsumeBool();
  epee::net_utils::ssl_authentication_t auth{};
  if (any_cert)
  {
    auth.priv_key = fdp.ConsumeBytes<std::uint8_t>(
        std::min<std::size_t>(fdp.remaining_bytes() / 2 + 1, 256));
    auth.certificate = fdp.ConsumeBytes<std::uint8_t>(
        std::min<std::size_t>(fdp.remaining_bytes() / 2 + 1, 256));
  }

  epee::net_utils::ssl_options_t options(certs, ca_path);
  options.auth = auth;
  options.support = fdp.ConsumeBool()
      ? epee::net_utils::ssl_support_t::e_ssl_support_enabled
      : epee::net_utils::ssl_support_t::e_ssl_support_autodetect;
  options.on_handshake = fdp.ConsumeBool()
      ? epee::net_utils::ssl_support_t::e_ssl_support_enabled
      : epee::net_utils::ssl_support_t::e_ssl_support_autodetect;
  options.verification = fdp.ConsumeBool()
      ? epee::net_utils::ssl_verification_t::e_ssl_verification_enabled
      : (fdp.ConsumeBool()
            ? epee::net_utils::ssl_verification_t::e_ssl_verification_none
            : epee::net_utils::ssl_verification_t::e_ssl_verification_open_ssl_ca);
  if (fdp.ConsumeBool())
    options.verification = epee::net_utils::ssl_verification_t::e_ssl_verification_open_ssl_ca;

  // Context creation: OpenSSL object construction driven entirely by the options.
  try
  {
    boost::asio::ssl::context ctx = options.create_context();
    (void)ctx;
  }
  catch (...) {}

  // On-wire detection: first bytes of a peer stream.
  const std::string wire = fdp.ConsumeBytesAsString(
      std::min<std::size_t>(fdp.remaining_bytes(), 64));
  const bool looks_ssl = epee::net_utils::is_ssl(
      reinterpret_cast<const unsigned char *>(wire.data()), wire.size());
  (void)looks_ssl;

  // Per-host verification-mode selection.
  const std::string host = fdp.ConsumeBytesAsString(
      std::min<std::size_t>(fdp.remaining_bytes(), 64));
  const bool strong = options.has_strong_verification(host);
  (void)strong;

  // Option-string parser (daemon/wallet CLI values).
  epee::net_utils::ssl_support_t parsed_support =
      epee::net_utils::ssl_support_t::e_ssl_support_disabled;
  epee::net_utils::ssl_support_from_string(parsed_support,
      fdp.ConsumeBytesAsString(std::min<std::size_t>(fdp.remaining_bytes(), 16)));
END_SIMPLE_FUZZER()
