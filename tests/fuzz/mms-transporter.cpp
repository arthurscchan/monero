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

// Fuzzes the MMS transporter's handling of PyBitmessage API responses: a stub HTTP
// client feeds attacker-controlled XML answers into receive_messages(), which then
// runs the XML <string> tag extraction, the epee JSON parse of the inbox message
// list, the double-Base64 decode, and the transport_message JSON parse per message.
// Also fuzzes derive_transport_address() (pure seed -> transport address derivation).

#include <algorithm>
#include <deque>
#include <cstring>
#include <string>

#include "include_base_utils.h"
#include "net/net_parse_helpers.h"
#include "wallet/message_transporter.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzzer.h"

namespace
{
  class stub_http_client final : public epee::net_utils::http::abstract_http_client
  {
  public:
    std::deque<std::string> responses;

    bool set_proxy(const std::string &/*address*/) override { return true; }
    void set_server(std::string /*host*/, std::string /*port*/,
        boost::optional<epee::net_utils::http::login> /*user*/,
        epee::net_utils::ssl_options_t /*ssl_options*/) override {}
    void set_auto_connect(bool /*auto_connect*/) override {}
    bool connect(std::chrono::milliseconds /*timeout*/) override { return true; }
    bool disconnect() override { return true; }
    bool is_connected(bool * /*ssl*/ = NULL) override { return true; }
    bool invoke(const boost::string_ref /*uri*/, const boost::string_ref /*method*/,
        const boost::string_ref /*body*/, std::chrono::milliseconds /*timeout*/,
        const epee::net_utils::http::http_response_info **ppresponse_info = NULL,
        const epee::net_utils::http::fields_list & /*additional_params*/ =
            epee::net_utils::http::fields_list()) override
    {
      if (ppresponse_info)
      {
        m_ri.clear();
        m_ri.m_response_code = 200;
        m_ri.m_mime_tipe = "text/xml";
        if (!responses.empty())
        {
          m_ri.m_body = responses.front();
          responses.pop_front();
        }
        *ppresponse_info = &m_ri;
      }
      return true;
    }
    bool invoke_get(const boost::string_ref uri, std::chrono::milliseconds timeout,
        const std::string &body = std::string(),
        const epee::net_utils::http::http_response_info **ppresponse_info = NULL,
        const epee::net_utils::http::fields_list &additional_params =
            epee::net_utils::http::fields_list()) override
    {
      return invoke(uri, "GET", body, timeout, ppresponse_info, additional_params);
    }
    uint64_t get_bytes_sent() const override { return 0; }
    uint64_t get_bytes_received() const override { return 0; }

  private:
    epee::net_utils::http::http_response_info m_ri;
  };
} // anonymous namespace

BEGIN_INIT_SIMPLE_FUZZER()
END_INIT_SIMPLE_FUZZER()

BEGIN_SIMPLE_FUZZER()
  FuzzedDataProvider fdp(buf, len);

  // Configuration from the back.
  const std::size_t n_answers = 1 + fdp.ConsumeIntegralInRange<std::size_t>(0, 2);
  const std::size_t answer_len = fdp.ConsumeIntegralInRange<std::size_t>(0, 256);
  const std::size_t seed_len = fdp.ConsumeIntegralInRange<std::size_t>(0, 64);

  stub_http_client *client = new stub_http_client();
  mms::message_transporter transporter{std::unique_ptr<epee::net_utils::http::abstract_http_client>(client)};
  transporter.set_options("http://localhost:8442/", epee::wipeable_string("user:password"));

  // Attacker-controlled PyBitmessage answers: XML-wrapped values, JSON payload lists,
  // and double-Base64 message bodies all come from the fuzz input.
  for (std::size_t i = 0; i < n_answers; ++i)
    client->responses.push_back(fdp.ConsumeBytesAsString(
        std::min<std::size_t>(answer_len, fdp.remaining_bytes())));

  try
  {
    std::vector<mms::transport_message> messages;
    std::vector<std::string> destinations = {"dest-0", "dest-1"};
    transporter.receive_messages(destinations, messages);
  }
  catch (...) {}

  // Pure derivation: seed -> transport address (no network).
  try
  {
    const std::string seed = fdp.ConsumeBytesAsString(
        std::min<std::size_t>(seed_len, fdp.remaining_bytes()));
    transporter.derive_transport_address(seed);
  }
  catch (...) {}
END_SIMPLE_FUZZER()
