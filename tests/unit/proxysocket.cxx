/* Copyright 2026 Pierre Ossman <ossman@cendio.se> for Cendio AB
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gtest/gtest.h>

#include <algorithm>
#include <exception>
#include <future>
#include <stdexcept>
#include <string>
#include <string.h>
#include <thread>
#include <vector>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define socketErrorNumber WSAGetLastError()
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define closesocket close
#define socketErrorNumber errno
#endif

#include <core/string.h>

#include <network/TcpSocket.h>

struct Socks5Request {
  uint8_t method;
  uint8_t atyp;
  std::string username;
  std::string password;
  std::string host;
  int port;
};

static void writeExact(int sock, const uint8_t *data, size_t length)
{
  while (length > 0) {
    int ret;

#ifdef WIN32
    ret = send(sock, (const char*)data, (int)length, 0);
#else
    ret = send(sock, data, length, 0);
#endif
    if (ret == -1) {
      int err = socketErrorNumber;

#ifndef WIN32
      if (err == EINTR)
        continue;
#endif
      throw std::runtime_error(core::format("send() failed: %d", err));
    }
    if (ret == 0)
      throw std::runtime_error("Unexpected EOF while writing");

    data += ret;
    length -= ret;
  }
}

static void readExact(int sock, uint8_t *data, size_t length)
{
  while (length > 0) {
    int ret;

#ifdef WIN32
    ret = recv(sock, (char*)data, (int)length, 0);
#else
    ret = recv(sock, data, length, 0);
#endif
    if (ret == -1) {
      int err = socketErrorNumber;

#ifndef WIN32
      if (err == EINTR)
        continue;
#endif
      throw std::runtime_error(core::format("recv() failed: %d", err));
    }
    if (ret == 0)
      throw std::runtime_error("Unexpected EOF while reading");

    data += ret;
    length -= ret;
  }
}

static void waitForPeerClose(int sock)
{
  uint8_t buffer[256];

  while (true) {
    int ret;

#ifdef WIN32
    ret = recv(sock, (char*)buffer, sizeof(buffer), 0);
#else
    ret = recv(sock, buffer, sizeof(buffer), 0);
#endif
    if (ret == 0)
      return;
    if (ret == -1) {
      int err = socketErrorNumber;

#ifndef WIN32
      if (err == EINTR)
        continue;
#endif
      throw std::runtime_error(core::format("recv() failed: %d", err));
    }
  }
}

static int createListener()
{
  int listener;
  struct sockaddr_in addr;

  network::initSockets();

  listener = socket(AF_INET, SOCK_STREAM, 0);
  if (listener < 0)
    throw std::runtime_error(core::format("socket() failed: %d",
                                          socketErrorNumber));

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    int err = socketErrorNumber;
    closesocket(listener);
    throw std::runtime_error(core::format("bind() failed: %d", err));
  }

  if (listen(listener, 1) < 0) {
    int err = socketErrorNumber;
    closesocket(listener);
    throw std::runtime_error(core::format("listen() failed: %d", err));
  }

  return listener;
}

static Socks5Request handleClient(int listener, bool requireAuth,
                                  bool invalidAuthVersion, bool unofferedAuth)
{
  Socks5Request request = {};
  int client;

  client = accept(listener, nullptr, nullptr);
  if (client < 0)
    throw std::runtime_error(core::format("accept() failed: %d",
                                          socketErrorNumber));

  try {
    uint8_t header[4];
    uint8_t portBytes[2];

    readExact(client, header, 2);
    if (header[0] != 0x05)
      throw std::runtime_error("Unexpected SOCKS version");

    std::vector<uint8_t> methods(header[1]);
    if (!methods.empty())
      readExact(client, methods.data(), methods.size());

    request.method = requireAuth ? 0x02 : 0x00;
    if (!unofferedAuth && std::find(methods.begin(), methods.end(), request.method) ==
        methods.end()) {
      throw std::runtime_error("Client did not offer the expected authentication method");
    }

    uint8_t methodReply[2] = {0x05, request.method};
    writeExact(client, methodReply, sizeof(methodReply));

    if (unofferedAuth) {
      waitForPeerClose(client);
      closesocket(client);
      return request;
    }

    if (request.method == 0x02) {
      readExact(client, header, 2);
      if (header[0] != 0x01)
        throw std::runtime_error("Unexpected username/password auth version");

      std::vector<uint8_t> username(header[1]);
      if (!username.empty())
        readExact(client, username.data(), username.size());
      request.username.assign(username.begin(), username.end());

      readExact(client, header, 1);
      std::vector<uint8_t> password(header[0]);
      if (!password.empty())
        readExact(client, password.data(), password.size());
      request.password.assign(password.begin(), password.end());

      uint8_t authReply[2] = {0x01, 0x00};
      if (invalidAuthVersion)
        authReply[0] = 0x05;
      writeExact(client, authReply, sizeof(authReply));

      if (invalidAuthVersion) {
        waitForPeerClose(client);
        closesocket(client);
        return request;
      }
    }

    readExact(client, header, sizeof(header));
    if (header[0] != 0x05)
      throw std::runtime_error("Unexpected SOCKS version in CONNECT request");
    if (header[1] != 0x01)
      throw std::runtime_error("Unexpected SOCKS command in CONNECT request");
    if (header[2] != 0x00)
      throw std::runtime_error("Unexpected reserved byte in CONNECT request");

    request.atyp = header[3];
    switch (request.atyp) {
    case 0x01: {
      uint8_t addr[4];
      char buffer[INET_ADDRSTRLEN];

      readExact(client, addr, sizeof(addr));
      if (inet_ntop(AF_INET, addr, buffer, sizeof(buffer)) == nullptr)
        throw std::runtime_error("Failed to decode IPv4 address");
      request.host = buffer;
      break;
    }
    case 0x03: {
      uint8_t length;
      std::vector<uint8_t> host;

      readExact(client, &length, 1);
      host.resize(length);
      if (!host.empty())
        readExact(client, host.data(), host.size());
      request.host.assign(host.begin(), host.end());
      break;
    }
    case 0x04: {
      uint8_t addr[16];
      char buffer[INET6_ADDRSTRLEN];

      readExact(client, addr, sizeof(addr));
      if (inet_ntop(AF_INET6, addr, buffer, sizeof(buffer)) == nullptr)
        throw std::runtime_error("Failed to decode IPv6 address");
      request.host = buffer;
      break;
    }
    default:
      throw std::runtime_error("Unexpected SOCKS5 address type");
    }

    readExact(client, portBytes, sizeof(portBytes));
    request.port = ((int)portBytes[0] << 8) | portBytes[1];

    uint8_t connectReply[] = {
      0x05, 0x00, 0x00, 0x01,
      127, 0, 0, 1,
      0x13, 0x37,
    };
    writeExact(client, connectReply, sizeof(connectReply));

    waitForPeerClose(client);
    closesocket(client);
  } catch (...) {
    closesocket(client);
    throw;
  }

  return request;
}

class Socks5Server {
public:
  explicit Socks5Server(bool requireAuth, bool invalidAuthVersion = false,
                        bool unofferedAuth = false)
    : listener_(createListener()),
      port_(network::getSockPort(listener_)),
      future_(promise_.get_future())
  {
    worker_ = std::thread([this, requireAuth, invalidAuthVersion, unofferedAuth]() {
      try {
        promise_.set_value(handleClient(listener_, requireAuth,
                                       invalidAuthVersion, unofferedAuth));
      } catch (...) {
        promise_.set_exception(std::current_exception());
      }
    });
  }

  ~Socks5Server()
  {
    if (listener_ != -1) {
      closesocket(listener_);
      listener_ = -1;
    }

    if (worker_.joinable())
      worker_.join();
  }

  int port() const
  {
    return port_;
  }

  Socks5Request wait()
  {
    Socks5Request request = future_.get();

    if (listener_ != -1) {
      closesocket(listener_);
      listener_ = -1;
    }

    return request;
  }

private:
  int listener_;
  int port_;
  std::promise<Socks5Request> promise_;
  std::future<Socks5Request> future_;
  std::thread worker_;
};

TEST(ProxySocket, socks5NoAuth)
{
  Socks5Server server(false);
  std::string proxy = core::format("socks5://127.0.0.1:%d", server.port());

  {
    network::TcpSocket sock("server.example", 5901, proxy.c_str());
  }

  Socks5Request request = server.wait();

  EXPECT_EQ(request.method, 0x00);
  EXPECT_EQ(request.atyp, 0x03);
  EXPECT_EQ(request.host, "server.example");
  EXPECT_EQ(request.port, 5901);
  EXPECT_TRUE(request.username.empty());
  EXPECT_TRUE(request.password.empty());
}

TEST(ProxySocket, socks5UserPassAndIpv6Target)
{
  Socks5Server server(true);
  std::string proxy = core::format(
    "socks5://user%%20name:pass%%40word@127.0.0.1:%d", server.port());

  {
    network::TcpSocket sock("2001:db8::10", 5902, proxy.c_str());
  }

  Socks5Request request = server.wait();

  EXPECT_EQ(request.method, 0x02);
  EXPECT_EQ(request.atyp, 0x04);
  EXPECT_EQ(request.host, "2001:db8::10");
  EXPECT_EQ(request.port, 5902);
  EXPECT_EQ(request.username, "user name");
  EXPECT_EQ(request.password, "pass@word");
}

TEST(ProxySocket, invalidScheme)
{
  EXPECT_THROW({
    network::TcpSocket sock("server.example", 5901, "http://127.0.0.1:3128");
  }, std::invalid_argument);
}

TEST(ProxySocket, socks5hIpv4Target)
{
  Socks5Server server(false);
  std::string proxy = core::format("socks5h://127.0.0.1:%d/", server.port());

  {
    network::TcpSocket sock("192.0.2.10", 5900, proxy.c_str());
  }

  Socks5Request request = server.wait();
  EXPECT_EQ(request.atyp, 0x01);
  EXPECT_EQ(request.host, "192.0.2.10");
  EXPECT_EQ(request.port, 5900);
}

TEST(ProxySocket, rejectsUnofferedAuthentication)
{
  Socks5Server server(true, false, true);
  std::string proxy = core::format("socks5://127.0.0.1:%d", server.port());

  EXPECT_THROW({
    network::TcpSocket sock("server.example", 5900, proxy.c_str());
  }, std::runtime_error);
  server.wait();
}

TEST(ProxySocket, rejectsInvalidAuthenticationVersion)
{
  Socks5Server server(true, true);
  std::string proxy = core::format("socks5://user:pass@127.0.0.1:%d", server.port());

  EXPECT_THROW({
    network::TcpSocket sock("server.example", 5900, proxy.c_str());
  }, std::runtime_error);
  server.wait();
}

int main(int argc, char **argv)
{
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
