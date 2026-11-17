/* Copyright (C) 2002-2005 RealVNC Ltd.  All Rights Reserved.
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

#ifdef WIN32
//#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define errorNumber WSAGetLastError()
#else
#define errorNumber errno
#define closesocket close
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <vector>

#include <core/Configuration.h>
#include <core/Exception.h>
#include <core/LogWriter.h>
#include <core/i18n.h>
#include <core/string.h>

#include <network/TcpSocket.h>

#ifdef WIN32
#include <core/winerrno.h>
#endif

#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long)-1)
#endif
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK ((unsigned long)0x7F000001)
#endif

#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a,b) \
  (memcmp ((const void*)(a), (const void*)(b), sizeof (struct in6_addr)) == 0)
#endif

// Missing on older Windows and OS X
#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif

using namespace network;

static core::LogWriter vlog("TcpSocket");

static core::BoolParameter
  UseIPv4("UseIPv4",
          _("Use IPv4 for incoming and outgoing connections"), true);
static core::BoolParameter
  UseIPv6("UseIPv6",
          _("Use IPv6 for incoming and outgoing connections"), true);

/* Tunnelling support. */
int network::findFreeTcpPort (void)
{
  int sock;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;

  if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    throw core::socket_error(_("Failed to create socket"), errorNumber);

  addr.sin_port = 0;
  if (bind (sock, (struct sockaddr *)&addr, sizeof (addr)) < 0)
    throw core::socket_error(_("Failed to find free port"), errorNumber);

  socklen_t n = sizeof(addr);
  if (getsockname (sock, (struct sockaddr *)&addr, &n) < 0)
    throw core::socket_error(_("Failed to get port number"), errorNumber);

  closesocket (sock);
  return ntohs(addr.sin_port);
}

static bool isAllSpace(const char *string) {
  if (string == nullptr)
    return false;
  while(*string != '\0') {
    if (! isspace(*string))
      return false;
    string++;
  }
  return true;
}

void network::getHostAndPort(const char* hi, std::string* host,
                             int* port, int basePort)
{
  const char* hostStart;
  const char* hostEnd;
  const char* portStart;

  if (hi == nullptr)
    throw std::invalid_argument("NULL host specified");

  // Trim leading whitespace
  while(isspace(*hi))
    hi++;

  assert(host);
  assert(port);

  if (hi[0] == '[') {
    hostStart = &hi[1];
    hostEnd = strchr(hostStart, ']');
    if (hostEnd == nullptr)
      throw std::runtime_error(_("Unmatched [ in hostname"));

    portStart = hostEnd + 1;
    if (isAllSpace(portStart))
      portStart = nullptr;
  } else {
    hostStart = &hi[0];
    hostEnd = strrchr(hostStart, ':');

    if (hostEnd == nullptr) {
      hostEnd = hostStart + strlen(hostStart);
      portStart = nullptr;
    } else {
      if ((hostEnd > hostStart) && (hostEnd[-1] == ':'))
        hostEnd--;
      portStart = strchr(hostStart, ':');
      if (portStart != hostEnd) {
        // We found more : in the host. This is probably an IPv6 address
        hostEnd = hostStart + strlen(hostStart);
        portStart = nullptr;
      }
    }
  }

  // Back up past trailing space
  while(isspace(*(hostEnd - 1)) && hostEnd > hostStart)
    hostEnd--;

  if (hostStart == hostEnd)
    *host = "localhost";
  else
    *host = std::string(hostStart, hostEnd - hostStart);

  if (portStart == nullptr)
    *port = basePort;
  else {
    char* end;

    if (portStart[0] != ':')
      throw std::runtime_error(_("Invalid port specified"));

    if (portStart[1] != ':')
      *port = strtol(portStart + 1, &end, 10);
    else
      *port = strtol(portStart + 2, &end, 10);
    if (*end != '\0' && ! isAllSpace(end))
      throw std::runtime_error(_("Invalid port specified"));

    if ((portStart[1] != ':') && (*port < 100))
      *port += basePort;
  }
}

int network::getSockPort(int sock)
{
  vnc_sockaddr_t sa;
  socklen_t sa_size = sizeof(sa);
  if (getsockname(sock, &sa.u.sa, &sa_size) < 0)
    return 0;

  switch (sa.u.sa.sa_family) {
  case AF_INET6:
    return ntohs(sa.u.sin6.sin6_port);
  default:
    return ntohs(sa.u.sin.sin_port);
  }
}

namespace {

  struct ProxyInfo {
    std::string host;
    int port;
    std::string username;
    std::string password;
  };

  static std::string trimString(const char *value)
  {
    const char *start;
    const char *end;

    if (value == nullptr)
      return "";

    start = value;
    while ((*start != '\0') && isspace((unsigned char)*start))
      start++;

    end = start + strlen(start);
    while ((end > start) && isspace((unsigned char)end[-1]))
      end--;

    return std::string(start, end - start);
  }

  static int hexValue(char c)
  {
    if ((c >= '0') && (c <= '9'))
      return c - '0';
    c = tolower((unsigned char)c);
    if ((c >= 'a') && (c <= 'f'))
      return c - 'a' + 10;
    return -1;
  }

  static std::string percentDecode(const std::string& value)
  {
    std::string decoded;

    decoded.reserve(value.length());

    for (size_t i = 0;i < value.length();i++) {
      if (value[i] != '%') {
        decoded += value[i];
        continue;
      }

      if ((i + 2) >= value.length())
        throw std::invalid_argument("Invalid percent-encoding in proxy URL");

      int upper = hexValue(value[i + 1]);
      int lower = hexValue(value[i + 2]);
      if ((upper < 0) || (lower < 0))
        throw std::invalid_argument("Invalid percent-encoding in proxy URL");

      decoded += (char)((upper << 4) | lower);
      i += 2;
    }

    return decoded;
  }

  static int parsePort(const std::string& value, int defaultPort)
  {
    char *end;
    long port;

    if (value.empty())
      return defaultPort;

    port = strtol(value.c_str(), &end, 10);
    if ((*end != '\0') || (port < 1) || (port > 65535))
      throw std::invalid_argument("Invalid proxy port");

    return (int)port;
  }

  static ProxyInfo parseProxy(const char *proxy)
  {
    ProxyInfo info;
    std::string url;
    std::string scheme;
    std::string authority;
    std::string hostPort;
    std::string portString;
    size_t schemeEnd;
    size_t authorityEnd;
    size_t at;

    url = trimString(proxy);
    if (url.empty())
      throw std::invalid_argument("Empty proxy URL");

    schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos)
      throw std::invalid_argument("Proxy URL is missing a scheme");

    scheme = url.substr(0, schemeEnd);
    for (size_t i = 0;i < scheme.length();i++)
      scheme[i] = tolower((unsigned char)scheme[i]);

    if ((scheme != "socks5") && (scheme != "socks5h"))
      throw std::invalid_argument(core::format("Unsupported proxy URL scheme \"%s\"",
                                               scheme.c_str()));

    authorityEnd = url.find_first_of("/?#", schemeEnd + 3);
    authority = url.substr(schemeEnd + 3,
                           authorityEnd == std::string::npos ?
                             authorityEnd : authorityEnd - (schemeEnd + 3));
    if (authority.empty())
      throw std::invalid_argument("Proxy URL is missing a host");

    if (authorityEnd != std::string::npos) {
      std::string suffix = url.substr(authorityEnd);

      if (suffix != "/")
        throw std::invalid_argument("Proxy URL must not contain a path, query, or fragment");
    }

    at = authority.rfind('@');
    if (at != std::string::npos) {
      std::string userinfo = authority.substr(0, at);
      size_t colon;

      hostPort = authority.substr(at + 1);
      colon = userinfo.find(':');
      if (colon == std::string::npos) {
        info.username = percentDecode(userinfo);
      } else {
        info.username = percentDecode(userinfo.substr(0, colon));
        info.password = percentDecode(userinfo.substr(colon + 1));
      }
    } else {
      hostPort = authority;
    }

    if (hostPort.empty())
      throw std::invalid_argument("Proxy URL is missing a host");

    if (hostPort[0] == '[') {
      size_t bracketEnd;

      bracketEnd = hostPort.find(']');
      if (bracketEnd == std::string::npos)
        throw std::invalid_argument("Unmatched [ in proxy host");

      info.host = hostPort.substr(1, bracketEnd - 1);
      if ((bracketEnd + 1) < hostPort.length()) {
        if (hostPort[bracketEnd + 1] != ':')
          throw std::invalid_argument("Invalid proxy URL");
        portString = hostPort.substr(bracketEnd + 2);
      }
    } else {
      size_t colon = hostPort.rfind(':');

      if (colon == std::string::npos) {
        info.host = hostPort;
      } else {
        if (hostPort.find(':') != colon)
          throw std::invalid_argument("IPv6 proxy addresses must be enclosed in []");
        info.host = hostPort.substr(0, colon);
        portString = hostPort.substr(colon + 1);
      }
    }

    if (info.host.empty())
      throw std::invalid_argument("Proxy URL is missing a host");

    info.port = parsePort(portString, 1080);

    if ((info.username.length() > 255) || (info.password.length() > 255))
      throw std::invalid_argument("SOCKS5 proxy credentials are too long");

    return info;
  }

  static int connectTcpHost(const char *host, int port)
  {
    int sock;
    int err;
    int result;
    struct addrinfo *ai;
    struct addrinfo *current;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_canonname = nullptr;
    hints.ai_addr = nullptr;
    hints.ai_next = nullptr;

    result = getaddrinfo(host, nullptr, &hints, &ai);
    if (result != 0)
      throw core::getaddrinfo_error(_("Failed get address for hostname"), result);

    sock = -1;
    err = 0;
    for (current = ai; current != nullptr; current = current->ai_next) {
      int family;
      vnc_sockaddr_t sa;
      socklen_t salen;
      char ntop[NI_MAXHOST];

      family = current->ai_family;

      switch (family) {
      case AF_INET:
        if (!UseIPv4)
          continue;
        break;
      case AF_INET6:
        if (!UseIPv6)
          continue;
        break;
      default:
        continue;
      }

      salen = current->ai_addrlen;
      memcpy(&sa, current->ai_addr, salen);

      if (family == AF_INET)
        sa.u.sin.sin_port = htons(port);
      else
        sa.u.sin6.sin6_port = htons(port);

      getnameinfo(&sa.u.sa, salen, ntop, sizeof(ntop), nullptr, 0,
                  NI_NUMERICHOST);
      vlog.debug("Connecting to %s [%s] port %d", host, ntop, port);

      sock = socket(family, SOCK_STREAM, 0);
      if (sock == -1) {
        err = errorNumber;
        freeaddrinfo(ai);
        throw core::socket_error(_("Failed to create socket"), err);
      }

      while ((result = connect(sock, &sa.u.sa, salen)) == -1) {
        err = errorNumber;
#ifndef WIN32
        if (err == EINTR)
          continue;
#endif
        vlog.debug("Failed to connect to address %s port %d: %d",
                   ntop, port, err);
        closesocket(sock);
        sock = -1;
        break;
      }

      if (result == 0)
        break;
    }

    freeaddrinfo(ai);

    if (sock == -1) {
      if (err == 0)
        throw std::runtime_error(_("No useful address found for hostname"));
      throw core::socket_error(_("Failed to connect to host"), err);
    }

    return sock;
  }

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
        int err = errorNumber;

#ifndef WIN32
        if (err == EINTR)
          continue;
#endif
        throw core::socket_error("Unable to write to socket", err);
      }
      if (ret == 0)
        throw std::runtime_error("Unexpected EOF when writing to socket");

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
        int err = errorNumber;

#ifndef WIN32
        if (err == EINTR)
          continue;
#endif
        throw core::socket_error("Unable to read from socket", err);
      }
      if (ret == 0)
        throw std::runtime_error("Unexpected EOF when reading from socket");

      data += ret;
      length -= ret;
    }
  }

  static void appendSocks5Destination(std::vector<uint8_t> *request,
                                      const char *host, int port)
  {
    struct in_addr ipv4;
    struct in6_addr ipv6;
    size_t hostLength;

    if ((port < 1) || (port > 65535))
      throw std::invalid_argument("Invalid target port for SOCKS5 proxy");

    if (inet_pton(AF_INET, host, &ipv4) == 1) {
      request->push_back(0x01);
      const uint8_t *addr = (const uint8_t*)&ipv4;
      request->insert(request->end(), addr, addr + 4);
    } else if (inet_pton(AF_INET6, host, &ipv6) == 1) {
      request->push_back(0x04);
      const uint8_t *addr = (const uint8_t*)&ipv6;
      request->insert(request->end(), addr, addr + 16);
    } else {
      hostLength = strlen(host);
      if ((hostLength == 0) || (hostLength > 255))
        throw std::invalid_argument("Invalid target host for SOCKS5 proxy");

      request->push_back(0x03);
      request->push_back((uint8_t)hostLength);
      request->insert(request->end(), host, host + hostLength);
    }

    request->push_back((uint8_t)(port >> 8));
    request->push_back((uint8_t)(port & 0xff));
  }

  static const char *socks5ReplyString(uint8_t reply)
  {
    switch (reply) {
    case 0x01:
      return "general SOCKS server failure";
    case 0x02:
      return "connection not allowed by ruleset";
    case 0x03:
      return "network unreachable";
    case 0x04:
      return "host unreachable";
    case 0x05:
      return "connection refused";
    case 0x06:
      return "TTL expired";
    case 0x07:
      return "command not supported";
    case 0x08:
      return "address type not supported";
    default:
      return "unknown error";
    }
  }

  static void discardSocks5Address(int sock, uint8_t atyp)
  {
    size_t length;
    uint8_t size;

    switch (atyp) {
    case 0x01:
      length = 4;
      break;
    case 0x04:
      length = 16;
      break;
    case 0x03:
      readExact(sock, &size, 1);
      length = size;
      break;
    default:
      throw std::runtime_error("SOCKS5 proxy returned an unknown address type");
    }

    std::vector<uint8_t> discard(length + 2);
    if (!discard.empty())
      readExact(sock, discard.data(), discard.size());
  }

  static void connectViaSocks5(int sock, const ProxyInfo& proxy,
                               const char *host, int port)
  {
    std::vector<uint8_t> message;
    uint8_t response[4];

    message.push_back(0x05);
    if (proxy.username.empty() && proxy.password.empty()) {
      message.push_back(0x01);
      message.push_back(0x00);
    } else {
      message.push_back(0x02);
      message.push_back(0x00);
      message.push_back(0x02);
    }

    writeExact(sock, message.data(), message.size());
    readExact(sock, response, 2);

    if (response[0] != 0x05)
      throw std::runtime_error("SOCKS5 proxy returned an invalid version");

    if (response[1] == 0xff)
      throw std::runtime_error("SOCKS5 proxy rejected all authentication methods");

    if (response[1] == 0x02) {
      if (proxy.username.empty() && proxy.password.empty())
        throw std::runtime_error("SOCKS5 proxy selected an authentication method that was not offered");

      message.clear();
      message.push_back(0x01);
      message.push_back((uint8_t)proxy.username.length());
      message.insert(message.end(),
                     proxy.username.begin(), proxy.username.end());
      message.push_back((uint8_t)proxy.password.length());
      message.insert(message.end(),
                     proxy.password.begin(), proxy.password.end());

      writeExact(sock, message.data(), message.size());
      readExact(sock, response, 2);

      if (response[0] != 0x01)
        throw std::runtime_error("SOCKS5 proxy returned an invalid authentication version");
      if (response[1] != 0x00)
        throw std::runtime_error("SOCKS5 proxy authentication failed");
    } else if (response[1] != 0x00) {
      throw std::runtime_error(core::format(
        "SOCKS5 proxy requested unsupported authentication method %u",
        response[1]));
    }

    message.clear();
    message.push_back(0x05);
    message.push_back(0x01);
    message.push_back(0x00);
    appendSocks5Destination(&message, host, port);

    writeExact(sock, message.data(), message.size());
    readExact(sock, response, 4);

    if (response[0] != 0x05)
      throw std::runtime_error("SOCKS5 proxy returned an invalid version");
    if (response[2] != 0x00)
      throw std::runtime_error("SOCKS5 proxy returned an invalid response");
    if (response[1] != 0x00) {
      throw std::runtime_error(core::format("SOCKS5 proxy connect failed: %s",
                                            socks5ReplyString(response[1])));
    }

    discardSocks5Address(sock, response[3]);
  }

}

// -=- TcpSocket

TcpSocket::TcpSocket(int sock) : Socket(sock)
{
  // Disable Nagle's algorithm, to reduce latency
  enableNagles(false);
}

TcpSocket::TcpSocket(const char *host, int port, const char *proxy)
{
  int sock = -1;

  try {
    if ((proxy != nullptr) && (*proxy != '\0')) {
      ProxyInfo proxyInfo = parseProxy(proxy);

      vlog.debug("Connecting to %s port %d via SOCKS5 proxy %s port %d",
                 host, port, proxyInfo.host.c_str(), proxyInfo.port);

      sock = connectTcpHost(proxyInfo.host.c_str(), proxyInfo.port);
      connectViaSocks5(sock, proxyInfo, host, port);
    } else {
      sock = connectTcpHost(host, port);
    }

    setFd(sock);
    sock = -1;
  } catch (...) {
    if (sock != -1)
      closesocket(sock);
    throw;
  }

  // Disable Nagle's algorithm, to reduce latency
  enableNagles(false);
}

const char* TcpSocket::getPeerAddress() {
  vnc_sockaddr_t sa;
  socklen_t sa_size = sizeof(sa);

  if (getpeername(getFd(), &sa.u.sa, &sa_size) != 0) {
    vlog.error(_("Failed to get peer name for socket"));
    return _("(N/A)");
  }

  if (sa.u.sa.sa_family == AF_INET6) {
    static char buffer[INET6_ADDRSTRLEN + 2];
    int ret;

    buffer[0] = '[';

    ret = getnameinfo(&sa.u.sa, sizeof(sa.u.sin6),
                      buffer + 1, sizeof(buffer) - 2, nullptr, 0,
                      NI_NUMERICHOST);
    if (ret != 0) {
      vlog.error(_("Failed to convert peer name to a string"));
      return _("(N/A)");
    }

    strcat(buffer, "]");

    return buffer;
  }

  if (sa.u.sa.sa_family == AF_INET) {
    char *name;

    name = inet_ntoa(sa.u.sin.sin_addr);
    if (name == nullptr) {
      vlog.error(_("Failed to convert peer name to a string"));
      return _("(N/A)");
    }

    return name;
  }

  vlog.error(_("Unknown address family"));
  return _("(N/A)");
}

const char* TcpSocket::getPeerEndpoint() {
  static char buffer[INET6_ADDRSTRLEN + 2 + 32];
  vnc_sockaddr_t sa;
  socklen_t sa_size = sizeof(sa);
  int port;

  getpeername(getFd(), &sa.u.sa, &sa_size);

  if (sa.u.sa.sa_family == AF_INET6)
    port = ntohs(sa.u.sin6.sin6_port);
  else if (sa.u.sa.sa_family == AF_INET)
    port = ntohs(sa.u.sin.sin_port);
  else
    port = 0;

  sprintf(buffer, "%s::%d", getPeerAddress(), port);

  return buffer;
}

bool TcpSocket::enableNagles(bool enable) {
  int one = enable ? 0 : 1;
  if (setsockopt(getFd(), IPPROTO_TCP, TCP_NODELAY,
                 (char *)&one, sizeof(one)) < 0) {
    int e = errorNumber;
    vlog.error(_("Failed to set TCP_NODELAY: %d"), e);
    return false;
  }
  return true;
}

TcpListener::TcpListener(int sock) : SocketListener(sock)
{
}

TcpListener::TcpListener(const struct sockaddr *listenaddr,
                         socklen_t listenaddrlen)
{
  int one = 1;
  vnc_sockaddr_t sa;
  int sock;

  if ((sock = socket (listenaddr->sa_family, SOCK_STREAM, 0)) < 0)
    throw core::socket_error(_("Failed to create socket"), errorNumber);

  memcpy (&sa, listenaddr, listenaddrlen);
#ifdef IPV6_V6ONLY
  if (listenaddr->sa_family == AF_INET6) {
    if (setsockopt (sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&one, sizeof(one))) {
      int e = errorNumber;
      closesocket(sock);
      throw core::socket_error(_("Failed to set IPV6_V6ONLY"), e);
    }
  }
#endif /* defined(IPV6_V6ONLY) */

#ifdef FD_CLOEXEC
  // - By default, close the socket on exec()
  fcntl(sock, F_SETFD, FD_CLOEXEC);
#endif

  // SO_REUSEADDR is broken on Windows. It allows binding to a port
  // that already has a listening socket on it. SO_EXCLUSIVEADDRUSE
  // might do what we want, but requires investigation.
#ifndef WIN32
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                 (char *)&one, sizeof(one)) < 0) {
    int e = errorNumber;
    closesocket(sock);
    throw core::socket_error(_("Failed to set SO_REUSEADDR"), e);
  }
#endif

  if (bind(sock, &sa.u.sa, listenaddrlen) == -1) {
    int e = errorNumber;
    closesocket(sock);
    throw core::socket_error(_("Failed to set socket address"), e);
  }

  listen(sock);
}

Socket* TcpListener::createSocket(int fd_) {
  return new TcpSocket(fd_);
}

std::list<std::string> TcpListener::getMyAddresses() {
  struct addrinfo *ai, *current, hints;
  std::list<std::string> result;

  initSockets();

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_canonname = nullptr;
  hints.ai_addr = nullptr;
  hints.ai_next = nullptr;

  // Windows doesn't like NULL for service, so specify something
  if ((getaddrinfo(nullptr, "1", &hints, &ai)) != 0)
    return result;

  for (current= ai; current != nullptr; current = current->ai_next) {
    char addr[INET6_ADDRSTRLEN];

    switch (current->ai_family) {
    case AF_INET:
      if (!UseIPv4)
        continue;
      break;
    case AF_INET6:
      if (!UseIPv6)
        continue;
      break;
    default:
      continue;
    }

    getnameinfo(current->ai_addr, current->ai_addrlen, addr, INET6_ADDRSTRLEN,
                nullptr, 0, NI_NUMERICHOST);

    result.push_back(addr);
  }

  freeaddrinfo(ai);

  return result;
}

int TcpListener::getMyPort() {
  return getSockPort(getFd());
}


void network::createLocalTcpListeners(std::list<SocketListener*> *listeners,
                                      int port)
{
  struct addrinfo ai[2];
  vnc_sockaddr_t sa[2];

  memset(ai, 0, sizeof(ai));
  memset(sa, 0, sizeof(sa));

  sa[0].u.sin.sin_family = AF_INET;
  sa[0].u.sin.sin_port = htons (port);
  sa[0].u.sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  ai[0].ai_family = sa[0].u.sin.sin_family;
  ai[0].ai_addr = &sa[0].u.sa;
  ai[0].ai_addrlen = sizeof(sa[0].u.sin);
  ai[0].ai_next = &ai[1];

  sa[1].u.sin6.sin6_family = AF_INET6;
  sa[1].u.sin6.sin6_port = htons (port);
  sa[1].u.sin6.sin6_addr = in6addr_loopback;

  ai[1].ai_family = sa[1].u.sin6.sin6_family;
  ai[1].ai_addr = &sa[1].u.sa;
  ai[1].ai_addrlen = sizeof(sa[1].u.sin6);
  ai[1].ai_next = nullptr;

  createTcpListeners(listeners, ai);
}

void network::createTcpListeners(std::list<SocketListener*> *listeners,
                                 const char *addr,
                                 int port)
{
  struct addrinfo *ai, hints;
  char service[16];
  int result;

  initSockets();

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_canonname = nullptr;
  hints.ai_addr = nullptr;
  hints.ai_next = nullptr;

  snprintf (service, sizeof (service) - 1, "%d", port);
  service[sizeof (service) - 1] = '\0';
  if ((result = getaddrinfo(addr, service, &hints, &ai)) != 0)
    throw core::getaddrinfo_error(
      _("Failed to get address for hostname"), result);

  try {
    createTcpListeners(listeners, ai);
  } catch(...) {
    freeaddrinfo(ai);
    throw;
  }

  freeaddrinfo(ai);
}

void network::createTcpListeners(std::list<SocketListener*> *listeners,
                                 const struct addrinfo *ai)
{
  const struct addrinfo *current;
  std::list<SocketListener*> new_listeners;

  initSockets();

  for (current = ai; current != nullptr; current = current->ai_next) {
    switch (current->ai_family) {
    case AF_INET:
      if (!UseIPv4)
        continue;
      break;

    case AF_INET6:
      if (!UseIPv6)
        continue;
      break;

    default:
      continue;
    }

    try {
      new_listeners.push_back(new TcpListener(current->ai_addr,
                                              current->ai_addrlen));
    } catch (core::socket_error& e) {
      // Ignore this if it is due to lack of address family support on
      // the interface or on the system
      if (e.err != EADDRNOTAVAIL && e.err != EAFNOSUPPORT) {
        // Otherwise, report the error
        while (!new_listeners.empty()) {
          delete new_listeners.back();
          new_listeners.pop_back();
        }
        throw;
      }
    }
  }

  listeners->splice (listeners->end(), new_listeners);
}


TcpFilter::TcpFilter(const char* spec) {
  std::vector<std::string> patterns;

  patterns = core::split(spec, ',');

  for (size_t i = 0; i < patterns.size(); i++) {
    if (!patterns[i].empty())
      filter.push_back(parsePattern(patterns[i].c_str()));
  }
}

TcpFilter::~TcpFilter() {
}


static bool
patternMatchIP(const TcpFilter::Pattern& pattern, vnc_sockaddr_t *sa) {
  switch (pattern.address.u.sa.sa_family) {
    unsigned long address;

  case AF_INET:
    if (sa->u.sa.sa_family != AF_INET)
      return false;

    address = sa->u.sin.sin_addr.s_addr;
    if (address == htonl (INADDR_NONE)) return false;
    return ((pattern.address.u.sin.sin_addr.s_addr &
             pattern.mask.u.sin.sin_addr.s_addr) ==
            (address & pattern.mask.u.sin.sin_addr.s_addr));

  case AF_INET6:
    if (sa->u.sa.sa_family != AF_INET6)
      return false;

    for (unsigned int n = 0; n < 16; n++) {
      unsigned int bits = (n + 1) * 8;
      unsigned int mask;
      if (pattern.prefixlen > bits)
        mask = 0xff;
      else {
        unsigned int lastbits = 0xff;
        lastbits <<= bits - pattern.prefixlen;
        mask = lastbits & 0xff;
      }

      if ((pattern.address.u.sin6.sin6_addr.s6_addr[n] & mask) !=
          (sa->u.sin6.sin6_addr.s6_addr[n] & mask))
        return false;

      if (mask < 0xff)
        break;
    }

    return true;

  case AF_UNSPEC:
    // Any address matches
    return true;

  default:
    break;
  }

  return false;
}

bool
TcpFilter::verifyConnection(Socket* s) {
  vnc_sockaddr_t sa;
  socklen_t sa_size = sizeof(sa);

  if (getpeername(s->getFd(), &sa.u.sa, &sa_size) != 0)
    return false;

  std::list<TcpFilter::Pattern>::iterator i;
  for (i=filter.begin(); i!=filter.end(); i++) {
    if (patternMatchIP(*i, &sa)) {
      switch ((*i).action) {
      case Accept:
        vlog.debug("ACCEPT %s", s->getPeerAddress());
        return true;
      case Query:
        vlog.debug("QUERY %s", s->getPeerAddress());
        s->setRequiresQuery();
        return true;
      case Reject:
        vlog.debug("REJECT %s", s->getPeerAddress());
        return false;
      }
    }
  }

  vlog.debug("[REJECT] %s", s->getPeerAddress());
  return false;
}


TcpFilter::Pattern TcpFilter::parsePattern(const char* p) {
  TcpFilter::Pattern pattern;

  std::vector<std::string> parts;
  int family;

  initSockets();

  parts = core::split(&p[1], '/');
  if (parts.size() > 2)
    throw std::runtime_error(_("Invalid filter specified"));

  if (parts.empty() || parts[0].empty()) {
    // Match any address
    memset (&pattern.address, 0, sizeof (pattern.address));
    pattern.address.u.sa.sa_family = AF_UNSPEC;
    pattern.prefixlen = 0;
  } else {
    struct addrinfo hints;
    struct addrinfo *ai;
    int result;
    memset (&hints, 0, sizeof (hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;

    // Take out brackets, if present
    if (parts[0][0] == '[') {
      parts[0].erase(0, 1);
      if (!parts[0].empty() && parts[0][parts.size()-1] == ']')
        parts[0].erase(parts.size()-1, 1);
    }

    if ((result = getaddrinfo (parts[0].c_str(), nullptr, &hints, &ai)) != 0) {
      throw core::getaddrinfo_error(
        _("Failed to get address for hostname"), result);
    }

    memcpy (&pattern.address.u.sa, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo (ai);

    family = pattern.address.u.sa.sa_family;

    if (parts.size() > 1) {
      if (family == AF_INET &&
          (parts[1].find('.') != std::string::npos)) {
        throw std::runtime_error(
          _("A mask is no longer supported for filters, use a prefix "
            "instead"));
      }

      pattern.prefixlen = (unsigned int) atoi(parts[1].c_str());
    } else {
      switch (family) {
      case AF_INET:
        pattern.prefixlen = 32;
        break;
      case AF_INET6:
        pattern.prefixlen = 128;
        break;
      default:
        throw std::runtime_error(_("Unknown address family"));
      }
    }
  }

  family = pattern.address.u.sa.sa_family;

  if (pattern.prefixlen > (family == AF_INET ? 32: 128))
    throw std::runtime_error(
      core::format(_("Invalid prefix length for filter: %u"),
                   pattern.prefixlen));

  // Compute mask from address and prefix length
  memset (&pattern.mask, 0, sizeof (pattern.mask));
  switch (family) {
    unsigned long mask;
  case AF_INET:
    mask = 0;
    for (unsigned int i=0; i<pattern.prefixlen; i++)
      mask |= 1<<(31-i);
    pattern.mask.u.sin.sin_addr.s_addr = htonl(mask);
    break;

  case AF_INET6:
    for (unsigned int n = 0; n < 16; n++) {
      unsigned int bits = (n + 1) * 8;
      if (pattern.prefixlen > bits)
        pattern.mask.u.sin6.sin6_addr.s6_addr[n] = 0xff;
      else {
        unsigned int lastbits = 0xff;
        lastbits <<= bits - pattern.prefixlen;
        pattern.mask.u.sin6.sin6_addr.s6_addr[n] = lastbits & 0xff;
        break;
      }
    }
    break;
  case AF_UNSPEC:
    // No mask to compute
    break;
  default:
    ; /* not reached */
  }

  switch(p[0]) {
  case '+': pattern.action = TcpFilter::Accept; break;
  case '-': pattern.action = TcpFilter::Reject; break;
  case '?': pattern.action = TcpFilter::Query; break;
  };

  return pattern;
}

std::string TcpFilter::patternToStr(const TcpFilter::Pattern& p) {
  char addr[INET6_ADDRSTRLEN + 2];

  if (p.address.u.sa.sa_family == AF_INET) {
    getnameinfo(&p.address.u.sa, sizeof(p.address.u.sin),
                addr, sizeof(addr), nullptr, 0, NI_NUMERICHOST);
  } else if (p.address.u.sa.sa_family == AF_INET6) {
    addr[0] = '[';
    getnameinfo(&p.address.u.sa, sizeof(p.address.u.sin6),
                addr + 1, sizeof(addr) - 2, nullptr, 0, NI_NUMERICHOST);
    strcat(addr, "]");
  } else
    addr[0] = '\0';

  char action;
  switch (p.action) {
  case Accept: action = '+'; break;
  case Reject: action = '-'; break;
  default:
  case Query: action = '?'; break;
  };
  size_t resultlen = (1                   // action
                      + strlen (addr)     // address
                      + 1                 // slash
                      + 3                 // prefix length, max 128
                      + 1);               // terminating nul
  char* result = new char[resultlen];
  if (addr[0] == '\0')
    snprintf(result, resultlen, "%c", action);
  else
    snprintf(result, resultlen, "%c%s/%u", action, addr, p.prefixlen);

  std::string out = result;

  delete [] result;

  return out;
}
