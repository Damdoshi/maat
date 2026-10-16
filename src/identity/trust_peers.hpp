#pragma once

#include <iosfwd>
#include <string>
#include <vector>

namespace maat { namespace identity {

// Locally configured peers are TRANSPORT destinations, never trust roots.
// The registry identifier and signing key are independently pinned by the
// caller; a peer cannot update either of them.
struct TrustPeer final {
    std::string destination;
    std::string port;
    std::string privateKey;
    std::string knownHosts;
    unsigned maxPages = 256;
};

// A deliberately small, non-shell configuration grammar:
//   user@host port /absolute/ssh_private_key /absolute/pinned_known_hosts [pages]
// One peer per line, '#' comments on their own lines only; at most 8 peers.
std::vector<TrustPeer> parseTrustPeers(std::istream& in);

// Refuse symlinks, non-regular, shared-writable or unowned config files.
// The configuration directory must also be controlled by the operator.
std::vector<TrustPeer> loadTrustPeers(const std::string& absolutePath);

}} // namespace maat::identity
