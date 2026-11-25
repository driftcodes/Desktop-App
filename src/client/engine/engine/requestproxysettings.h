#pragma once

#include <optional>

#include "types/proxysettings.h"

// The proxy settings a connection request was made with. Engine::connectClickImpl takes them when the
// user picks a location; everything that request leads to (re-entry after the previous session has
// ended, the request built for the connection manager, a redial after fetching server credentials or
// a node evacuation, the DNS leak filter's hand-over) uses them, not the preference as it is later: a
// profile picked with the proxy on must not become a direct connection because the proxy was turned
// off while the previous session was ending. So does the engine's own traffic meanwhile (API requests
// such as the credential fetch, the firewall's proxy exception, direct probes of imported servers):
// a preference change takes effect for it when the session ends. Cleared when the session ends.
class RequestProxySettings
{
public:
    void onRequest(const types::ProxySettings &current) { settings_ = current; }
    void onSessionEnded() { settings_.reset(); }
    // The request's settings, or the current preference when no request is in progress.
    types::ProxySettings get(const types::ProxySettings &current) const { return settings_ ? *settings_ : current; }
    bool isRequestInProgress() const { return settings_.has_value(); }

    // The proxy the engine's own traffic should switch to, if it differs from the one it was last
    // given (nothing while a request keeps its settings and the preference changes).
    std::optional<types::ProxySettings> engineTrafficUpdate(const types::ProxySettings &current)
    {
        const types::ProxySettings wanted = get(current);
        if (engineTraffic_ && *engineTraffic_ == wanted) {
            return std::nullopt;
        }
        engineTraffic_ = wanted;
        return wanted;
    }

private:
    std::optional<types::ProxySettings> settings_;
    std::optional<types::ProxySettings> engineTraffic_;
};
