#pragma once

// Who may change the Windows DNS leak filter. Two callers share it: the OpenVPN / WireGuard / IKEv2
// connectors (each enables it when it starts and disables it when it ends) and the engine, which
// holds it for a whole proxied session, reconnects included. Their lifetimes overlap: on a location
// switch the next session's rules are in place before the previous connector has ended, and a late
// retry of the engine's can arrive once a connector manages the filter. So the filter follows one
// owner at a time, and the other's requests are ignored meanwhile.
enum class DnsLeakFilterOwner : int {
    kConnection = 0,      // a connector (sessions without a proxy)
    kProxiedSession = 1,  // the engine (sessions with a proxy)
    kAny = 2              // cleanup (app start, firewall removal tool): always carried out
};

class DnsLeakFilterOwnership
{
public:
    // Whether an enable request is carried out. The engine always may: it claims the filter for a
    // proxied session, also from a connector that is still ending. A connector may not while the
    // engine holds it.
    bool acceptEnable(DnsLeakFilterOwner requester)
    {
        if (requester == DnsLeakFilterOwner::kConnection && hasOwner_ && owner_ == DnsLeakFilterOwner::kProxiedSession) {
            return false;
        }
        owner_ = requester == DnsLeakFilterOwner::kAny ? DnsLeakFilterOwner::kConnection : requester;
        hasOwner_ = true;
        return true;
    }

    // Whether a disable request is carried out: only by the owner (or for cleanup). Ownership ends
    // with the request even if the rules cannot be removed, so the next owner is not locked out; the
    // releasing caller retries the removal, which is ignored once someone else owns the filter.
    bool acceptDisable(DnsLeakFilterOwner requester)
    {
        if (requester != DnsLeakFilterOwner::kAny && hasOwner_ && owner_ != requester) {
            return false;
        }
        hasOwner_ = false;
        return true;
    }

    bool hasOwner() const { return hasOwner_; }
    DnsLeakFilterOwner owner() const { return owner_; }

private:
    DnsLeakFilterOwner owner_ = DnsLeakFilterOwner::kConnection;
    bool hasOwner_ = false;
};
