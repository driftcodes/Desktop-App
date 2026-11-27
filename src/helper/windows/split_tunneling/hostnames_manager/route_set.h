#pragma once

#include <map>
#include <set>
#include <vector>

// The split tunneling destination routes (IpRoutes), kept free of the Windows routing API so they can
// be unit-tested. A destination is in place when its route was created, the same route (prefix,
// interface and next hop, read back) already existed, or it needs none (directly attached, e.g.
// loopback or the local subnet, or IPv6 on a network without IPv6; see needsNoRouteForFamily). A
// route for the same prefix and interface through another next hop is someone else's: left alone,
// and the destination is not in place. A route that could not be deleted stays tracked and is deleted again on the next update or
// clear: it would otherwise keep sending that destination outside the tunnel after it was taken off
// the list, with nothing left to remove it.
namespace route_set {

enum class CreateResult { kCreated, kAlreadyThere, kFailed };

// A destination of a family the adapter has no gateway for. IPv4 always needs one: an exclusion
// without a route is not in place (the engine retries, then ends a proxied attempt). An IPv6
// destination needs none when the network has no IPv6 at all (an IPv4 gateway but none for IPv6):
// that traffic cannot leave the adapter either way.
inline bool needsNoRouteForFamily(bool isV6, bool hasGatewayV4, bool hasGatewayV6)
{
    return isV6 && !hasGatewayV6 && hasGatewayV4;
}

// HostnamesManager::disable(): the routes are cleared when it was enabled, and also, while disabled,
// as long as an earlier clear left one behind (each later disable or periodic retry tries again).
inline bool shouldClearOnDisable(bool isEnabled, bool hasLeftovers)
{
    return isEnabled || hasLeftovers;
}
enum class DeleteResult { kDeleted, kNotFound, kFailed };

template <typename Key, typename Row>
class RouteSet
{
public:
    // needsNoRoute(key): directly attached, or no gateway of its family. create(key, row) fills row
    // (on kCreated). remove(row).
    template <typename NeedsNoRoute, typename Create, typename Remove>
    bool apply(const std::set<Key> &wanted, NeedsNoRoute needsNoRoute, Create create, Remove remove)
    {
        retryStale(remove);
        for (auto it = active_.begin(); it != active_.end();) {
            if (wanted.count(it->first) == 0) {
                removeOrKeep(it->second, remove);
                it = active_.erase(it);
            } else {
                ++it;
            }
        }
        inPlace_.clear();
        for (const Key &key : wanted) {
            if (active_.count(key) != 0 || needsNoRoute(key)) {
                inPlace_.insert(key);
                continue;
            }
            Row row {};
            switch (create(key, row)) {
            case CreateResult::kCreated:
                active_[key] = row;
                inPlace_.insert(key);
                break;
            case CreateResult::kAlreadyThere:
                inPlace_.insert(key);  // not ours: left in place when the list changes
                break;
            case CreateResult::kFailed:
                break;
            }
        }
        return isApplied(wanted);
    }

    template <typename Remove>
    bool clear(Remove remove)
    {
        retryStale(remove);
        for (const auto &kv : active_) {
            removeOrKeep(kv.second, remove);
        }
        active_.clear();
        inPlace_.clear();
        return stale_.empty();
    }

    // Every wanted destination in place, and no route left behind that should be gone.
    bool isApplied(const std::set<Key> &wanted) const
    {
        if (!stale_.empty()) {
            return false;
        }
        for (const Key &key : wanted) {
            if (inPlace_.count(key) == 0) {
                return false;
            }
        }
        return true;
    }
    size_t staleCount() const { return stale_.size(); }
    bool hasLeftovers() const { return !stale_.empty(); }
    size_t activeCount() const { return active_.size(); }

private:
    template <typename Remove>
    void removeOrKeep(const Row &row, Remove remove)
    {
        if (remove(row) == DeleteResult::kFailed) {
            stale_.push_back(row);
        }
    }
    template <typename Remove>
    void retryStale(Remove remove)
    {
        std::vector<Row> stillThere;
        for (const Row &row : stale_) {
            if (remove(row) == DeleteResult::kFailed) {
                stillThere.push_back(row);
            }
        }
        stale_ = stillThere;
    }

    std::map<Key, Row> active_;
    std::set<Key> inPlace_;
    std::vector<Row> stale_;
};

} // namespace route_set
