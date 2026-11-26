#include "ws_branding.h"
#include <spdlog/spdlog.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Fwpmu.h>
#include <iphlpapi.h>

#include "dns_firewall.h"
#include "scoped_permit_plan.h"
#include "utils.h"
#include "utils/log/debug_trace.h"

#define FIREWALL_SUBLAYER_DNS_NAMEW WS_APP_IDENTIFIER_W L"DnsFirewallSublayer"
#define UUID_LAYER_DNS L"7e4a5678-bc70-45e8-8674-21a8e610fd02"
#define FIREWALL_SUBLAYER_DNS_BASELINE_NAMEW WS_APP_IDENTIFIER_W L"DnsBaselineSublayer"
// v2: global blocks. The id of the first version (per-adapter blocks) is removed at start.
#define UUID_LAYER_DNS_BASELINE L"9a3d5e71-2c4b-4f8e-b6a1-73d0c5e9f214"
#define UUID_LAYER_DNS_BASELINE_V1 L"c4b2f1d6-6a3e-4e8b-9d27-5f0a8e3b71c9"


DnsFirewall::DnsFirewall(FwpmWrapper &fwmpWrapper) : fwmpWrapper_(fwmpWrapper), bCurrentState_(false)
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    UuidFromString((RPC_WSTR)UUID_LAYER_DNS, &subLayerGUID_);
    UuidFromString((RPC_WSTR)UUID_LAYER_DNS_BASELINE, &baselineSubLayerGUID_);
    UuidFromString((RPC_WSTR)UUID_LAYER_DNS_BASELINE_V1, &legacyBaselineSubLayerGUID_);
}

DnsFirewall::~DnsFirewall()
{
    stopMonitor();
}

void DnsFirewall::release()
{
    disable(DnsLeakFilterOwner::kAny);
    stopMonitor();
    WSACleanup();
}

namespace {

// The DnsFirewall sublayer's rules in one WFP transaction (see scoped_permits::replaceDnsRules).
class WfpDnsRuleStore : public scoped_permits::DnsRuleStore
{
public:
    WfpDnsRuleStore(FwpmWrapper &wrapper, HANDLE engine, const GUID &subLayer, AppsIds &permittedApps)
        : wrapper_(wrapper), engine_(engine), subLayer_(subLayer), permittedApps_(permittedApps) {}

    bool begin() override { return wrapper_.beginTransaction(); }

    bool removeAll() override
    {
        bool allDeleted = true;
        const GUID layers[] = {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                               FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
        for (const GUID &layer : layers) {
            Utils::deleteAllFiltersForSublayer(engine_, &subLayer_, layer, &allDeleted);
        }
        return allDeleted;
    }

    bool ensureSublayer() override
    {
        FWPM_SUBLAYER0 subLayer = { 0 };
        subLayer.subLayerKey = subLayer_;
        subLayer.displayData.name = (wchar_t *)FIREWALL_SUBLAYER_DNS_NAMEW;
        subLayer.displayData.description = (wchar_t *)FIREWALL_SUBLAYER_DNS_NAMEW;
        subLayer.flags = 0;
        subLayer.weight = 0xFFFF;
        const DWORD ret = FwpmSubLayerAdd0(engine_, &subLayer, NULL);
        if (ret != ERROR_SUCCESS && ret != FWP_E_ALREADY_EXISTS) {
            spdlog::error("DnsFirewall: FwpmSubLayerAdd0 failed: {}", ret);
            return false;
        }
        return true;
    }

    bool add(const scoped_permits::DnsRule &rule) override
    {
        // Blocks at weight 6, above the main firewall's LAN permit (4); permits for the permitted
        // programs at 7, which win within this sublayer. The main firewall still decides separately
        // whether those programs may reach the address.
        const std::vector<types::IpAddressRange> addr = { rule.target };
        const FWP_ACTION_TYPE action = rule.isPermitForApps ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
        const UINT8 weight = rule.isPermitForApps ? 7 : 6;
        AppsIds *apps = rule.isPermitForApps ? &permittedApps_ : nullptr;
        bool ret = false;
        if (rule.target.isV4()) {
            ret = Utils::addFilterV4(engine_, nullptr, action, weight, subLayer_, (wchar_t*)FIREWALL_SUBLAYER_DNS_NAMEW, nullptr, &addr, 0, 53, apps, false);
        } else if (rule.target.isV6()) {
            ret = Utils::addFilterV6(engine_, nullptr, action, weight, subLayer_, (wchar_t*)FIREWALL_SUBLAYER_DNS_NAMEW, nullptr, &addr, 0, 53, apps, false);
        }
        const char *kind = rule.isPermitForApps ? "permit (permitted programs)" : "block";
        if (!ret) {
            spdlog::error("Could not add DNS {} filter for {}", kind, rule.target.toString());
        } else {
            spdlog::debug("Added DNS {} filter for {}", kind, rule.target.toString());
        }
        return ret;
    }

    bool commit() override { return wrapper_.endTransaction(); }
    void abort() override { wrapper_.abortTransaction(); }

private:
    FwpmWrapper &wrapper_;
    HANDLE engine_;
    GUID subLayer_;
    AppsIds &permittedApps_;
};

// The baseline's sublayer: persistent sublayer and filters, like the main firewall's.
class WfpBaselineRuleStore : public scoped_permits::RuleStore<scoped_permits::BaselineRule>
{
public:
    WfpBaselineRuleStore(FwpmWrapper &wrapper, HANDLE engine, const GUID &subLayer, AppsIds &permittedApps)
        : wrapper_(wrapper), engine_(engine), subLayer_(subLayer), permittedApps_(permittedApps) {}

    bool begin() override { return wrapper_.beginTransaction(); }

    bool removeAll() override
    {
        bool allDeleted = true;
        const GUID layers[] = {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                               FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
        for (const GUID &layer : layers) {
            Utils::deleteAllFiltersForSublayer(engine_, &subLayer_, layer, &allDeleted);
        }
        return allDeleted;
    }

    bool ensureSublayer() override
    {
        FWPM_SUBLAYER0 subLayer = { 0 };
        subLayer.subLayerKey = subLayer_;
        subLayer.displayData.name = (wchar_t *)FIREWALL_SUBLAYER_DNS_BASELINE_NAMEW;
        subLayer.displayData.description = (wchar_t *)FIREWALL_SUBLAYER_DNS_BASELINE_NAMEW;
        subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        subLayer.weight = 0xFFFE;
        const DWORD ret = FwpmSubLayerAdd0(engine_, &subLayer, NULL);
        if (ret != ERROR_SUCCESS && ret != FWP_E_ALREADY_EXISTS) {
            spdlog::error("DnsFirewall: baseline FwpmSubLayerAdd0 failed: {}", ret);
            return false;
        }
        return true;
    }

    bool add(const scoped_permits::BaselineRule &rule) override
    {
        // Port 53, UDP and TCP. Weights from scoped_permits::baselineWeight: the highest matching
        // filter wins in this sublayer.
        using scoped_permits::BaselineAction;
        const FWP_ACTION_TYPE action = rule.action == BaselineAction::kBlock ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
        const UINT8 weight = scoped_permits::baselineWeight(rule.action);
        AppsIds *apps = rule.action == BaselineAction::kPermitApps ? &permittedApps_ : nullptr;
        NET_LUID luid;
        luid.Value = rule.interfaceLuid;
        PNET_LUID pluid = rule.interfaceLuid != 0 ? &luid : nullptr;
        std::vector<types::IpAddressRange> addr;
        if (rule.range.isValid()) {
            addr.push_back(rule.range);
        }
        const std::vector<types::IpAddressRange> *range = addr.empty() ? nullptr : &addr;
        const bool ret = rule.isV6
            ? Utils::addFilterV6(engine_, nullptr, action, weight, subLayer_, (wchar_t*)FIREWALL_SUBLAYER_DNS_BASELINE_NAMEW, pluid, range, 0, 53, apps, rule.isPersistent)
            : Utils::addFilterV4(engine_, nullptr, action, weight, subLayer_, (wchar_t*)FIREWALL_SUBLAYER_DNS_BASELINE_NAMEW, pluid, range, 0, 53, apps, rule.isPersistent);
        if (!ret) {
            spdlog::error("Could not add DNS baseline filter (action {}, v6 {}, interface {})",
                          static_cast<int>(rule.action), rule.isV6, rule.interfaceLuid);
        }
        return ret;
    }

    bool commit() override { return wrapper_.endTransaction(); }
    void abort() override { wrapper_.abortTransaction(); }

private:
    FwpmWrapper &wrapper_;
    HANDLE engine_;
    GUID subLayer_;
    AppsIds &permittedApps_;
};

} // namespace

bool DnsFirewall::disable(DnsLeakFilterOwner requester, bool keepRules)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (!requests_.acceptDisable(requester)) {
        spdlog::info("DnsFirewall::disable() from {} ignored: the filter belongs to {}", static_cast<int>(requester),
                     static_cast<int>(requests_.ownership().owner()));
        return true;
    }
    if (keepRules) {
        spdlog::info("DnsFirewall: handed over by {}; rules stay until the next owner replaces them",
                     static_cast<int>(requester));
        return true;
    }
    HANDLE hEngine = fwmpWrapper_.getHandleAndLock();

    bool isRemoved = false;
    if (fwmpWrapper_.beginTransaction()) {
        bool allDeleted = true;
        const GUID layers[] = {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                               FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
        for (const GUID &layer : layers) {
            Utils::deleteAllFiltersForSublayer(hEngine, &subLayerGUID_, layer, &allDeleted);
        }
        if (allDeleted) {
            const DWORD ret = FwpmSubLayerDeleteByKey0(hEngine, &subLayerGUID_);
            if (ret != ERROR_SUCCESS && ret != FWP_E_SUBLAYER_NOT_FOUND) {
                spdlog::error("DnsFirewall::disable(), FwpmSubLayerDeleteByKey0 failed: {}", ret);
            }
            isRemoved = fwmpWrapper_.endTransaction();
        } else {
            // Keep it whole rather than half removed; the client retries.
            fwmpWrapper_.abortTransaction();
        }
    }
    fwmpWrapper_.unlock();

    if (isRemoved) {
        bCurrentState_ = false;
        isDirty_ = false;
        appliedServers_.clear();
        permittedApps_.onNoPermitsInPlace();
        spdlog::debug("DnsFirewall::disable(), all filters deleted");
        updateBaselineIfNeeded();
    } else {
        spdlog::error("DnsFirewall::disable() failed; the DNS leak filter stays as it was");
    }
    return isRemoved;
}

DnsLeakFilterResult DnsFirewall::enable(bool permitApps, DnsLeakFilterOwner requester,
                                        const std::set<types::IpAddress> &excludeIps)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (!requests_.acceptEnable(requester, permitApps, excludeIps)) {
        spdlog::info("DnsFirewall::enable() from {} ignored: the filter belongs to {}", static_cast<int>(requester),
                     static_cast<int>(requests_.ownership().owner()));
        return DnsLeakFilterResult::kIgnored;
    }
    startMonitor();
    return enableImpl();
}

DnsLeakFilterResult DnsFirewall::enableImpl()
{
    const bool permitApps = requests_.permitApps();
    AppsIds permittedApps;
    if (permitApps) {
        permittedApps = permittedApps_.requested();
        if (permittedApps.count() == 0) {
            spdlog::error("DnsFirewall::enable(), no permitted programs known; blocking DNS for every program");
        }
    }
    std::set<types::IpAddress> dnsServers;
    const bool serversKnown = getDnsServers(dnsServers);
    const auto plan = scoped_permits::planDnsRules(serversKnown, dnsServers, appliedServers_, requests_.excluded(), permitApps,
                                                   permittedApps.count());

    HANDLE hEngine = fwmpWrapper_.getHandleAndLock();
    WfpDnsRuleStore store(fwmpWrapper_, hEngine, subLayerGUID_, permittedApps);
    // Old rules out and new rules in within one transaction, aborted (keeping the old rules) unless
    // every block is in: re-enabling never leaves a moment without the block.
    const auto result = scoped_permits::replaceDnsRules(store, plan.canApply, plan.rules);
    fwmpWrapper_.unlock();

    if (result == scoped_permits::ReplaceResult::kKeptPrevious) {
        spdlog::error("DnsFirewall::enable() failed (adapters readable: {}); the previous rules stay", serversKnown);
        isDirty_ = true;
        return DnsLeakFilterResult::kFailed;
    }
    bCurrentState_ = true;
    if (!plan.isFallback) {
        appliedServers_ = dnsServers;
    }
    if (permitApps && result == scoped_permits::ReplaceResult::kApplied) {
        permittedApps_.onApplied();
    } else {
        permittedApps_.onNoPermitsInPlace();
    }
    isDirty_ = plan.isFallback || result != scoped_permits::ReplaceResult::kApplied;
    // The session filter's mode decides whether the baseline permits the custom connected DNS.
    updateBaselineIfNeeded();
    if (isDirty_) {
        spdlog::error("DnsFirewall::enable(), blocks in place but incomplete (adapters unreadable: {}); will retry",
                      plan.isFallback);
        return DnsLeakFilterResult::kIncomplete;
    }
    return DnsLeakFilterResult::kApplied;
}

void DnsFirewall::setWindscribeAppsIds(const AppsIds &appsIds)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    windscribeAppsIds_ = appsIds;
    updatePermittedApps();
}

void DnsFirewall::setExcludedAppsIds(const AppsIds &appsIds)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    excludedAppsIds_ = appsIds;
    isExcludedAppsKnown_ = true;
    isWaitingForExcludedApps_ = false;
    updatePermittedApps();
}

void DnsFirewall::updatePermittedApps()
{
    AppsIds permitted = windscribeAppsIds_;
    permitted.addFrom(excludedAppsIds_);
    // Compared with the programs of the rules in place, not with the last request: after a failed
    // rebuild the old permits are still there, so the same list sent again must still rebuild.
    if (permittedApps_.request(permitted) && requests_.isWanted() && requests_.permitApps()) {
        enableImpl();  // on failure isDirty_ is set and the monitor retries
    }
    updateBaselineIfNeeded();
}

std::set<types::IpAddress> DnsFirewall::baselinePermittedAddresses() const
{
    if (requests_.isWanted() && !requests_.permitApps()) {
        return requests_.excluded();
    }
    return {};
}

bool DnsFirewall::setBaselineEnabled(bool isEnabled)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (isEnabled) {
        if (!isBaselineEnabled_) {
            isBaselineEnabled_ = true;
            isBaselineDirty_ = true;  // build it now
        }
        startMonitor();
        updateBaselineIfNeeded();
        return isBaselineInPlace_;
    }
    isBaselineEnabled_ = false;
    isWaitingForExcludedApps_ = false;
    if (!removeBaselineImpl()) {
        isBaselineDirty_ = true;  // the monitor retries the removal
        startMonitor();
    }
    return true;
}

void DnsFirewall::setBaselineReadyCallback(std::function<void()> callback)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    baselineReadyCallback_ = std::move(callback);
}

bool DnsFirewall::adoptBaselineAtStart()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    isBaselineEnabled_ = true;
    startMonitor();
    if (!removeSublayerWithFilters(legacyBaselineSubLayerGUID_)) {
        spdlog::error("DnsFirewall: could not remove the first version's DNS baseline");
    }
    bool isV4Verified = false;
    bool isV6Verified = false;
    findBaselineBlocks(isV4Verified, isV6Verified);
    if (scoped_permits::planBaselineAtStart(isV4Verified, isV6Verified) == scoped_permits::BaselineAtStart::kBuild) {
        spdlog::info("DnsFirewall: no complete DNS baseline from before (v4 block {}, v6 block {}); building one",
                     isV4Verified, isV6Verified);
        isBaselineInPlace_ = false;
        isBaselineDirty_ = true;
        updateBaselineIfNeeded();
        return isBaselineInPlace_;
    }
    // The persistent rules from before block DNS on every adapter (including any added while Windows
    // was off) and, unlike a rebuild now, already permit the excluded apps, which the client only
    // sends later. They hold no tunnel or custom DNS permit (those are not persistent).
    isBaselineInPlace_ = true;
    baselineTunnels_.clear();
    baselineAddresses_.clear();
    isWaitingForExcludedApps_ = !isExcludedAppsKnown_;
    spdlog::info("DnsFirewall: keeping the verified DNS baseline from before until the client's excluded apps arrive");
    addTunnelPermitsWhileWaiting();
    return true;
}

bool DnsFirewall::isBaselineInPlace()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return isBaselineEnabled_ && isBaselineInPlace_;
}

void DnsFirewall::addTunnelPermitsWhileWaiting()
{
    // A Windscribe tunnel adapter needs its permit, but rebuilding now would drop the saved permit
    // for the excluded apps (Throne) until the client sends them: add only the tunnel permits.
    if (!isWaitingForExcludedApps_) {
        return;
    }
    std::set<types::IpAddress> servers;
    std::set<uint64_t> tunnels;
    if (!getAdapters(servers, tunnels)) {
        return;
    }
    std::vector<scoped_permits::BaselineRule> rules;
    for (const auto &rule : scoped_permits::dnsBaselineRules(tunnels, {}, 0)) {
        if (rule.action == scoped_permits::BaselineAction::kPermitTunnel && baselineTunnels_.count(rule.interfaceLuid) == 0) {
            rules.push_back(rule);
        }
    }
    if (rules.empty()) {
        return;
    }
    AppsIds noApps;
    HANDLE hEngine = fwmpWrapper_.getHandleAndLock();
    WfpBaselineRuleStore store(fwmpWrapper_, hEngine, baselineSubLayerGUID_, noApps);
    bool isAdded = store.begin() && store.ensureSublayer();
    for (const auto &rule : rules) {
        isAdded = isAdded && store.add(rule);
    }
    if (isAdded) {
        isAdded = store.commit();
    } else {
        store.abort();
    }
    fwmpWrapper_.unlock();
    if (isAdded) {
        for (const auto &rule : rules) {
            baselineTunnels_.insert(rule.interfaceLuid);
        }
        spdlog::info("DnsFirewall: added DNS baseline permits for {} tunnel adapter(s), saved rules kept", rules.size() / 2);
    } else {
        spdlog::error("DnsFirewall: could not add the tunnel adapter's DNS baseline permit; retrying");
    }
}

void DnsFirewall::updateBaselineIfNeeded()
{
    if (!isBaselineEnabled_ || isWaitingForExcludedApps_) {
        return;
    }
    std::set<types::IpAddress> servers;
    std::set<uint64_t> tunnels;
    const bool isKnown = getAdapters(servers, tunnels);
    const bool appsChanged = baselineApps_.request(permittedApps_.requested());
    const bool tunnelsChanged = isKnown && tunnels != baselineTunnels_;
    const bool addressesChanged = baselinePermittedAddresses() != baselineAddresses_;
    if (isBaselineDirty_ || appsChanged || tunnelsChanged || addressesChanged) {
        applyBaselineImpl();
    }
}

void DnsFirewall::applyBaselineImpl()
{
    // The block does not depend on the adapters; only the tunnel permits do. If they cannot be read,
    // the last ones known are used and the monitor retries.
    std::set<types::IpAddress> servers;
    std::set<uint64_t> tunnels;
    const bool isKnown = getAdapters(servers, tunnels);
    if (!isKnown) {
        tunnels = baselineTunnels_;
    }
    AppsIds permittedApps = permittedApps_.requested();
    baselineApps_.request(permittedApps);
    const std::set<types::IpAddress> addresses = baselinePermittedAddresses();
    const auto rules = scoped_permits::dnsBaselineRules(tunnels, addresses, permittedApps.count());

    HANDLE hEngine = fwmpWrapper_.getHandleAndLock();
    WfpBaselineRuleStore store(fwmpWrapper_, hEngine, baselineSubLayerGUID_, permittedApps);
    const auto result = scoped_permits::replaceDnsRules(store, true, rules);
    fwmpWrapper_.unlock();

    if (result == scoped_permits::ReplaceResult::kKeptPrevious) {
        spdlog::error("DnsFirewall: DNS baseline could not be {}; {}", isBaselineInPlace_ ? "rebuilt" : "installed",
                      isBaselineInPlace_ ? "the previous rules stay" : "the firewall holds its LAN permit back");
        isBaselineDirty_ = true;
        return;
    }
    if (!isBaselineInPlace_) {
        isReadyNotificationPending_ = true;  // the monitor calls the ready callback
    }
    isBaselineInPlace_ = true;
    baselineTunnels_ = tunnels;
    baselineAddresses_ = addresses;
    if (result == scoped_permits::ReplaceResult::kApplied && isKnown) {
        baselineApps_.onApplied();
        isBaselineDirty_ = false;
    } else {
        if (result != scoped_permits::ReplaceResult::kApplied) {
            baselineApps_.onNoPermitsInPlace();
            spdlog::error("DnsFirewall: DNS baseline blocks in place, a permit is missing; will retry");
        } else {
            baselineApps_.onApplied();
        }
        isBaselineDirty_ = true;
    }
    spdlog::info("DnsFirewall: DNS baseline on, {} tunnel adapter(s), {} permitted address(es), {} program(s)",
                 tunnels.size(), addresses.size(), permittedApps.count());
}

bool DnsFirewall::removeBaselineImpl()
{
    removeSublayerWithFilters(legacyBaselineSubLayerGUID_);
    const bool isRemoved = removeSublayerWithFilters(baselineSubLayerGUID_);
    if (isRemoved) {
        isBaselineInPlace_ = false;
        baselineTunnels_.clear();
        baselineAddresses_.clear();
        baselineApps_.onNoPermitsInPlace();
        isBaselineDirty_ = false;
    } else {
        spdlog::error("DnsFirewall: DNS baseline could not be removed; it stays");
    }
    return isRemoved;
}

void DnsFirewall::findBaselineBlocks(bool &isV4Found, bool &isV6Found)
{
    isV4Found = false;
    isV6Found = false;
    HANDLE hEngine = fwmpWrapper_.getHandleAndLock();
    const GUID layers[2] = {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6};
    for (int i = 0; i < 2; ++i) {
        bool &isFound = i == 0 ? isV4Found : isV6Found;
        FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate;
        ZeroMemory(&enumTemplate, sizeof(enumTemplate));
        enumTemplate.layerKey = layers[i];
        enumTemplate.actionMask = 0xFFFFFFFF;
        HANDLE enumHandle = NULL;
        if (FwpmFilterCreateEnumHandle0(hEngine, &enumTemplate, &enumHandle) != ERROR_SUCCESS) {
            spdlog::error("DnsFirewall: could not enumerate filters to verify the DNS baseline");
            continue;
        }
        FWPM_FILTER0 **filters = nullptr;
        UINT32 count = 0;
        while (!isFound && FwpmFilterEnum0(hEngine, enumHandle, INFINITE, &filters, &count) == ERROR_SUCCESS && count > 0) {
            for (UINT32 k = 0; k < count && !isFound; ++k) {
                const FWPM_FILTER0 &f = *filters[k];
                if (f.subLayerKey != baselineSubLayerGUID_) {
                    continue;
                }
                scoped_permits::InstalledFilter summary = {};
                summary.isBlock = f.action.type == FWP_ACTION_BLOCK;
                summary.isPersistent = (f.flags & FWPM_FILTER_FLAG_PERSISTENT) != 0;
                for (UINT32 j = 0; j < f.numFilterConditions; ++j) {
                    const FWPM_FILTER_CONDITION0 &cond = f.filterCondition[j];
                    if (cond.fieldKey == FWPM_CONDITION_IP_REMOTE_PORT && cond.conditionValue.type == FWP_UINT16 &&
                        cond.conditionValue.uint16 == 53) {
                        summary.hasRemotePort53 = true;
                    } else if (cond.fieldKey == FWPM_CONDITION_IP_LOCAL_INTERFACE) {
                        summary.hasInterfaceCondition = true;
                    } else if (cond.fieldKey == FWPM_CONDITION_IP_REMOTE_ADDRESS) {
                        summary.hasAddressCondition = true;
                    } else if (cond.fieldKey == FWPM_CONDITION_ALE_APP_ID) {
                        summary.hasAppCondition = true;
                    }
                }
                isFound = scoped_permits::isGlobalBaselineBlock(summary);
            }
            FwpmFreeMemory0((void **)&filters);
        }
        FwpmFilterDestroyEnumHandle0(hEngine, enumHandle);
    }
    fwmpWrapper_.unlock();
}

bool DnsFirewall::removeSublayerWithFilters(const GUID &subLayer)
{
    HANDLE hEngine = fwmpWrapper_.getHandleAndLock();
    bool isRemoved = false;
    if (fwmpWrapper_.beginTransaction()) {
        bool allDeleted = true;
        const GUID layers[] = {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                               FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
        for (const GUID &layer : layers) {
            Utils::deleteAllFiltersForSublayer(hEngine, &subLayer, layer, &allDeleted);
        }
        if (allDeleted) {
            const DWORD ret = FwpmSubLayerDeleteByKey0(hEngine, &subLayer);
            if (ret != ERROR_SUCCESS && ret != FWP_E_SUBLAYER_NOT_FOUND) {
                spdlog::error("DnsFirewall: FwpmSubLayerDeleteByKey0 failed: {}", ret);
            }
            isRemoved = fwmpWrapper_.endTransaction();
        } else {
            fwmpWrapper_.abortTransaction();
        }
    }
    fwmpWrapper_.unlock();
    return isRemoved;
}

void DnsFirewall::startMonitor()
{
    if (monitor_.joinable()) {
        return;
    }
    stopMonitorEvent_ = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (stopMonitorEvent_ == NULL) {
        spdlog::error("DnsFirewall: CreateEvent failed: {}", ::GetLastError());
        return;
    }
    monitor_ = std::thread(&DnsFirewall::monitorThread, this);
}

void DnsFirewall::stopMonitor()
{
    if (!monitor_.joinable()) {
        return;
    }
    SetEvent(stopMonitorEvent_);
    monitor_.join();
    CloseHandle(stopMonitorEvent_);
    stopMonitorEvent_ = nullptr;
}

void DnsFirewall::monitorThread()
{
    // Windows keeps each adapter's DNS servers (static and DHCP) under these keys; a change there is
    // the earliest sign of a new resolver, on the same network or another. A short poll backs it up
    // and retries a rebuild that failed.
    const wchar_t *paths[2] = {L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                               L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces"};
    HKEY keys[2] = {nullptr, nullptr};
    HANDLE events[3] = {stopMonitorEvent_, CreateEvent(NULL, FALSE, FALSE, NULL), CreateEvent(NULL, FALSE, FALSE, NULL)};
    const auto arm = [&](int i) {
        if (keys[i] != nullptr && events[i + 1] != NULL) {
            const LONG ret = RegNotifyChangeKeyValue(keys[i], TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                                                     events[i + 1], TRUE);
            if (ret != ERROR_SUCCESS) {
                spdlog::error("DnsFirewall: RegNotifyChangeKeyValue failed: {}", ret);
            }
        }
    };
    for (int i = 0; i < 2; ++i) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paths[i], 0, KEY_NOTIFY, &keys[i]) != ERROR_SUCCESS) {
            keys[i] = nullptr;
            spdlog::error(L"DnsFirewall: could not watch {}; polling only", paths[i]);
        }
        arm(i);
    }
    const DWORD count = (events[1] != NULL && events[2] != NULL) ? 3 : 1;

    constexpr DWORD kPollMs = 2000;
    while (true) {
        const DWORD wait = WaitForMultipleObjects(count, events, FALSE, kPollMs);
        if (wait == WAIT_OBJECT_0) {
            break;
        }
        if (wait == WAIT_OBJECT_0 + 1) {
            arm(0);
        } else if (wait == WAIT_OBJECT_0 + 2) {
            arm(1);
        } else if (wait == WAIT_FAILED) {
            spdlog::error("DnsFirewall: WaitForMultipleObjects failed: {}", ::GetLastError());
            if (WaitForSingleObject(stopMonitorEvent_, kPollMs) == WAIT_OBJECT_0) {
                break;
            }
        }
        checkForChanges();
    }

    for (int i = 0; i < 2; ++i) {
        if (keys[i] != nullptr) {
            RegCloseKey(keys[i]);
        }
        if (events[i + 1] != NULL) {
            CloseHandle(events[i + 1]);
        }
    }
}

void DnsFirewall::checkForChanges()
{
    std::function<void()> callback;
    {
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (requests_.isWanted()) {
        std::set<types::IpAddress> servers;
        const bool serversKnown = getDnsServers(servers);
        const bool serversChanged = scoped_permits::dnsServersChanged(serversKnown, servers, appliedServers_);
        const bool appsChanged = requests_.permitApps() && permittedApps_.needsRebuild();
        if (isDirty_ || serversChanged || appsChanged) {
            spdlog::info("DnsFirewall: rebuilding (retry: {}, DNS servers changed: {}, programs changed: {})", isDirty_,
                         serversChanged, appsChanged);
            enableImpl();
        }
    }
    bool hasBecomeReady = false;
    if (isBaselineEnabled_) {
        // A Windscribe tunnel adapter appearing while the saved rules are kept gets its permit added.
        addTunnelPermitsWhileWaiting();
        updateBaselineIfNeeded();
        hasBecomeReady = isReadyNotificationPending_ && isBaselineInPlace_;
        isReadyNotificationPending_ = false;
    } else if (isBaselineDirty_) {
        // A removal that failed.
        removeBaselineImpl();
    }
    callback = hasBecomeReady ? baselineReadyCallback_ : std::function<void()>();
    }
    // Outside the lock: the callback turns the main firewall's LAN permit back on.
    if (callback) {
        callback();
    }
}

bool DnsFirewall::getDnsServers(std::set<types::IpAddress> &dnsServers)
{
    std::set<uint64_t> tunnelInterfaces;
    return getAdapters(dnsServers, tunnelInterfaces);
}

bool DnsFirewall::getAdapters(std::set<types::IpAddress> &dnsServers, std::set<uint64_t> &tunnelInterfaces)
{
    WS_DEBUG_TRACE_SCOPE("DnsFirewall::getAdapters");
    dnsServers.clear();
    tunnelInterfaces.clear();

    DWORD dwRetVal = 0;
    ULONG outBufLen = 0;
    ULONG iterations = 0;
    const int MAX_TRIES = 5;
    std::vector<unsigned char> arr;
    arr.resize(1);

    outBufLen = static_cast<ULONG>(arr.size());
    do {
        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, NULL, NULL, (PIP_ADAPTER_ADDRESSES)&arr[0], &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            arr.resize(outBufLen);
        } else {
            break;
        }
        iterations++;
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (iterations < MAX_TRIES));

    if (dwRetVal != NO_ERROR) {
        // An error, unlike a network without DNS servers (ERROR_NO_DATA: no adapters at all).
        if (dwRetVal == ERROR_NO_DATA) {
            return true;
        }
        spdlog::error("DnsFirewall::getDnsServers(), GetAdaptersAddresses failed: {}", dwRetVal);
        return false;
    }

    PIP_ADAPTER_ADDRESSES pCurrAddresses = (PIP_ADAPTER_ADDRESSES)&arr[0];
    while (pCurrAddresses) {
        // Warning: we control the FriendlyName of the wireguard-nt adapter, but not the Description.
        if ((wcsstr(pCurrAddresses->Description, WS_PRODUCT_NAME_W) != 0) ||
            (wcsstr(pCurrAddresses->FriendlyName, WS_PRODUCT_NAME_W) != 0)) {
            // Windscribe's own adapters: the tunnel (DNS through the VPN).
            tunnelInterfaces.insert(pCurrAddresses->Luid.Value);
        } else {
            PIP_ADAPTER_DNS_SERVER_ADDRESS dnsServerAddress = pCurrAddresses->FirstDnsServerAddress;
            while (dnsServerAddress) {
                const auto family = dnsServerAddress->Address.lpSockaddr->sa_family;
                if (family == AF_INET) {
                    const auto *sin = reinterpret_cast<const sockaddr_in *>(dnsServerAddress->Address.lpSockaddr);
                    types::IpAddress addr(types::IpAddress::IPv4,
                                          reinterpret_cast<const uint8_t *>(&sin->sin_addr), 4);
                    if (addr.isValid()) {
                        dnsServers.insert(std::move(addr));
                    }
                } else if (family == AF_INET6) {
                    const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(dnsServerAddress->Address.lpSockaddr);
                    types::IpAddress addr(types::IpAddress::IPv6,
                                          reinterpret_cast<const uint8_t *>(&sin6->sin6_addr), 16);
                    if (addr.isValid()) {
                        dnsServers.insert(std::move(addr));
                    }
                }
                dnsServerAddress = dnsServerAddress->Next;
            }
        }

        pCurrAddresses = pCurrAddresses->Next;
    }

    return true;
}
