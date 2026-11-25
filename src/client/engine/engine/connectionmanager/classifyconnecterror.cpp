#include "classifyconnecterror.h"

ConnectErrorClassification classifyConnectError(ConnectError err, bool isAutomaticMode, bool emitAuthError, bool retryOnAttemptFailure)
{
    switch (err) {
        case ConnectError::kAuthFailure:
            return emitAuthError ? ConnectErrorClassification::ErrorAfterDisconnect : ConnectErrorClassification::Retry;
        // An endpoint-list policy treats these local fatal errors as walk-to-the-next-endpoint;
        // otherwise they are attempt-fatal. A missing adapter driver (OpenVPN TAP) is reported only
        // after the non-TAP protocols in the automatic walk, so every remaining attempt needs the
        // same absent driver and failing over cannot help.
        case ConnectError::kLocalProcessNotResponding:
        case ConnectError::kAdapterNotInstalled:
            return retryOnAttemptFailure ? ConnectErrorClassification::Retry : ConnectErrorClassification::ErrorAfterDisconnect;
        case ConnectError::kLocalProcessLaunchFailure:
            return retryOnAttemptFailure ? ConnectErrorClassification::Retry : ConnectErrorClassification::ErrorImmediately;
        // A custom config the OpenVPN daemon rejected before binding its management socket. There is
        // no next endpoint to try, and the dialog shows the daemon's fatal line.
        case ConnectError::kCustomConfigInvalid:
            return ConnectErrorClassification::ErrorImmediately;
        case ConnectError::kAdapterSetupFailure:
            if (retryOnAttemptFailure) {
                return ConnectErrorClassification::Retry;
            }
            [[fallthrough]];
        // Automatic mode fails over to another protocol; manual mode surfaces the failure.
        case ConnectError::kTunnelEstablishmentFailure:
            return isAutomaticMode ? ConnectErrorClassification::Retry : ConnectErrorClassification::ErrorAfterDisconnect;
        case ConnectError::kPrivKeyPasswordFailure:
            return ConnectErrorClassification::ErrorAfterDisconnect;
        // The tunnel came up without its routes. Another attempt would fail the same way, and failing
        // over could pick a protocol that bypasses the configured proxy.
        case ConnectError::kRouteSetupFailure:
            return ConnectErrorClassification::ErrorAfterDisconnect;
        // The connector's DNS leak filter could not be installed; another attempt or protocol would
        // run without it as well.
        case ConnectError::kDnsLeakProtectionFailed:
            return ConnectErrorClassification::ErrorAfterDisconnect;
        case ConnectError::kVpnServiceSetupFailure:
        case ConnectError::kHostsFileNotWritable:
        case ConnectError::kOSServiceUnavailable:
            return isAutomaticMode ? ConnectErrorClassification::Retry : ConnectErrorClassification::ErrorImmediately;
        case ConnectError::kTransientTunnelFailure:
            return ConnectErrorClassification::Retry;
        // Not runtime connector errors: these arrive via classifyPrepareError or engine-level paths.
        case ConnectError::kNoError:
        case ConnectError::kLocationUnavailable:
        case ConnectError::kAccountBlocked:
        case ConnectError::kConfigFetchFailure:
        case ConnectError::kLocalConfigGenerationFailure:
        case ConnectError::kDnsServiceStartFailure:
        case ConnectError::kBlockedByOsPolicy:
        case ConnectError::kLocalDnsServerNotAvailable:
        case ConnectError::kProxyUnreachable:
        case ConnectError::kProxyRequiresTcp:
            return ConnectErrorClassification::Unknown;
    }
    return ConnectErrorClassification::Unknown;
}

// Routing for pre-dial prepare failures; runtime connector errors go through classifyConnectError.
// Config-acquisition failures route to failover rather than a hard stop: kLocalConfigGenerationFailure
// in both modes; API-exhausted (kConfigFetchFailure) only when automatic mode has a next option to
// advance to.
PrepareErrorRouting classifyPrepareError(ConnectError err, bool isAutomaticMode)
{
    if (err == ConnectError::kLocalConfigGenerationFailure ||
        (err == ConnectError::kConfigFetchFailure && isAutomaticMode)) {
        return PrepareErrorRouting::Failover;
    }
    return PrepareErrorRouting::HardStop;
}
