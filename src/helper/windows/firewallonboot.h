#pragma once

#include "scoped_permit_plan.h"

class FirewallOnBootManager
{
public:
    static FirewallOnBootManager& instance()
    {
        static FirewallOnBootManager fobm;
        return fobm;
    }

    // false if the setting could not be written (the registry keeps the old one).
    bool setEnabled(bool enabled);
    // Enabled, disabled (also: never set), or unreadable (the key or value exists but cannot be read).
    scoped_permits::BootSetting setting();

private:
    FirewallOnBootManager();
    ~FirewallOnBootManager();

    bool enable();
    bool disable();
};
