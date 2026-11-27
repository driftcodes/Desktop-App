#pragma once

#include <fwptypes.h>
#include <string>
#include <vector>

class AppsIds
{
public:
    AppsIds();
    AppsIds(const AppsIds &a);
    ~AppsIds();

    void setFromList(const std::vector<std::wstring> &apps);
    void addFrom(const AppsIds &a);

    size_t count() const;
    // The programs of the last setFromList() that exist but could not be identified (their rules are
    // missing). A path that does not exist is not one: there is no such program to run.
    const std::vector<std::wstring> &unresolved() const { return unresolved_; }
    const FWP_BYTE_BLOB *getAppId(size_t ind) const;

    bool operator==(const AppsIds& other) const;

    AppsIds& operator = (const AppsIds &a);

private:
    std::vector<FWP_BYTE_BLOB> appIds_;
    std::vector<std::wstring> unresolved_;

    void clear();
    void addFromListImpl(const std::vector<std::wstring> &apps);
    void addFromAppsImpl(const AppsIds &a);
};
