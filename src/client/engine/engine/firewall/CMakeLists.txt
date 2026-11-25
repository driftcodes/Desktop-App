target_sources(engine PRIVATE
    firewallcontroller.cpp
    firewallcontroller.h
    firewallexceptions.cpp
    firewallexceptions.h
    firewallpolicy.cpp
    firewallpolicy.h
    uniqueiplist.cpp
    uniqueiplist.h
)

if (WIN32)
    target_sources(engine PRIVATE
        firewallcontroller_win.cpp
        firewallcontroller_win.h
    )
elseif(APPLE)
    target_sources(engine PRIVATE
        firewallcontroller_mac.cpp
        firewallcontroller_mac.h
    )
elseif(UNIX)
    target_sources(engine PRIVATE
        firewallcontroller_linux.cpp
        firewallcontroller_linux.h
    )
endif()

if(IS_BUILD_TESTS)
    add_subdirectory(tests)
endif(IS_BUILD_TESTS)
