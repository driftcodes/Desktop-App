if(IS_BUILD_TESTS)
    add_executable(firewallpolicy.test
        firewallpolicy.test.cpp
        firewallpolicy.test.h
    )
    target_link_libraries(firewallpolicy.test PRIVATE
        Qt6::Network Qt6::Test engine client-common wsnet::wsnet spdlog::spdlog ${OS_SPECIFIC_LIBRARIES})
    target_include_directories(firewallpolicy.test PRIVATE
        ${PROJECT_DIRECTORY}/engine
        ${PROJECT_DIRECTORY}/client-common
    )
    set_target_properties(firewallpolicy.test PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    ws_add_test(firewallpolicy)
endif(IS_BUILD_TESTS)
