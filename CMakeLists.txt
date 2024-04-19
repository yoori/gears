project(Gears)

add_subdirectory(src)

set(TARGET_NAME Gears)
install(TARGETS ${TARGET_NAME} DESTINATION lib)
