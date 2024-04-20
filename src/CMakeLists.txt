project(Gears)

# projects executable name
set(TARGET_NAME Gears)

set(
  GEARS_SOURCE_FILES
    StringManip.cpp
    AsciiStringManip.cpp
    Time.cpp
    Condition.cpp
    ActiveObject.cpp
    CompositeActiveObject.cpp 
    StringManip.cpp
    ThreadRunner.cpp
    TaskRunner.cpp
    Planner.cpp
    Time.cpp
    Logger.cpp
    StreamLogger.cpp
    SimpleLogger.cpp
    ActiveObjectCallback.cpp
    Rand.cpp
    Listener.cpp
    Singleton.cpp
    AppUtils.cpp
    TextTemplate.cpp
    MMap.cpp
    CRC.cpp
    PathManip.cpp
    UTF8Category.cpp
    UTF8IsDigit.cpp
    UTF8IsSpace.cpp
    UTF8IsLetter.cpp
    UTF8IsLowerLetter.cpp
    UTF8IsUpperLetter.cpp
    UTF8IsTitleLetter.cpp
    MemBuf.cpp
    Allocator.cpp
    UrlAddress.cpp
    UnicodeNormalizer.cpp
    UnicodeNormTables.cpp
)

add_library(${TARGET_NAME} SHARED ${GEARS_SOURCE_FILES})

target_include_directories(${TARGET_NAME} PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include/gears>
  )

target_link_libraries(${TARGET_NAME}
  ${LIBEVENT_LIB}
  ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS ${TARGET_NAME} DESTINATION lib)
