# Copyright (C) 2011-2012 Project SkyFire <http://www.projectskyfire.org/>
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

file(GLOB_RECURSE sources_Protocol Protocol/*.h)
file(GLOB_RECURSE sources_Daemon Daemon/*.cpp Daemon/*.h)
file(GLOB_RECURSE sources_Socket Socket/*.cpp Socket/*.h)
file(GLOB_RECURSE sources_Buffered Buffered/*.cpp Buffered/*.h)
file(GLOB sources *.cpp *.h)
file(GLOB sources_localdir *.cpp *.h)

if ( USE_COREPCH )
  include_directories(${CMAKE_CURRENT_BINARY_DIR})
endif()

if ( USE_COREPCH AND MSVC )
  set(wardenserver_SRCS
    PrecompiledHeaders/wardenPCH.cpp
    PrecompiledHeaders/wardenPCH.h
  )
endif()

set(wardenserver_SRCS
  ${wardenserver_SRCS}
  ${sources_Protocol}
  ${sources_Daemon}
  ${sources_Socket}
  ${sources_Buffered}
  ${sources}
)

if ( WIN32 )
set(wardenserver_SRCS
    ${wardenserver_SRCS}
    ${sources_Debugging}
    wardenserver.rc
)
endif()

include_directories(
  ${CMAKE_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/dep/zlib
  ${CMAKE_SOURCE_DIR}/dep/mysqllite/include
  ${CMAKE_SOURCE_DIR}/src/server/shared
  ${CMAKE_SOURCE_DIR}/src/server/shared/Logging
  ${CMAKE_SOURCE_DIR}/src/server/shared/Packets
  ${CMAKE_SOURCE_DIR}/src/server/shared/Configuration
  ${CMAKE_SOURCE_DIR}/src/server/shared/Utilities
  ${CMAKE_SOURCE_DIR}/src/server/shared/Cryptography
  ${CMAKE_SOURCE_DIR}/src/server/shared/Database
  ${CMAKE_SOURCE_DIR}/src/server/shared/Database/Implementation
  ${CMAKE_SOURCE_DIR}/src/server/shared/Threading
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/Buffered
  ${CMAKE_CURRENT_SOURCE_DIR}/Protocol
  ${CMAKE_CURRENT_SOURCE_DIR}/Daemon
  ${CMAKE_CURRENT_SOURCE_DIR}/Socket
  ${ACE_INCLUDE_DIR}
  ${OPENSSL_INCLUDE_DIR}
)

set(wardenserver_LINK_FLAGS "")

add_executable(wardenserver
  ${wardenserver_SRCS}
)

add_dependencies(wardenserver revision.h)

if ( NOT WIN32 )
  add_definitions(-D_TRINITY_REALM_CONFIG='"${CONF_DIR}/wardenserver.conf"')
endif()

if ( UNIX )
  set(wardenserver_LINK_FLAGS "-pthread ${wardenserver_LINK_FLAGS}")
endif()

if ( CMAKE_SYSTEM_NAME MATCHES "Darwin" )
  set(wardenserver_LINK_FLAGS "-framework Carbon ${wardenserver_LINK_FLAGS}")
endif()

set_target_properties(wardenserver PROPERTIES LINK_FLAGS "${wardenserver_LINK_FLAGS}")

target_link_libraries(wardenserver
  shared
  ${ACE_LIBRARY}
  ${OPENSSL_LIBRARIES}
  ${OPENSSL_EXTRA_LIBRARIES}
  ${ZLIB_LIBRARIES}
  ${MYSQL_LIBRARY}
  )

if ( WIN32 )
  add_custom_command(TARGET wardenserver
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/wardenserver.conf.dist ${CMAKE_BINARY_DIR}/bin/$(ConfigurationName)/
  )
endif()

if ( UNIX )
  install(TARGETS wardenserver DESTINATION bin)
  install(FILES  wardenserver.conf.dist DESTINATION etc)
elseif( WIN32 )
  install(TARGETS wardenserver DESTINATION "${CMAKE_INSTALL_PREFIX}")
  install(FILES wardenserver.conf.dist DESTINATION "${CMAKE_INSTALL_PREFIX}")
endif()

# Generate precompiled header
if ( USE_COREPCH )
  if (CMAKE_COMPILER_IS_GNUCXX)
    add_precompiled_header(wardenserver ${CMAKE_CURRENT_SOURCE_DIR}/PrecompiledHeaders/wardenPCH.h)
  elseif(MSVC)
    add_native_precompiled_header(wardenserver ${CMAKE_CURRENT_SOURCE_DIR}/PrecompiledHeaders/wardenPCH)
  endif()
endif()
