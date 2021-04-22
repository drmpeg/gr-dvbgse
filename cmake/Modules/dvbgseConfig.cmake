if(NOT PKG_CONFIG_FOUND)
    INCLUDE(FindPkgConfig)
endif()
PKG_CHECK_MODULES(PC_DVBGSE dvbgse)

FIND_PATH(
    DVBGSE_INCLUDE_DIRS
    NAMES dvbgse/api.h
    HINTS $ENV{DVBGSE_DIR}/include
        ${PC_DVBGSE_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    DVBGSE_LIBRARIES
    NAMES gnuradio-dvbgse
    HINTS $ENV{DVBGSE_DIR}/lib
        ${PC_DVBGSE_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/dvbgseTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(DVBGSE DEFAULT_MSG DVBGSE_LIBRARIES DVBGSE_INCLUDE_DIRS)
MARK_AS_ADVANCED(DVBGSE_LIBRARIES DVBGSE_INCLUDE_DIRS)
