# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT dvbgse_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT dvbgse_sources)

########################################################################
# Check for pygccxml
########################################################################
GR_PYTHON_CHECK_MODULE_RAW(
    "pygccxml"
    "import pygccxml"
    PYGCCXML_FOUND
    )

include(GrPybind)

########################################################################
# Python Bindings
########################################################################

list(APPEND dvbgse_python_files
    bbheader_source_python.cc
    bbheader_sink_python.cc
    dvb_config_python.cc python_bindings.cc)

GR_PYBIND_MAKE_OOT(dvbgse 
   ../..
   gr::dvbgse
   "${dvbgse_python_files}")

install(TARGETS dvbgse_python DESTINATION ${GR_PYTHON_DIR}/dvbgse COMPONENT pythonapi)
