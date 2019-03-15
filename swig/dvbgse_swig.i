/* -*- c++ -*- */

#define DVBGSE_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "dvbgse_swig_doc.i"

%{
#include "dvbgse/dvb_config.h"
#include "dvbgse/bbheader_source.h"
#include "dvbgse/bbheader_sink.h"
%}


%include "dvbgse/dvb_config.h"
%include "dvbgse/bbheader_source.h"
GR_SWIG_BLOCK_MAGIC2(dvbgse, bbheader_source);
%include "dvbgse/bbheader_sink.h"
GR_SWIG_BLOCK_MAGIC2(dvbgse, bbheader_sink);
