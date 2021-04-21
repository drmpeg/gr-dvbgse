/* -*- c++ -*- */
/* 
 * Copyright 2016 Ron Economos.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_DVBGSE_BBHEADER_SOURCE_H
#define INCLUDED_DVBGSE_BBHEADER_SOURCE_H

#include <dvbgse/api.h>
#include <dvbgse/dvb_config.h>
#include <gnuradio/sync_block.h>

namespace gr {
  namespace dvbgse {

    /*!
     * \brief <+description of block+>
     * \ingroup dvbgse
     *
     */
    class DVBGSE_API bbheader_source : virtual public gr::sync_block
    {
     public:
      typedef boost::shared_ptr<bbheader_source> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of dvbgse::bbheader_source.
       *
       * To avoid accidental use of raw pointers, dvbgse::bbheader_source's
       * constructor is in a private implementation
       * class. dvbgse::bbheader_source::make is the public interface for
       * creating new instances.
       */
      static sptr make(dvb_standard_t standard, dvb_framesize_t framesize, dvb_code_rate_t rate, dvbs2_rolloff_factor_t rolloff, dvbt2_inband_t inband, int fecblocks, int tsrate, dvbt2_ping_reply_t ping_reply, dvbt2_ipaddr_spoof_t ipaddr_spoof, char *src_address, char *dst_address);
    };

  } // namespace dvbgse
} // namespace gr

#endif /* INCLUDED_DVBGSE_BBHEADER_SOURCE_H */

