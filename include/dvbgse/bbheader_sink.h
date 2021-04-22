/* -*- c++ -*- */
/* 
 * Copyright 2019 Ron Economos.
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

#ifndef INCLUDED_DVBGSE_BBHEADER_SINK_H
#define INCLUDED_DVBGSE_BBHEADER_SINK_H

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
    class DVBGSE_API bbheader_sink : virtual public gr::sync_block
    {
     public:
      typedef boost::shared_ptr<bbheader_sink> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of dvbgse::bbheader_sink.
       *
       * To avoid accidental use of raw pointers, dvbgse::bbheader_sink's
       * constructor is in a private implementation
       * class. dvbgse::bbheader_sink::make is the public interface for
       * creating new instances.
       */
      static sptr make(dvb_standard_t standard, dvb_framesize_t framesize, dvb_code_rate_t rate);
    };

  } // namespace dvbgse
} // namespace gr

#endif /* INCLUDED_DVBGSE_BBHEADER_SINK_H */

