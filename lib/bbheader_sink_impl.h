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

#ifndef INCLUDED_DVBGSE_BBHEADER_SINK_IMPL_H
#define INCLUDED_DVBGSE_BBHEADER_SINK_IMPL_H

#include <dvbgse/bbheader_sink.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>

typedef struct{
    int ts_gs;
    int sis_mis;
    int ccm_acm;
    int issyi;
    int npd;
    int ro;
    int isi;
    int upl;
    int dfl;
    int sync;
    int syncd;
}BBHeader;

typedef struct{
   BBHeader bb_header;
}FrameFormat;

namespace gr {
  namespace dvbgse {

    class bbheader_sink_impl : public bbheader_sink
    {
     private:
      unsigned int kbch;
      unsigned int dvb_standard;
      unsigned int synched;
      unsigned int index;
      int crc32_partial;
      FrameFormat m_format[1];
      int fd;
      unsigned char tap_mac_address[6];
      unsigned int crc32_table[256];
      unsigned char packet[4096];
      unsigned char *packet_alloc[256];
      unsigned char *packet_ptr[256];
      unsigned int packet_ttl[256];
      unsigned int check_crc8_bits(const unsigned char *, int);
      void crc32_init(void);
      int crc32_calc(unsigned char *, int, int);

     public:
      bbheader_sink_impl(dvb_standard_t standard, dvb_framesize_t framesize, dvb_code_rate_t rate, char *mac_address);
      ~bbheader_sink_impl();

      // Where all the action really happens
      int work(int noutput_items,
         gr_vector_const_void_star &input_items,
         gr_vector_void_star &output_items);
    };

  } // namespace dvbgse
} // namespace gr

#endif /* INCLUDED_DVBGSE_BBHEADER_SINK_IMPL_H */

