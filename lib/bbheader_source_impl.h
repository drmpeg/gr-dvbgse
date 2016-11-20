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

#ifndef INCLUDED_DVBGSE_BBHEADER_SOURCE_IMPL_H
#define INCLUDED_DVBGSE_BBHEADER_SOURCE_IMPL_H

#include <dvbgse/bbheader_source.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/if_tun.h>

#define START_INDICATOR_SIZE 1
#define END_INDICATOR_SIZE 1
#define LABEL_TYPE_INDICATOR_SIZE 2
#define GSE_LENGTH_SIZE 12

#define HEADER_SIZE ((START_INDICATOR_SIZE + END_INDICATOR_SIZE + LABEL_TYPE_INDICATOR_SIZE + GSE_LENGTH_SIZE) / 8)
#define FRAG_ID_SIZE 1
#define TOTAL_LENGTH_SIZE 2
#define MAX_GSE_LENGTH 4096

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

    class bbheader_source_impl : public bbheader_source
    {
     private:
      unsigned int kbch;
      unsigned int count;
      unsigned char crc;
      unsigned int frame_size;
      int inband_type_b;
      int fec_blocks;
      int fec_block;
      int ts_rate;
      bool dvbs2x;
      bool alternate;
      bool nibble;
      FrameFormat m_format[1];
      unsigned char crc_tab[256];
      unsigned int crc32_table[256];
      pcap_t* descr;
      unsigned char *packet_ptr;
      bool packet_fragmented;
      int packet_length;
      const unsigned char *packet;
      unsigned char frag_id;
      int crc32_partial;
      void add_bbheader(unsigned char *, int, int, bool);
      void build_crc8_table(void);
      int add_crc8_bits(unsigned char *, int);
      void add_inband_type_b(unsigned char *, int);
      void crc32_init(void);
      int crc32_calc(unsigned char *, int);
      int crc32_calc_partial(unsigned char *, int, int);
      int crc32_calc_final(unsigned char *, int, int);
      int checksum(unsigned short *, int);
      inline void ping_reply(void);

     public:
      bbheader_source_impl(dvb_standard_t standard, dvb_framesize_t framesize, dvb_code_rate_t rate, dvbs2_rolloff_factor_t rolloff, dvbt2_inband_t inband, int fecblocks, int tsrate, char *mac_address);
      ~bbheader_source_impl();

      int work(int noutput_items,
         gr_vector_const_void_star &input_items,
         gr_vector_void_star &output_items);
    };

  } // namespace dvbgse
} // namespace gr

#endif /* INCLUDED_DVBGSE_BBHEADER_SOURCE_IMPL_H */

