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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "bbheader_source_impl.h"

#define DEFAULT_IF "tap0"
#define FILTER "ether src "
#undef DEBUG

namespace gr {
  namespace dvbgse {

    bbheader_source::sptr
    bbheader_source::make(dvb_standard_t standard, dvb_framesize_t framesize, dvb_code_rate_t rate, dvbs2_rolloff_factor_t rolloff, dvbt2_inband_t inband, int fecblocks, int tsrate, char *mac_address, dvbt2_ping_reply_t ping_reply, dvbt2_ipaddr_spoof_t ipaddr_spoof, char *src_address, char *dst_address)
    {
      return gnuradio::get_initial_sptr
        (new bbheader_source_impl(standard, framesize, rate, rolloff, inband, fecblocks, tsrate, mac_address, ping_reply, ipaddr_spoof, src_address, dst_address));
    }

    /*
     * The private constructor
     */
    bbheader_source_impl::bbheader_source_impl(dvb_standard_t standard, dvb_framesize_t framesize, dvb_code_rate_t rate, dvbs2_rolloff_factor_t rolloff, dvbt2_inband_t inband, int fecblocks, int tsrate, char *mac_address, dvbt2_ping_reply_t ping_reply, dvbt2_ipaddr_spoof_t ipaddr_spoof, char *src_address, char *dst_address)
      : gr::sync_block("bbheader_source",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(1, 1, sizeof(unsigned char)))
    {
      char errbuf[PCAP_ERRBUF_SIZE];
      char dev[IFNAMSIZ];
      struct bpf_program fp;
      bpf_u_int32 netp = 0;
      char filter[50];
      struct ifreq ifr;
      int err;

      count = 0;
      crc = 0x0;
      dvbs2x = FALSE;
      alternate = TRUE;
      nibble = TRUE;
      frame_size = framesize;
      ping_reply_mode = ping_reply;
      ipaddr_spoof_mode = ipaddr_spoof;
      inet_pton(AF_INET, src_address, &src_addr);
      inet_pton(AF_INET, dst_address, &dst_addr);
      packet_fragmented = FALSE;
      last_packet_valid = FALSE;
      frag_id = 1;
      descr = NULL;
      fd = 0;
      BBHeader *f = &m_format[0].bb_header;
      if (framesize == FECFRAME_NORMAL) {
        switch (rate) {
          case C1_4:
            kbch = 16008;
            break;
          case C1_3:
            kbch = 21408;
            break;
          case C2_5:
            kbch = 25728;
            break;
          case C1_2:
            kbch = 32208;
            break;
          case C3_5:
            kbch = 38688;
            break;
          case C2_3:
            kbch = 43040;
            break;
          case C3_4:
            kbch = 48408;
            break;
          case C4_5:
            kbch = 51648;
            break;
          case C5_6:
            kbch = 53840;
            break;
          case C8_9:
            kbch = 57472;
            break;
          case C9_10:
            kbch = 58192;
            break;
          case C2_9_VLSNR:
            kbch = 14208;
            break;
          case C13_45:
            kbch = 18528;
            break;
          case C9_20:
            kbch = 28968;
            break;
          case C90_180:
            kbch = 32208;
            break;
          case C96_180:
            kbch = 34368;
            break;
          case C11_20:
            kbch = 35448;
            break;
          case C100_180:
            kbch = 35808;
            break;
          case C104_180:
            kbch = 37248;
            break;
          case C26_45:
            kbch = 37248;
            break;
          case C18_30:
            kbch = 38688;
            break;
          case C28_45:
            kbch = 40128;
            break;
          case C23_36:
            kbch = 41208;
            break;
          case C116_180:
            kbch = 41568;
            break;
          case C20_30:
            kbch = 43008;
            break;
          case C124_180:
            kbch = 44448;
            break;
          case C25_36:
            kbch = 44808;
            break;
          case C128_180:
            kbch = 45888;
            break;
          case C13_18:
            kbch = 46608;
            break;
          case C132_180:
            kbch = 47328;
            break;
          case C22_30:
            kbch = 47328;
            break;
          case C135_180:
            kbch = 48408;
            break;
          case C140_180:
            kbch = 50208;
            break;
          case C7_9:
            kbch = 50208;
            break;
          case C154_180:
            kbch = 55248;
            break;
          default:
            kbch = 0;
            break;
        }
      }
      else if (framesize == FECFRAME_SHORT) {
        switch (rate) {
          case C1_4:
            kbch = 3072;
            break;
          case C1_3:
            kbch = 5232;
            break;
          case C2_5:
            kbch = 6312;
            break;
          case C1_2:
            kbch = 7032;
            break;
          case C3_5:
            kbch = 9552;
            break;
          case C2_3:
            kbch = 10632;
            break;
          case C3_4:
            kbch = 11712;
            break;
          case C4_5:
            kbch = 12432;
            break;
          case C5_6:
            kbch = 13152;
            break;
          case C8_9:
            kbch = 14232;
            break;
          case C11_45:
            kbch = 3792;
            break;
          case C4_15:
            kbch = 4152;
            break;
          case C14_45:
            kbch = 4872;
            break;
          case C7_15:
            kbch = 7392;
            break;
          case C8_15:
            kbch = 8472;
            break;
          case C26_45:
            kbch = 9192;
            break;
          case C32_45:
            kbch = 11352;
            break;
          case C1_5_VLSNR_SF2:
            kbch = 2512;
            break;
          case C11_45_VLSNR_SF2:
            kbch = 3792;
            break;
          case C1_5_VLSNR:
            kbch = 3072;
            break;
          case C4_15_VLSNR:
            kbch = 4152;
            break;
          case C1_3_VLSNR:
            kbch = 5232;
            break;
          default:
            kbch = 0;
            break;
        }
      }
      else {
        switch (rate) {
          case C1_5_MEDIUM:
            kbch = 5660;
            break;
          case C11_45_MEDIUM:
            kbch = 7740;
            break;
          case C1_3_MEDIUM:
            kbch = 10620;
            break;
          default:
            kbch = 0;
            break;
        }
      }

      if (standard == STANDARD_DVBS2) {
        inband_type_b = FALSE;
      }
      f->ts_gs   = TS_GS_GENERIC_CONTINUOUS;
      f->sis_mis = SIS_MIS_SINGLE;
      f->ccm_acm = CCM;
      f->issyi   = ISSYI_NOT_ACTIVE;
      f->npd     = NPD_NOT_ACTIVE;
      f->upl  = 0;
      f->dfl  = kbch - 80;
      f->sync = 0;
      if (standard == STANDARD_DVBS2) {
        if (rolloff & 0x4) {
          dvbs2x = TRUE;
        }
        f->ro = rolloff & 0x3;
      }
      else {
        f->ro = 0;
      }

      build_crc8_table();
      crc32_init();
      inband_type_b = inband;
      fec_blocks = fecblocks;
      fec_block = 0;
      ts_rate = tsrate;

      if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
        throw std::runtime_error("Error calling open()\n");
      }
      memset(&ifr, 0, sizeof(ifr));
      ifr.ifr_flags = IFF_TAP;
      strncpy(ifr.ifr_name, DEFAULT_IF, IFNAMSIZ);

      if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) == -1) {
        close(fd);
        throw std::runtime_error("Error calling ioctl()\n");
      }

      strcpy(dev, DEFAULT_IF);
      descr = pcap_create(dev, errbuf);
      if (descr == NULL) {
        std::stringstream s;
        s << "Error calling pcap_create(): " << errbuf << std::endl;
        throw std::runtime_error(s.str());
      }
      if (pcap_set_promisc(descr, 0) != 0) {
        pcap_close(descr);
        throw std::runtime_error("Error calling pcap_set_promisc()\n");
      }
      if (pcap_set_timeout(descr, -1) != 0) {
        pcap_close(descr);
        throw std::runtime_error("Error calling pcap_set_timeout()\n");
      }
      if (pcap_set_snaplen(descr, 65536) != 0) {
        pcap_close(descr);
        throw std::runtime_error("Error calling pcap_set_snaplen()\n");
      }
      if (pcap_set_buffer_size(descr, 1024 * 1024 * 16) != 0) {
        pcap_close(descr);
        throw std::runtime_error("Error calling pcap_set_buffer_size()\n");
      }
      if (pcap_activate(descr) != 0) {
        pcap_close(descr);
        throw std::runtime_error("Error calling pcap_activate()\n");
      }
      strcpy(filter, FILTER);
      strcat(filter, mac_address);
      if (pcap_compile(descr, &fp, filter, 0, netp) == -1) {
        pcap_close(descr);
        throw std::runtime_error("Error calling pcap_compile()\n");
      }
      if (pcap_setfilter(descr, &fp) == -1) {
        pcap_close(descr);
        throw std::runtime_error("Error calling pcap_setfilter()\n");
      }

      set_output_multiple(kbch);
    }

    /*
     * Our virtual destructor.
     */
    bbheader_source_impl::~bbheader_source_impl()
    {
      if (fd) {
        close(fd);
      }
      if (descr) {
        pcap_close(descr);
      }
    }

#define CRC_POLY 0xAB
// Reversed
#define CRC_POLYR 0xD5

    void
    bbheader_source_impl::build_crc8_table(void)
    {
      int r, crc;

      for (int i = 0; i < 256; i++) {
        r = i;
        crc = 0;
        for (int j = 7; j >= 0; j--) {
          if ((r & (1 << j) ? 1 : 0) ^ ((crc & 0x80) ? 1 : 0)) {
            crc = (crc << 1) ^ CRC_POLYR;
          }
          else {
            crc <<= 1;
          }
        }
        crc_tab[i] = crc;
      }
    }

    /*
     * MSB is sent first
     *
     * The polynomial has been reversed
     */
    int
    bbheader_source_impl::add_crc8_bits(unsigned char *in, int length)
    {
      int crc = 0;
      int b;
      int i = 0;

      for (int n = 0; n < length; n++) {
        b = in[i++] ^ (crc & 0x01);
        crc >>= 1;
        if (b) {
          crc ^= CRC_POLY;
        }
      }

      for (int n = 0; n < 8; n++) {
        in[i++] = (crc & (1 << n)) ? 1 : 0;
      }
      return 8;// Length of CRC
    }

    void
    bbheader_source_impl::add_bbheader(unsigned char *out, int count, int padding, bool nibble)
    {
      int temp, m_frame_offset_bits;
      unsigned char *m_frame = out;
      BBHeader *h = &m_format[0].bb_header;

      m_frame[0] = h->ts_gs >> 1;
      m_frame[1] = h->ts_gs & 1;
      m_frame[2] = h->sis_mis;
      m_frame[3] = h->ccm_acm;
      m_frame[4] = h->issyi & 1;
      m_frame[5] = h->npd & 1;
      if (dvbs2x == TRUE) {
        if (alternate == TRUE) {
          alternate = FALSE;
          m_frame[6] = 1;
          m_frame[7] = 1;
        }
        else {
          alternate = TRUE;
          m_frame[6] = h->ro >> 1;
          m_frame[7] = h->ro & 1;
        }
      }
      else {
        m_frame[6] = h->ro >> 1;
        m_frame[7] = h->ro & 1;
      }
      m_frame_offset_bits = 8;
      if (h->sis_mis == SIS_MIS_MULTIPLE) {
        temp = h->isi;
        for (int n = 7; n >= 0; n--) {
          m_frame[m_frame_offset_bits++] = temp & (1 << n) ? 1 : 0;
        }
      }
      else {
        for (int n = 7; n >= 0; n--) {
          m_frame[m_frame_offset_bits++] = 0;
        }
      }
      temp = h->upl;
      for (int n = 15; n >= 0; n--) {
        m_frame[m_frame_offset_bits++] = temp & (1 << n) ? 1 : 0;
      }
      temp = h->dfl - padding;
      for (int n = 15; n >= 0; n--) {
        m_frame[m_frame_offset_bits++] = temp & (1 << n) ? 1 : 0;
      }
      temp = h->sync;
      for (int n = 7; n >= 0; n--) {
        m_frame[m_frame_offset_bits++] = temp & (1 << n) ? 1 : 0;
      }
      // Calculate syncd, this should point to the MSB of the CRC
      temp = count;
      if (temp == 0) {
        temp = count;
      }
      else {
        temp = (188 - count) * 8;
      }
      if (nibble == FALSE) {
        temp += 4;
      }
      for (int n = 15; n >= 0; n--) {
        m_frame[m_frame_offset_bits++] = temp & (1 << n) ? 1 : 0;
      }
      // Add CRC to BB header, at end
      int len = BB_HEADER_LENGTH_BITS;
      m_frame_offset_bits += add_crc8_bits(m_frame, len);
    }

    void
    bbheader_source_impl::add_inband_type_b(unsigned char *out, int ts_rate)
    {
      int temp, m_frame_offset_bits;
      unsigned char *m_frame = out;

      m_frame[0] = 0;
      m_frame[1] = 1;
      m_frame_offset_bits = 2;
      for (int n = 30; n >= 0; n--) {
        m_frame[m_frame_offset_bits++] = 0;
      }
      for (int n = 21; n >= 0; n--) {
        m_frame[m_frame_offset_bits++] = 0;
      }
      for (int n = 1; n >= 0; n--) {
        m_frame[m_frame_offset_bits++] = 0;
      }
      for (int n = 9; n >= 0; n--) {
        m_frame[m_frame_offset_bits++] = 0;
      }
      temp = ts_rate;
      for (int n = 26; n >= 0; n--) {
        m_frame[m_frame_offset_bits++] = temp & (1 << n) ? 1 : 0;
      }
      for (int n = 9; n >= 0; n--) {
        m_frame[m_frame_offset_bits++] = 0;
      }
    }

    int
    bbheader_source_impl::crc32_calc(unsigned char *buf, int size, int crc)
    {
      for (int i = 0; i < size; i++) {
        crc = (crc << 8) ^ crc32_table[((crc >> 24) ^ buf[i]) & 0xff];
      }
      return (crc);
    }

    void
    bbheader_source_impl::crc32_init(void)
    {
      unsigned int i, j, k;

      for (i = 0; i < 256; i++) {
        k = 0;
        for (j = (i << 24) | 0x800000; j != 0x80000000; j <<= 1) {
          k = (k << 1) ^ (((k ^ j) & 0x80000000) ? 0x04c11db7 : 0);
        }
        crc32_table[i] = k;
      }
    }

    int
    bbheader_source_impl::checksum(unsigned short *addr, int count, int sum)
    {
      while (count > 1) {
        sum += *addr++;
        count -= 2;
      }
      if (count > 0) {
        sum += *(unsigned char *)addr;
      }
      sum = (sum & 0xffff) + (sum >> 16);
      sum += (sum >> 16);
      return (~sum);
    }

    inline void
    bbheader_source_impl::ping_reply(void)
    {
      unsigned short *csum_ptr;
      unsigned short header_length, total_length, type_code, fragment_offset;
      int csum;
      struct ip *ip_ptr;
      unsigned char *saddr_ptr, *daddr_ptr;
      unsigned char addr[sizeof(in_addr)];

      /* jam ping reply and calculate new checksum */
      ip_ptr = (struct ip*)(packet + sizeof(struct ether_header));
      csum_ptr = (unsigned short *)ip_ptr;
      header_length = (*csum_ptr & 0xf) * 4;
      csum_ptr = &ip_ptr->ip_len;
      total_length = ((*csum_ptr & 0xff) << 8) | ((*csum_ptr & 0xff00) >> 8);
      csum_ptr = &ip_ptr->ip_off;
      fragment_offset = ((*csum_ptr & 0xff) << 8) | ((*csum_ptr & 0xff00) >> 8);

      csum_ptr = (unsigned short *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
      type_code = *csum_ptr;
      type_code = (type_code & 0xff00) | 0x0;
      if ((fragment_offset & 0x1fff) == 0) {
        *csum_ptr++ = type_code;
        *csum_ptr = 0x0000;
        csum_ptr = (unsigned short *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        csum = checksum(csum_ptr, total_length - header_length, 0);
        csum_ptr++;
        *csum_ptr = csum;
      }

      /* swap IP adresses */
      saddr_ptr = (unsigned char *)&ip_ptr->ip_src;
      daddr_ptr = (unsigned char *)&ip_ptr->ip_dst;
      for (unsigned int i = 0; i < sizeof(in_addr); i++) {
        addr[i] = *daddr_ptr++;
      }
      daddr_ptr = (unsigned char *)&ip_ptr->ip_dst;
      for (unsigned int i = 0; i < sizeof(in_addr); i++) {
        *daddr_ptr++ = *saddr_ptr++;
      }
      saddr_ptr = (unsigned char *)&ip_ptr->ip_src;
      for (unsigned int i = 0; i < sizeof(in_addr); i++) {
        *saddr_ptr++ = addr[i];
      }
    }

    inline void
    bbheader_source_impl::ipaddr_spoof(void)
    {
      unsigned short *csum_ptr;
      unsigned short header_length, fragment_offset;
      int csum;
      struct ip *ip_ptr;
      unsigned char *saddr_ptr, *daddr_ptr;

      ip_ptr = (struct ip*)(packet + sizeof(struct ether_header));

      saddr_ptr = (unsigned char *)&ip_ptr->ip_src;
      for (unsigned int i = 0; i < sizeof(in_addr); i++) {
        *saddr_ptr++ = src_addr[i];
      }

      daddr_ptr = (unsigned char *)&ip_ptr->ip_dst;
      for (unsigned int i = 0; i < sizeof(in_addr); i++) {
        *daddr_ptr++ = dst_addr[i];
      }

      csum_ptr = (unsigned short *)ip_ptr;
      header_length = (*csum_ptr & 0xf) * 4;
      csum_ptr = &ip_ptr->ip_off;
      fragment_offset = ((*csum_ptr & 0xff) << 8) | ((*csum_ptr & 0xff00) >> 8);

      if ((fragment_offset & 0x1fff) == 0) {
        csum_ptr = &ip_ptr->ip_sum;
        *csum_ptr = 0x0000;
        csum_ptr = (unsigned short *)ip_ptr;
        csum = checksum(csum_ptr, header_length, 0);
        csum_ptr = &ip_ptr->ip_sum;
        *csum_ptr = csum;

        csum_ptr = (unsigned short *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + 6);
        *csum_ptr = 0x0000;
      }
    }

    inline void
    bbheader_source_impl::dump_packet(unsigned char *packet)
    {
#ifdef DEBUG
      unsigned char pack;

      printf("\n");
      for (unsigned int i = 0; i < kbch / 8; i++) {
        if (i % 16 == 0) {
          printf("\n");
        }
        pack = 0;
        for (int n = 0; n < 8; n++) {
          pack |= *packet++ << (7 - n);
        }
        printf("0x%02x:", pack);
      }
      printf("\n");
#endif
    }

    int
    bbheader_source_impl::work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items)
    {
      unsigned char *out = (unsigned char *) output_items[0];
      unsigned int offset = 0;
      unsigned int padding, bits, first_offset;
      struct ether_header *eptr;
      unsigned char *ptr;
      unsigned char total_length[2];
      int length, crc32;
      unsigned int ether_addr_len;
      bool maxsize;
      bool gse = FALSE;

      for (int i = 0; i < noutput_items; i += kbch) {
        if (frame_size != FECFRAME_MEDIUM) {
          if (fec_block == 0 && inband_type_b == TRUE) {
            padding = 104;
          }
          else {
            padding = 0;
          }
        }
        else {
          if (fec_block == 0 && inband_type_b == TRUE) {
            padding = 108;
          }
          else {
            padding = 4;
          }
        }
        ether_addr_len = ETHER_ADDR_LEN;
        add_bbheader(&out[offset], count, padding, TRUE);
        first_offset = offset;
        offset = offset + 80;
        while (1) {
          if (packet_fragmented == FALSE) {
            if (last_packet_valid == FALSE) {
              packet = pcap_next(descr, &hdr);
            }
            if (packet != NULL) {
              last_packet_valid = FALSE;
              if (((hdr.len - sizeof(struct ether_header) + HEADER_SIZE + ETHER_TYPE_LEN + ether_addr_len) <= ((kbch - (offset - first_offset) - padding) / 8)) && ((hdr.len - sizeof(struct ether_header) + ETHER_TYPE_LEN + ether_addr_len) < 4096)) {
                /* PDU start, no fragmentation */
                gse = TRUE;
                out[offset++] = 1;    /* Start_Indicator = 1 */
                out[offset++] = 1;    /* End_Indicator = 1 */
                if (ether_addr_len) {
                  bits = 0x0;           /* Label_Type_Indicator = 6 byte */
                }
                else {
                  bits = 0x3;           /* Label_Type_Indicator = re-use */
                }
                for (int n = 1; n >= 0; n--) {
                  out[offset++] = bits & (1 << n) ? 1 : 0;
                }
                bits = hdr.len - sizeof(struct ether_header) + ETHER_TYPE_LEN + ether_addr_len;    /* GSE_Length */
                for (int n = 11; n >= 0; n--) {
                  out[offset++] = bits & (1 << n) ? 1 : 0;
                }

                if (ping_reply_mode) {
                  ping_reply();
                }
                if (ipaddr_spoof_mode) {
                  ipaddr_spoof();
                }

                eptr = (struct ether_header *)packet;
                /* Protocol_Type */
                ptr = (unsigned char *)&eptr->ether_type;
                for (int j = 0; j < ETHER_TYPE_LEN; j++) {
                  bits = *ptr++;
                  for (int n = 7; n >= 0; n--) {
                    out[offset++] = bits & (1 << n) ? 1 : 0;
                  }
                }
                /* 6_Byte_Label */
                ptr = eptr->ether_dhost;
                for (unsigned int j = 0; j < ether_addr_len; j++) {
                  bits = *ptr++;
                  for (int n = 7; n >= 0; n--) {
                    out[offset++] = bits & (1 << n) ? 1 : 0;
                  }
                }
                ether_addr_len = ETHER_ADDR_LEN;    /* disable label re-use for now */
                /* GSE_data_byte */
                ptr = (unsigned char *)(packet + sizeof(struct ether_header));
                for (unsigned int j = 0; j < hdr.len - sizeof(struct ether_header); j++) {
                  bits = *ptr++;
                  for (int n = 7; n >= 0; n--) {
                    out[offset++] = bits & (1 << n) ? 1 : 0;
                  }
                }
                if (offset == (i + kbch) - padding) {
                  break;
                }
                continue;
              }
              else {
                /* PDU start, fragmented */
                if (((kbch - (offset - first_offset) - padding) / 8) >= (HEADER_SIZE + FRAG_ID_SIZE + TOTAL_LENGTH_SIZE + ETHER_TYPE_LEN + ether_addr_len)) {
                  gse = TRUE;
                  out[offset++] = 1;    /* Start_Indicator = 1 */
                  out[offset++] = 0;    /* End_Indicator = 0 */
                  if (ether_addr_len) {
                    bits = 0x0;           /* Label_Type_Indicator = 6 byte */
                  }
                  else {
                    bits = 0x3;           /* Label_Type_Indicator = re-use */
                  }
                  for (int n = 1; n >= 0; n--) {
                    out[offset++] = bits & (1 << n) ? 1 : 0;
                  }
                  bits = (kbch - ((offset + GSE_LENGTH_SIZE) - first_offset) - padding) / 8;    /* GSE_Length */
                  if (bits >= MAX_GSE_LENGTH) {
                    bits = MAX_GSE_LENGTH - 1;
                    maxsize = TRUE;
                  }
                  else {
                    maxsize = FALSE;
                  }
                  for (int n = 11; n >= 0; n--) {
                    out[offset++] = bits & (1 << n) ? 1 : 0;
                  }
                  bits = frag_id;    /* Frag_ID */
                  for (int n = 7; n >= 0; n--) {
                    out[offset++] = bits & (1 << n) ? 1 : 0;
                  }
                  bits = hdr.len - sizeof(struct ether_header) + ETHER_TYPE_LEN + ether_addr_len;    /* Total_Length */
                  total_length[0] = (bits >> 8) & 0xff;
                  total_length[1] = bits & 0xff;
                  crc32_partial = crc32_calc(&total_length[0], 2, 0xffffffff);
                  for (int n = 15; n >= 0; n--) {
                    out[offset++] = bits & (1 << n) ? 1 : 0;
                  }

                  if (ping_reply_mode) {
                    ping_reply();
                  }
                  if (ipaddr_spoof_mode) {
                    ipaddr_spoof();
                  }

                  eptr = (struct ether_header *)packet;
                  /* Protocol_Type */
                  ptr = (unsigned char *)&eptr->ether_type;
                  crc32_partial = crc32_calc(ptr, ETHER_TYPE_LEN, crc32_partial);
                  for (int j = 0; j < ETHER_TYPE_LEN; j++) {
                    bits = *ptr++;
                    for (int n = 7; n >= 0; n--) {
                      out[offset++] = bits & (1 << n) ? 1 : 0;
                    }
                  }
                  /* 6_Byte_Label */
                  ptr = eptr->ether_dhost;
                  crc32_partial = crc32_calc(ptr, ether_addr_len, crc32_partial);
                  for (unsigned int j = 0; j < ether_addr_len; j++) {
                    bits = *ptr++;
                    for (int n = 7; n >= 0; n--) {
                      out[offset++] = bits & (1 << n) ? 1 : 0;
                    }
                  }
                  ether_addr_len = ETHER_ADDR_LEN;    /* disable label re-use for now */
                  /* GSE_data_byte */
                  ptr = (unsigned char *)(packet + sizeof(struct ether_header));
                  if (maxsize == TRUE) {
                    length = MAX_GSE_LENGTH - 1 - FRAG_ID_SIZE - TOTAL_LENGTH_SIZE - ETHER_TYPE_LEN - ether_addr_len;
                  }
                  else {
                    length = (kbch - (offset - first_offset) - padding) / 8;
                  }
                  crc32_partial = crc32_calc(ptr, length, crc32_partial);
                  packet_length = hdr.len - sizeof(struct ether_header) - length;
                  for (int j = 0; j < length; j++) {
                    bits = *ptr++;
                    for (int n = 7; n >= 0; n--) {
                      out[offset++] = bits & (1 << n) ? 1 : 0;
                    }
                  }
                  packet_ptr = ptr;
                  packet_fragmented = TRUE;
                  if (offset == (i + kbch) - padding) {
                    break;
                  }
                }
                else {
                  last_packet_valid = TRUE;
                }
              }
            }
          }
          if (packet_fragmented == TRUE) {
            if (((packet_length + HEADER_SIZE + FRAG_ID_SIZE + sizeof(crc32)) <= ((kbch - (offset - first_offset) - padding) / 8)) && ((packet_length + HEADER_SIZE + FRAG_ID_SIZE + sizeof(crc32)) < 4096)) {
              /* PDU end */
              gse = TRUE;
              out[offset++] = 0;    /* Start_Indicator = 0 */
              out[offset++] = 1;    /* End_Indicator = 1 */
              bits = 0x3;           /* Label_Type_Indicator = re-use */
              for (int n = 1; n >= 0; n--) {
                out[offset++] = bits & (1 << n) ? 1 : 0;
              }
              if (packet_length != 0) {
                bits = FRAG_ID_SIZE + packet_length + sizeof(crc32);    /* GSE_Length */
              }
              else {
                bits = FRAG_ID_SIZE + sizeof(crc32);    /* GSE_Length */
              }
              for (int n = 11; n >= 0; n--) {
                out[offset++] = bits & (1 << n) ? 1 : 0;
              }
              bits = frag_id;    /* Frag_ID */
              frag_id++;
              for (int n = 7; n >= 0; n--) {
                out[offset++] = bits & (1 << n) ? 1 : 0;
              }
              /* GSE_data_byte */
              ptr = packet_ptr;
              length = packet_length;
              if (length != 0) {
                crc32 = crc32_calc(ptr, length, crc32_partial);
                for (int j = 0; j < length; j++) {
                  bits = *ptr++;
                  for (int n = 7; n >= 0; n--) {
                    out[offset++] = bits & (1 << n) ? 1 : 0;
                  }
                }
                bits = crc32;
                for (int n = 31; n >= 0; n--) {
                  out[offset++] = bits & (1 << n) ? 1 : 0;
                }
              }
              else {
                bits = crc32_partial;
                for (int n = 31; n >= 0; n--) {
                  out[offset++] = bits & (1 << n) ? 1 : 0;
                }
              }
              packet_fragmented = FALSE;
              if (offset == (i + kbch) - padding) {
                break;
              }
            }
            else {
              /* PDU continuation */
              gse = TRUE;
              length = (kbch - (offset - first_offset) - padding) / 8;
              if (packet_length < (length - (HEADER_SIZE + FRAG_ID_SIZE))) {
                padding = ((length - (HEADER_SIZE + FRAG_ID_SIZE)) - packet_length) * 8;
                add_bbheader(&out[first_offset], count, padding, TRUE);
              }
              out[offset++] = 0;    /* Start_Indicator = 0 */
              out[offset++] = 0;    /* End_Indicator = 0 */
              bits = 0x3;           /* Label_Type_Indicator = re-use */
              for (int n = 1; n >= 0; n--) {
                out[offset++] = bits & (1 << n) ? 1 : 0;
              }
              bits = (kbch - (offset + GSE_LENGTH_SIZE - first_offset) - padding) / 8;    /* GSE_Length */
              if (bits >= MAX_GSE_LENGTH) {
                bits = MAX_GSE_LENGTH - 1;
                maxsize = TRUE;
              }
              else {
                maxsize = FALSE;
              }
              for (int n = 11; n >= 0; n--) {
                out[offset++] = bits & (1 << n) ? 1 : 0;
              }
              bits = frag_id;    /* Frag_ID */
              for (int n = 7; n >= 0; n--) {
                out[offset++] = bits & (1 << n) ? 1 : 0;
              }
              /* GSE_data_byte */
              ptr = packet_ptr;
              if (maxsize == TRUE) {
                length = MAX_GSE_LENGTH - 1 - FRAG_ID_SIZE;
              }
              else {
                length = (kbch - (offset - first_offset) - padding) / 8;
              }
              packet_ptr += length;
              packet_length -= length;
              crc32_partial = crc32_calc(ptr, length, crc32_partial);
              for (int j = 0; j < length; j++) {
                bits = *ptr++;
                for (int n = 7; n >= 0; n--) {
                  out[offset++] = bits & (1 << n) ? 1 : 0;
                }
              }
              if (offset == (i + kbch) - padding) {
                break;
              }
            }
          }
          else {
            padding = kbch - (offset - first_offset);
            add_bbheader(&out[first_offset], count, padding, TRUE);
            if (offset == (i + kbch) - padding) {
              break;
            }
          }
        }
        if (fec_block == 0 && inband_type_b == TRUE) {
          add_inband_type_b(&out[offset], ts_rate);
          offset = offset + 104;
          padding -= 104;
        }
        if (inband_type_b == TRUE) {
          fec_block = (fec_block + 1) % fec_blocks;
        }
        if (padding != 0) {
          memset(&out[offset], 0, padding);
          offset += padding;
        }
        if (gse == TRUE) {
          gse = FALSE;
          dump_packet(&out[first_offset]);
        }
        else {
          add_bbheader(&out[first_offset], count, padding - 1, TRUE);
        }
      }

      // Tell runtime system how many output items we produced.
      return noutput_items;
    }

  } /* namespace dvbgse */
} /* namespace gr */

