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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "bbheader_sink_impl.h"
#include <stdio.h>

#define DEFAULT_IF "tap1"

namespace gr {
  namespace dvbgse {

    bbheader_sink::sptr
    bbheader_sink::make(dvb_standard_t standard, dvb_framesize_t framesize, dvb_code_rate_t rate)
    {
      return gnuradio::get_initial_sptr
        (new bbheader_sink_impl(standard, framesize, rate));
    }

    /*
     * The private constructor
     */
    bbheader_sink_impl::bbheader_sink_impl(dvb_standard_t standard, dvb_framesize_t framesize, dvb_code_rate_t rate)
      : gr::sync_block("bbheader_sink",
              gr::io_signature::make(1, 1, sizeof(unsigned char)),
              gr::io_signature::make(0, 0, 0))
    {
      struct ifreq ifr;
      int err;
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
      crc32_init();
      for (int i = 0; i < 256; i++) {
        packet_alloc[i] = NULL;
        packet_ptr[i] = NULL;
        packet_ttl[i] = 0;
      }
      dvb_standard = standard;
      synched = FALSE;

      if ((fd = open("/dev/net/tun", O_WRONLY)) == -1) {
        throw std::runtime_error("Error calling open()\n");
      }

      memset(&ifr, 0, sizeof(ifr));
      ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
      strncpy(ifr.ifr_name, DEFAULT_IF, IFNAMSIZ);

      if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) == -1) {
        close(fd);
        throw std::runtime_error("Error calling ioctl()\n");
      }

      set_output_multiple(kbch);
    }

    /*
     * Our virtual destructor.
     */
    bbheader_sink_impl::~bbheader_sink_impl()
    {
      for (int i = 0; i < 256; i++) {
        if (packet_alloc[i] != NULL) {
          free(packet_alloc[i]);
        }
      }
      if (fd) {
        close(fd);
      }
    }

#define CRC_POLY 0xAB

    /*
     * MSB is sent first
     *
     * The polynomial has been reversed
     */
    unsigned int
    bbheader_sink_impl::check_crc8_bits(const unsigned char *in, int length)
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

      return (crc);
    }

    int
    bbheader_sink_impl::crc32_calc(unsigned char *buf, int size, int crc)
    {
      for (int i = 0; i < size; i++) {
        crc = (crc << 8) ^ crc32_table[((crc >> 24) ^ buf[i]) & 0xff];
      }
      return (crc);
    }

    void
    bbheader_sink_impl::crc32_init(void)
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
    bbheader_sink_impl::work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items)
    {
      const unsigned char *in = (const unsigned char *) input_items[0];
      unsigned int check, padding, length, temp;
      unsigned int start_indicator, end_indicator, label_type_indicator;
      unsigned int gse_length, frag_id = 0;
      unsigned char total_length[2] = {0};
      unsigned char protocol_type[2] = {0};
      unsigned char label[ETHER_ADDR_LEN] = {0};
      unsigned char crc[4] = {0};
      unsigned char *packet_ptr_save;
      BBHeader *h = &m_format[0].bb_header;
      int status;

      for (int i = 0; i < noutput_items; i += kbch) {
        check = check_crc8_bits(in, BB_HEADER_LENGTH_BITS + 8);
        if (check != 0) {
          synched = FALSE;
          printf("Baseband header crc failed.\n");
          in += kbch;
        }
        else {
          h->ts_gs = *in++ << 1;
          h->ts_gs |= *in++;
          h->sis_mis = *in++;
          h->ccm_acm = *in++;
          h->issyi = *in++;
          h->npd = *in++;
          h->ro = *in++ << 1;
          h->ro |= *in++;
          h->isi = 0;
          if (h->sis_mis == 0) {
            for (int n = 7; n >= 0; n--) {
              h->isi |= *in++ << n;
            }
          }
          else {
            in += 8;
          }
          h->upl = 0;
          for (int n = 15; n >= 0; n--) {
            h->upl |= *in++ << n;
          }
          h->dfl = 0;
          for (int n = 15; n >= 0; n--) {
            h->dfl |= *in++ << n;
          }
          h->sync = 0;
          for (int n = 7; n >= 0; n--) {
            h->sync |= *in++ << n;
          }
          h->syncd = 0;
          for (int n = 15; n >= 0; n--) {
            h->syncd |= *in++ << n;
          }
          in += 8;
          padding = kbch - h->dfl - (BB_HEADER_LENGTH_BITS + 8);
          while (h->dfl) {
            start_indicator = *in++;
            end_indicator = *in++;
            label_type_indicator = *in++ << 1;
            label_type_indicator |= *in++;
            h->dfl -= 4;
            gse_length = 0;
            for (int n = 11; n >= 0; n--) {
              gse_length |= *in++ << n;
            }
            h->dfl -= 12;
            if (start_indicator == 0 || end_indicator == 0) {
              frag_id = 0;
              for (int n = 7; n >= 0; n--) {
                frag_id |= *in++ << n;
              }
              h->dfl -= 8;
              gse_length -= 1;
            }
            if (start_indicator == 1 && end_indicator == 0) {
              for (unsigned int j = 0; j < 2; j++) {
                temp = 0;
                for (int n = 7; n >= 0; n--) {
                  temp |= *in++ << n;
                }
                total_length[j] = (unsigned char)temp;
              }
              crc32_partial = crc32_calc(&total_length[0], 2, 0xffffffff);
              length = (total_length[0] & 0xff) << 8;
              length |= (total_length[1] & 0xff);
              length += ETHER_ADDR_LEN;
              printf("id = %d, length = %d\n", frag_id, length);
              packet_alloc[frag_id] = (unsigned char*) malloc(sizeof(unsigned char) * length);
              packet_ptr[frag_id] = packet_alloc[frag_id];
              packet_ttl[frag_id] = 10;
              h->dfl -= 16;
              gse_length -= 2;
            }
            if (start_indicator == 1) {
              for (unsigned int j = 0; j < ETHER_TYPE_LEN; j++) {
                temp = 0;
                for (int n = 7; n >= 0; n--) {
                  temp |= *in++ << n;
                }
                protocol_type[j] = (unsigned char)temp;
              }
              crc32_partial = crc32_calc(&protocol_type[0], 2, crc32_partial);
              h->dfl -= 16;
              gse_length -= 2;
              if (label_type_indicator == 0) {
                for (unsigned int j = 0; j < ETHER_ADDR_LEN; j++) {
                  temp = 0;
                  for (int n = 7; n >= 0; n--) {
                    temp |= *in++ << n;
                  }
                  label[j] = (unsigned char)temp;
                }
                crc32_partial = crc32_calc(&label[0], ETHER_ADDR_LEN, crc32_partial);
                h->dfl -= 48;
                gse_length -= 6;
              }
              else if (label_type_indicator == 1) {
                for (int j = 0; j < 3; j++) {
                  temp = 0;
                  for (int n = 7; n >= 0; n--) {
                    temp |= *in++ << n;
                  }
                  label[j] = (unsigned char)temp;
                }
                crc32_partial = crc32_calc(&label[0], 3, crc32_partial);
                h->dfl -= 24;
                gse_length -= 3;
              }
              else if (label_type_indicator == 2) {
              }
              else if (label_type_indicator == 3) {
              }
            }
            if (start_indicator == 1 && end_indicator == 1) {
              printf("gse length full = %d\n", gse_length);
              index = 0;
              for (unsigned int j = 0; j < ETHER_ADDR_LEN; j++) {
                packet[index++] = label[j];
              }
              for (unsigned int j = 0; j < ETHER_ADDR_LEN; j++) {
                packet[index++] = label[j];
              }
              packet[index++] = protocol_type[0];
              packet[index++] = protocol_type[1];
              for (unsigned int j = 0; j < gse_length; j++) {
                temp = 0;
                for (int n = 7; n >= 0; n--) {
                  temp |= *in++ << n;
                }
                h->dfl -= 8;
                packet[index++] = temp;
              }
              status = write(fd, &packet[0], index);
              if (status < 0) {
                printf("Write Error\n");
              }
              printf("length out full = %d\n", h->dfl);
            }
            else if (start_indicator == 1 && end_indicator == 0) {
              printf("gse length start = %d\n", gse_length);
              if (packet_ptr[frag_id]) {
                index = 0;
                for (unsigned int j = 0; j < ETHER_ADDR_LEN; j++) {
                  *packet_ptr[frag_id]++ = label[j];
                  index++;
                }
                for (unsigned int j = 0; j < ETHER_ADDR_LEN; j++) {
                  *packet_ptr[frag_id]++ = label[j];
                  index++;
                }
                *packet_ptr[frag_id]++ = protocol_type[0];
                *packet_ptr[frag_id]++ = protocol_type[1];
                index += 2;
                packet_ptr_save = packet_ptr[frag_id];
                for (unsigned int j = 0; j < gse_length; j++) {
                  temp = 0;
                  for (int n = 7; n >= 0; n--) {
                    temp |= *in++ << n;
                  }
                  h->dfl -= 8;
                  *packet_ptr[frag_id]++ = temp;
                  index++;
                }
                crc32_partial = crc32_calc(&packet_ptr_save[0], gse_length, crc32_partial);
              }
              else {
                for (unsigned int j = 0; j < gse_length; j++) {
                  h->dfl -= 8;
                  index++;
                }
              }
              printf("length out start = %d\n", h->dfl);
            }
            else if (start_indicator == 0 && end_indicator == 0) {
              printf("gse length continuation = %d\n", gse_length);
              if (packet_ptr[frag_id]) {
                packet_ptr_save = packet_ptr[frag_id];
                for (unsigned int j = 0; j < gse_length; j++) {
                  temp = 0;
                  for (int n = 7; n >= 0; n--) {
                    temp |= *in++ << n;
                  }
                  h->dfl -= 8;
                  *packet_ptr[frag_id]++ = temp;
                  index++;
                }
                crc32_partial = crc32_calc(&packet_ptr_save[0], gse_length, crc32_partial);
              }
              else {
                printf("no buffer available!\n");
                for (unsigned int j = 0; j < gse_length; j++) {
                  h->dfl -= 8;
                  index++;
                }
              }
              printf("length out continuation = %d\n", h->dfl);
            }
            else if (start_indicator == 0 && end_indicator == 1) {
              printf("gse length end = %d\n", gse_length);
              if (packet_ptr[frag_id]) {
                packet_ptr_save = packet_ptr[frag_id];
                for (unsigned int j = 0; j < gse_length - 4; j++) {
                  temp = 0;
                  for (int n = 7; n >= 0; n--) {
                    temp |= *in++ << n;
                  }
                  h->dfl -= 8;
                  *packet_ptr[frag_id]++ = temp;
                  index++;
                }
                crc32_partial = crc32_calc(&packet_ptr_save[0], gse_length - 4, crc32_partial);
                for (unsigned int j = 0; j < 4; j++) {
                  temp = 0;
                  for (int n = 7; n >= 0; n--) {
                    temp |= *in++ << n;
                  }
                  h->dfl -= 8;
                  crc[j] = (unsigned char)temp;
                }
                crc32_partial = crc32_calc(&crc[0], 4, crc32_partial);
                if (crc32_partial == 0) {
                  status = write(fd, packet_alloc[frag_id], index);
                  if (status < 0) {
                    printf("Write Error\n");
                  }
                  printf("length out end = %d\n", h->dfl);
                }
                else {
                  printf("crc error!\n");
                }
                if (packet_alloc[frag_id]) {
                  free(packet_alloc[frag_id]);
                  packet_alloc[frag_id] = NULL;
                  packet_ptr[frag_id] = NULL;
                  packet_ttl[frag_id] = 0;
                  printf("free = %d\n", index);
                }
                else {
                  printf("free error!\n");
                }
              }
              else {
                for (unsigned int j = 0; j < gse_length; j++) {
                  h->dfl -= 8;
                  index++;
                }
              }
            }
          }
          if (padding != 2992)
            printf("padding = %d\n\n", padding);
          in += padding;
        }
        for (int n = 0; n < 256; n++) {
          if (packet_ttl[n] != 0) {
            packet_ttl[n]--;
            if (packet_ttl[n] == 0) {
              printf("buffer %d timeout!\n", n);
              if (packet_alloc[n]) {
                free(packet_alloc[n]);
                packet_alloc[n] = NULL;
                packet_ptr[n] = NULL;
              }
              else {
                printf("free error!\n");
              }
            }
          }
        }
      }

      // Tell runtime system how many output items we produced.
      return noutput_items;
    }

  } /* namespace dvbgse */
} /* namespace gr */

