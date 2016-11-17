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

#ifndef INCLUDED_DVBGSE_CONFIG_H
#define INCLUDED_DVBGSE_CONFIG_H

#define TRUE 1
#define FALSE 0

#define BB_HEADER_LENGTH_BITS 72

// BB HEADER fields
#define TS_GS_TRANSPORT 3
#define TS_GS_GENERIC_PACKETIZED 0
#define TS_GS_GENERIC_CONTINUOUS 1
#define TS_GS_RESERVED 2

#define SIS_MIS_SINGLE 1
#define SIS_MIS_MULTIPLE 0

#define CCM 1
#define ACM 0

#define ISSYI_ACTIVE 1
#define ISSYI_NOT_ACTIVE 0

#define NPD_ACTIVE 1
#define NPD_NOT_ACTIVE 0

#define FRAME_SIZE_NORMAL 64800
#define FRAME_SIZE_MEDIUM 32400
#define FRAME_SIZE_SHORT  16200

namespace gr {
  namespace dvbgse {
    enum dvb_standard_t {
      STANDARD_DVBS2 = 0,
      STANDARD_DVBT2,
    };

    enum dvb_code_rate_t {
      C1_4 = 0,
      C1_3,
      C2_5,
      C1_2,
      C3_5,
      C2_3,
      C3_4,
      C4_5,
      C5_6,
      C7_8,
      C8_9,
      C9_10,
      C13_45,
      C9_20,
      C90_180,
      C96_180,
      C11_20,
      C100_180,
      C104_180,
      C26_45,
      C18_30,
      C28_45,
      C23_36,
      C116_180,
      C20_30,
      C124_180,
      C25_36,
      C128_180,
      C13_18,
      C132_180,
      C22_30,
      C135_180,
      C140_180,
      C7_9,
      C154_180,
      C11_45,
      C4_15,
      C14_45,
      C7_15,
      C8_15,
      C32_45,
      C2_9_VLSNR,
      C1_5_MEDIUM,
      C11_45_MEDIUM,
      C1_3_MEDIUM,
      C1_5_VLSNR_SF2,
      C11_45_VLSNR_SF2,
      C1_5_VLSNR,
      C4_15_VLSNR,
      C1_3_VLSNR,
      C_OTHER,
    };

    enum dvb_framesize_t {
      FECFRAME_SHORT = 0,
      FECFRAME_NORMAL,
      FECFRAME_MEDIUM,
    };

    enum dvbs2_rolloff_factor_t {
      RO_0_35 = 0,
      RO_0_25,
      RO_0_20,
      RO_RESERVED,
      RO_0_15,
      RO_0_10,
      RO_0_05,
    };

    enum dvbt2_inband_t {
      INBAND_OFF = 0,
      INBAND_ON,
    };

  } // namespace dvbgse
} // namespace gr

typedef gr::dvbgse::dvb_standard_t dvb_standard_t;
typedef gr::dvbgse::dvb_code_rate_t dvb_code_rate_t;
typedef gr::dvbgse::dvb_framesize_t dvb_framesize_t;
typedef gr::dvbgse::dvbs2_rolloff_factor_t dvbs2_rolloff_factor_t;
typedef gr::dvbgse::dvbt2_inband_t dvbt2_inband_t;

#endif /* INCLUDED_DVBGSE_CONFIG_H */

