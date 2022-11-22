/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */

#ifndef __CI_DRIVER_EFAB_HARDWARE_EFCT_H__
#define __CI_DRIVER_EFAB_HARDWARE_EFCT_H__

/* TODO many of these should be generated from hardware defs when possible */

/* tx header bit field definitions */
#define EFCT_TX_HEADER_PACKET_LENGTH_LBN 0
#define EFCT_TX_HEADER_PACKET_LENGTH_WIDTH 14

#define EFCT_TX_HEADER_CT_THRESH_LBN 14
#define EFCT_TX_HEADER_CT_THRESH_WIDTH 8

#define EFCT_TX_HEADER_TIMESTAMP_FLAG_LBN 22
#define EFCT_TX_HEADER_TIMESTAMP_FLAG_WIDTH 1

#define EFCT_TX_HEADER_WARM_FLAG_LBN 23
#define EFCT_TX_HEADER_WARM_FLAG_WIDTH 1

#define EFCT_TX_HEADER_ACTION_LBN 24
#define EFCT_TX_HEADER_ACTION_WIDTH 3

/* rx header bit field definitions */
#define EFCT_RX_HEADER_PACKET_LENGTH_LBN 0
#define EFCT_RX_HEADER_PACKET_LENGTH_WIDTH 14

#define EFCT_RX_HEADER_NEXT_FRAME_LOC_LBN 14
#define EFCT_RX_HEADER_NEXT_FRAME_LOC_WIDTH 2

#define EFCT_RX_HEADER_CSUM_LBN 16
#define EFCT_RX_HEADER_CSUM_WIDTH 16

#define EFCT_RX_HEADER_L2_CLASS_LBN 32
#define EFCT_RX_HEADER_L2_CLASS_WIDTH 2
#define EFCT_RX_HEADER_L2_CLASS_ETH_01VLAN 1

#define EFCT_RX_HEADER_L3_CLASS_LBN 34
#define EFCT_RX_HEADER_L3_CLASS_WIDTH 2
#define EFCT_RX_HEADER_L3_CLASS_IP4 0
#define EFCT_RX_HEADER_L3_CLASS_IP6 1

#define EFCT_RX_HEADER_L4_CLASS_LBN 36
#define EFCT_RX_HEADER_L4_CLASS_WIDTH 2
#define EFCT_RX_HEADER_L4_CLASS_TCP 0
#define EFCT_RX_HEADER_L4_CLASS_UDP 1

#define EFCT_RX_HEADER_L2_STATUS_LBN 38
#define EFCT_RX_HEADER_L2_STATUS_WIDTH 2
#define EFCT_RX_HEADER_L2_STATUS_LBN 38
#define EFCT_RX_HEADER_L2_STATUS_WIDTH 2
#define EFCT_RX_HEADER_L2_STATUS_LEN_ERR 1
#define EFCT_RX_HEADER_L2_STATUS_FCS_ERR 2

#define EFCT_RX_HEADER_L3_STATUS_LBN 40
#define EFCT_RX_HEADER_L3_STATUS_WIDTH 1

#define EFCT_RX_HEADER_L4_STATUS_LBN 41
#define EFCT_RX_HEADER_L4_STATUS_WIDTH 1

#define EFCT_RX_HEADER_ROLLOVER_LBN 42
#define EFCT_RX_HEADER_ROLLOVER_WIDTH 1

#define EFCT_RX_HEADER_SENTINEL_LBN 43
#define EFCT_RX_HEADER_SENTINEL_WIDTH 1

#define EFCT_RX_HEADER_TIMESTAMP_STATUS_LBN 44
#define EFCT_RX_HEADER_TIMESTAMP_STATUS_WIDTH 2

#define EFCT_RX_HEADER_FILTER_LBN 46
#define EFCT_RX_HEADER_FILTER_WIDTH 10

#define EFCT_RX_HEADER_USER_LBN 56
#define EFCT_RX_HEADER_USER_WIDTH 8

#define EFCT_RX_HEADER_TIMESTAMP_LBN 64
#define EFCT_RX_HEADER_TIMESTAMP_WIDTH 64

/* data offsets corresponding to NEXT_FRAME_LOC values */
#define EFCT_RX_HEADER_NEXT_FRAME_LOC_0 18
#define EFCT_RX_HEADER_NEXT_FRAME_LOC_1 66

/* generic event bit field definitions */
#define EFCT_EVENT_PHASE_LBN 59
#define EFCT_EVENT_PHASE_WIDTH 1

#define EFCT_EVENT_TYPE_LBN 60
#define EFCT_EVENT_TYPE_WIDTH 4

/* event types */
#define EFCT_EVENT_TYPE_RX 0
#define EFCT_EVENT_TYPE_TX 1
#define EFCT_EVENT_TYPE_CONTROL 3

/* control events */
#define EFCT_CTRL_SUBTYPE_LBN 53
#define EFCT_CTRL_SUBTYPE_WIDTH 6
#define EFCT_CTRL_EV_UNSOL_OVERFLOW 0
#define EFCT_CTRL_EV_TIME_SYNC 1
#define EFCT_CTRL_EV_FLUSH 2
#define EFCT_CTRL_EV_ERROR 3

/* time sync events */
#define EFCT_TIME_SYNC_TIME_HIGH_LBN 0
#define EFCT_TIME_SYNC_TIME_HIGH_WIDTH 48

#define EFCT_TIME_SYNC_CLOCK_IN_SYNC_LBN 48
#define EFCT_TIME_SYNC_CLOCK_IN_SYNC_WIDTH 1

#define EFCT_TIME_SYNC_CLOCK_IS_SET_LBN 49
#define EFCT_TIME_SYNC_CLOCK_IS_SET_WIDTH 1

/* flush events */
#define EFCT_FLUSH_TYPE_LBN 0
#define EFCT_FLUSH_TYPE_WIDTH 4
#define EFCT_FLUSH_TYPE_TX 0
#define EFCT_FLUSH_TYPE_RX 1

#define EFCT_FLUSH_LABEL_LBN 4
#define EFCT_FLUSH_LABEL_WIDTH 6

#define EFCT_FLUSH_QUEUE_ID_LBN 16
#define EFCT_FLUSH_QUEUE_ID_WIDTH 8

/* error events */
#define EFCT_ERROR_QUEUE_TYPE_LBN 0
#define EFCT_ERROR_QUEUE_TYPE_WIDTH 4
#define EFCT_ERROR_QUEUE_TYPE_TX 0
#define EFCT_ERROR_QUEUE_TYPE_RX 1

#define EFCT_ERROR_LABEL_LBN 4
#define EFCT_ERROR_LABEL_WIDTH 6

#define EFCT_ERROR_REASON_LBN 10
#define EFCT_ERROR_REASON_WIDTH 6
#define EFCT_ERROR_REASON_RX_BAD_DISC 1
#define EFCT_ERROR_REASON_RX_FIFO_OVERFLOW 2
#define EFCT_ERROR_REASON_RX_BAD_BUF_ADDR 3
#define EFCT_ERROR_REASON_CTPIO_LEN 4
#define EFCT_ERROR_REASON_CTPIO_ALIGN 5
#define EFCT_ERROR_REASON_CTPIO_FIFO_OVERFLOW 6
#define EFCT_ERROR_REASON_CTPIO_BAD_REORDERING 7
#define EFCT_ERROR_REASON_CTPIO_BAD_TPL_FLAGS 8
#define EFCT_ERROR_REASON_HW_INTERNAL 9

#define EFCT_ERROR_QUEUE_ID_LBN 16
#define EFCT_ERROR_QUEUE_ID_WIDTH 8

/* tx event bit field definitions */
#define EFCT_TX_EVENT_PARTIAL_TSTAMP_LBN 0
#define EFCT_TX_EVENT_PARTIAL_TSTAMP_WIDTH 40

#define EFCT_TX_EVENT_SEQUENCE_LBN 40
#define EFCT_TX_EVENT_SEQUENCE_WIDTH 8

#define EFCT_TX_EVENT_TIMESTAMP_STATUS_LBN 48
#define EFCT_TX_EVENT_TIMESTAMP_STATUS_WIDTH 2

#define EFCT_TX_EVENT_LABEL_LBN 50
#define EFCT_TX_EVENT_LABEL_WIDTH 6

/* time sync event bit field definitions */
#define EFCT_TIME_SYNC_EVENT_TIME_HIGH_LBN 0
#define EFCT_TIME_SYNC_EVENT_TIME_HIGH_WIDTH 48

#define EFCT_TIME_SYNC_EVENT_CLOCK_IN_SYNC_LBN 48
#define EFCT_TIME_SYNC_EVENT_CLOCK_IN_SYNC_WIDTH 1

#define EFCT_TIME_SYNC_EVENT_CLOCK_IS_SET_LBN 49
#define EFCT_TIME_SYNC_EVENT_CLOCK_IS_SET_WIDTH 1

#define DP_PARTIAL_TSTAMP_SUB_NANO_BITS 2

/* unsolicited credit definitions */

#define EFCT_EVQ_UNSOL_CREDIT_REGISTER_OFFSET 0
#define EFCT_EVQ_UNSOL_GRANT_SEQ_LBN 0
#define EFCT_EVQ_UNSOL_GRANT_SEQ_WIDTH 16
#define EFCT_EVQ_UNSOL_GRANT_MAX_SEQ_WIDTH 7
#define EFCT_EVQ_UNSOL_CLEAR_OVERFLOW_LBN 16
#define EFCT_EVQ_UNSOL_CLEAR_OVERFLOW_WIDTH 1

/* size of a transmit header in bytes */
#define EFCT_TX_HEADER_BYTES 8

/* size of a transmit descriptor in bytes */
#define EFCT_TX_DESCRIPTOR_BYTES 2

/* size of the transmit FIFO in bytes */
#define EFCT_TX_FIFO_BYTES 32768

/* size of the transmit aperture in bytes */
#define EFCT_TX_APERTURE 4096

/* alignment requirement for tx packets written to the aperture */
#define EFCT_TX_ALIGNMENT 64

/* magic value of ct_thresh to disable cut-through */
#define EFCT_TX_CT_DISABLE 0xff

/* size of a receive header in bytes */
#define EFCT_RX_HEADER_BYTES 16

/* size of a transmit descriptor in bytes */
#define EFCT_RX_DESCRIPTOR_BYTES 16

/* size of each receive buffer posted to RX_BUFFER_POST (DP_RX_BUFFER_SIZE) */
#define EFCT_RX_SUPERBUF_BYTES  1048576

/* FIXME EFCT: make this variable */
#define EFCT_PKT_STRIDE 2048

/* Interrupt priming */
#define ERF_HZ_READ_IDX_LBN 16
#define ERF_HZ_READ_IDX_WIDTH 16
#define ERF_HZ_EVQ_ID_LBN 0
#define ERF_HZ_EVQ_ID_WIDTH 16

#endif

