/*
 *      demod_flex.c
 *
 *      Copyright 2004,2006,2010 Free Software Foundation, Inc.
 *      Copyright (C) 2015 Craig Shelley (craig@microtron.org.uk)
 *
 *      FLEX Radio Paging Decoder - Adapted from GNURadio for use with Multimon
 *
 *      GNU Radio is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 3, or (at your option)
 *      any later version.
 *
 *      GNU Radio is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with GNU Radio; see the file COPYING.  If not, write to
 *      the Free Software Foundation, Inc., 51 Franklin Street,
 *      Boston, MA 02110-1301, USA.
 */
/*
 *  Modification (to this file) made by Vasyl Samoilov (vasyl.samoilov@gmail.com)
 *   - Per-word bch_err[] tracking; damaged words shown as '?' instead of garbage
 *   - Long address decoding: full ARIB STD-43A Table 3.8.2.2-1 (all address sets)
 *   - FIW: roaming, repeat, traffic, num_tx (1-4), td_collapse fields
 *   - BIW parsing: SSID1, Date, Time, SysInfo (timezone/DST/extended seconds), SSID2
 *   - BIW101 system message vector decode at end of VF (Section 3.9.2 method a/b)
 *   - S2 C/inv.C detection with symbol buffer and replay for boundary correction
 *   - Phase mapping: bit_b to PhaseC at 1600 baud (A3), PhaseB at 3200 baud (A4)
 *   - Address type classification: S/L/N/T/O/I/R with special address handling
 *   - Network address payload decode (area/zones/traffic)
 *   - Operator message category logging (SysMsg/SSIDChange/SysEvent)
 *   - Secure message (V=000): t1t0 sub-type dispatch; t=00 as alpha, t=10 as binary
 *   - Short message vector (V=010): sub-type decode (numeric/source/numbered/reserved)
 *   - Tone-only: address-level (no vector) vs all-space short message
 *   - Numeric: K checksum verification, BCD 0xA = '.', tags NUM/SNUM/NNUM
 *   - HEX: nibble extraction, hdr2 parsing, fill stripping, signature (S) validation
 *   - Alpha: K checksum (10-bit) and signature (7-bit) verification
 *   - HEX header: type-dependent bit extraction (12-bit K shifts C/F/N; R/M in hdr2)
 *   - Fragment reassembly: 16 slots, 64-frame timeout, F sequence tracking (mod 3)
 *   - Fragment keying by (capcode, type, msg_n) to separate interleaved messages
 *   - R/M carry-over: initial fragment's R/M propagated to continuation and reassembled
 *   - Frag flags: F.C.flag.Nnn.Rn[.M][.K-][.SIGN-][.DUP][.DUP+]
 *   - Word-level deduplication: 32-slot cache, word-level combining on retransmission
 *   - JSON output (--json): all message types, BIW system info, flextime, fragment info
 *   - flextime: OTA timestamp from BIW date/time/timezone with per-component age tracking
 *   - Timezone lookup table: 32-entry FLEX spec table with fractional offsets
 *   - Extended seconds: S5-S3 from BIW SYSINFO combined with S2-S0 for 0.9375s precision
 *   - flextime expiry: components invalidated after one full cycle (1920 frames + margin)
 *   - JSON fields: msg_type (human-readable), group_slot, instruction_type, sec_subtype,
 *     smsg_sub_type, source_code, blocking, opr_category, biw_position, frag_seq,
 *     frag_index, frag_words, frag_chars, total_fragments, total_chars, frag_seq_error,
 *     precision_seconds, group_capcodes array, flextime object with date/time/tz components
 *   Bug fixes:
 *   - Group message K checksum/signature: removed incorrect len skip for group addresses
 *   - Instruction vector (V=001): moved handler before hdr/len calculation to prevent
 *     "Invalid VIW" false positives when instruction data encodes out-of-range mw1
 *   - Instruction vector pre-scan: bypass nibble checksum for type=1 vectors
 *   - Atomic level-0 output: message line emitted in single verbprintf call to prevent
 *     debug output interleaving at higher verbosity levels
 *   - Group capcodes in capcode field (space-separated) matching FLEX output convention
 *  Modification (to this file) made by Ryan Farley (rfarley3@github)
 *   - Issue #139 !160 handle edge cases for start and end offsets (long vs short, single vs group)
 *   - Resolve type ambiguity to improve stability after Raspberry Pi compile
 *   - Compare algorithms to other open source libraries to reconcile group bit, frag bit, and capcode decode
 *   - Refactor message printing to single line, only printables, encoded % fmtstr directives
 *  Version 0.9.3v (28 Jan 2020)
 *  Modification made by bierviltje and implemented by Bruce Quinton (Zanoroy@gmail.com)
 *   - Issue #123 created by bierviltje (https://github.com/bierviltje) - Feature request: FLEX: put group messages in an array/list
 *   - This also changed the delimiter to a | rather than a space
 *  Version 0.9.2v (03 Apr 2019)
 *  Modification made by Bruce Quinton (Zanoroy@gmail.com)
 *   - Issue #120 created by PimHaarsma - Flex Tone-Only messages with short numeric body Bug fixed using code documented in the ticket system
 *  Version 0.9.1v (10 Jan 2019)
 *  Modification (to this file) made by Rob0101
 *   Fixed marking messages with K,F,C - One case had a 'C' marked as a 'K' 
 *  Version 0.9.0v (22 May 2018)
 *  Modification (to this file) made by Bruce Quinton (zanoroy@gmail.com)
 *    - Addded Define at top of file to modify the way missed group messages are reported in the debug output (default is 1; report missed capcodes on the same line)
 *                           REPORT_GROUP_CODES   1             // Report each cleared faulty group capcode : 0 = Each on a new line; 1 = All on the same line;
 *  Version 0.8.9 (20 Mar 2018)
 *  Modification (to this file) made by Bruce Quinton (zanoroy@gmail.com)
 *     - Issue #101 created by bertinhollan (https://github.com/bertinholland): Bug flex: Wrong split up group message after a data corruption frame.
 *     - Added logic to the FIW decoding that checks for any 'Group Messages' and if the frame has past them remove the group message and log output
 *     - The following settings (at the top of this file, just under these comments) have changed from:
 *                              PHASE_LOCKED_RATE    0.150
 *                              PHASE_UNLOCKED_RATE  0.150
 *       these new settings appear to work better when attempting to locate the Sync lock in the message preamble.
 *  Version 0.8.8v (20 APR 2018)
 *  Modification (to this file) made by Bruce Quinton (zanoroy@gmail.com)
 *     - Issue #101 created by bertinhollan (https://github.com/bertinholland): Bug flex: Wrong split up group message after a data corruption frame. 
 *  Version 0.8.7v (11 APR 2018)
 *  Modification (to this file) made by Bruce Quinton (zanoroy@gmail.com) and Rob0101 (as seen on github: https://github.com/rob0101)
 *     - Issue *#95 created by rob0101: '-a FLEX dropping first character of some message on regular basis'
 *     - Implemented Rob0101's suggestion of K, F and C flags to indicate the message fragmentation: 
 *         'K' message is complete and O'K' to display to the world.
 *         'F' message is a 'F'ragment and needs a 'C'ontinuation message to complete it. Message = Fragment + Continuation
 *         'C' message is a 'C'ontinuation of another fragmented message
 *  Version 0.8.6v (18 Dec 2017)
 *  Modification (to this file) made by Bruce Quinton (Zanoroy@gmail.com) on behalf of bertinhollan (https://github.com/bertinholland)
 *     - Issue #87 created by bertinhollan: Reported issue is that the flex period timeout was too short and therefore some group messages were not being processed correctly
 *                                          After some testing bertinhollan found that increasing the timeout period fixed the issue in his area. I have done further testing in my local
 *                                          area and found the change has not reduced my success rate. I think the timeout is a localisation setting and I have added "DEMOD_TIMEOUT" 
 *                                          to the definitions in the top of this file (the default value is 100 bertinhollan's prefered value, changed up from 50)
 *  Version 0.8.5v (08 Sep 2017)
 *  Modification made by Bruce Quinton (Zanoroy@gmail.com)
 *     - Issue #78 - Found a problem in the length detection sequence, modified the if statement to ensure the message length is 
 *       only checked for Aplha messages, the other types calculate thier length while decoding
 *  Version 0.8.4v (05 Sep 2017)
 *  Modification made by Bruce Quinton (Zanoroy@gmail.com)
 *     - Found a bug in the code that was not handling multiple group messages within the same frame, 
 *       and the long address bit was being miss treated in the same cases. Both issue have been fixed but further testing will help.
 *  Version 0.8.3v (22 Jun 2017)
 *  Modification made by Bruce Quinton (Zanoroy@gmail.com)
 *     - I had previously tagged Group Messages as GPN message types, 
 *       this was my own identification rather than a Flex standard type. 
 *       Now that I have cleaned up all identified (so far) issues I have changed back to the correct Flex message type of ALN (Alpha).
 *  Version 0.8.2v (21 Jun 2017)
 *  Modification made by Bruce Quinton (Zanoroy@gmail.com)
 *     - Fixed group messaging capcode issue - modified the Capcode Array to be int64_t rather than int (I was incorrectly casting the long to an int) 
 *  Version 0.8.1v (16 Jun 2017)
 *  Modification made by Bruce Quinton (Zanoroy@gmail.com)
 *     - Added Debugging to help track the group messaging issues
 *     - Improved Alpha output and removed several loops to improve CPU cycles
 *  Version 0.8v (08 Jun 2017)
 *  Modification made by Bruce Quinton (Zanoroy@gmail.com)
 *     - Added Group Messaging
 *     - Fixed Phase adjustments (phasing as part of Symbol identification)
 *     - Fixed Alpha numeric length adjustments to stop "Invalid Vector" errors
 *     - Fixed numeric message treatment
 *     - Fixed invalid identification of "unknown" messages
 *     - Added 3200 2 fsk identification to all more message types to be processed (this was a big deal for NZ)
 *     - Changed uint to int variables
 *      
 */

/* ---------------------------------------------------------------------- */

#include "multimon.h"
#include "filter.h"
#include "bch.h"
#include "cJSON.h"
#include <math.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

extern int json_mode;

/* ---------------------------------------------------------------------- */

#define FREQ_SAMP            22050
#define FILTLEN              1
#define REPORT_GROUP_CODES   1       // Report each cleared faulty group capcode : 0 = Each on a new line; 1 = All on the same line;

#define FLEX_SYNC_MARKER     0xA6C6AAAAul  // Synchronisation code marker for FLEX
#define SLICE_THRESHOLD      0.6659        // 4-level quantization threshold (optimized from 2/3)
#define SLICE_THRESHOLD_IAD  0.665         // Integrate-and-dump alternate slicer threshold
#define DC_OFFSET_FILTER     0.010         // DC Offset removal IIR filter response (seconds)
#define PHASE_LOCKED_RATE    0.045         // Correction factor for locked state
#define PHASE_UNLOCKED_RATE  0.050         // Correction factor for unlocked state
#define LOCK_LEN             24            // Number of symbols to check for phase locking (max 32)
#define IDLE_THRESHOLD       0             // Number of idle codewords allowed in data section
#define CAPCODES_INDEX       0
#define DEMOD_TIMEOUT        100           // Maximum number of periods with no zero crossings before we decide that the system is not longer within a Timing lock.
#define GROUP_BITS           17            // Centralized maximum of group msg cache
#define PHASE_WORDS          88            // per spec, there are 88 4B words per frame

// S2 C-pattern per ARIB STD-43A Table 3.2-6
// S2 = BS2 + C(16 bits) + inv.BS2 + inv.C(16 bits)
// C and inv.C are used for timing verification after baud rate switch
#define FLEX_S2_C            0xED84u       // C pattern (16 bits)
#define FLEX_S2_C_INV        0x127Bu       // inv.C pattern (16 bits)
// there are 3 chars per message word (mw)
// there are at most 88 words per frame's phase buffer of a page
//   but at least 1 BIW 1 AW 1 VW, so max 85 data words (dw) for text
// each dw is 3 chars of 7b ASCII (21 bits of text, 11 bits of checksum)
// this is 256, BUT each char could need to be escaped (%, \n, \r, \t), so double it
#define MAX_ALN              512           // max possible ALN characters


enum Flex_PageTypeEnum {
  FLEX_PAGETYPE_SECURE,
  FLEX_PAGETYPE_SHORT_INSTRUCTION,
  FLEX_PAGETYPE_SHORT_MESSAGE,
  FLEX_PAGETYPE_STANDARD_NUMERIC,
  FLEX_PAGETYPE_SPECIAL_NUMERIC,
  FLEX_PAGETYPE_ALPHANUMERIC,
  FLEX_PAGETYPE_BINARY,
  FLEX_PAGETYPE_NUMBERED_NUMERIC,
  FLEX_PAGETYPE_TONE_ONLY          // synthetic: address with no vector word
};


enum Flex_StateEnum {
  FLEX_STATE_SYNC1,
  FLEX_STATE_FIW,
  FLEX_STATE_SYNC2,
  FLEX_STATE_DATA
};

struct Flex_Demodulator {
  unsigned int                sample_freq;
  double                      sample_last;
  int                         locked;
  int                         phase;
  unsigned int                sample_count;
  unsigned int                symbol_count;
  double                      envelope_sum;
  int                         envelope_count;
  uint64_t                    lock_buf;
  int                         symcount[4];
  double                      sym_sum;         // integrate-and-dump: sample sum over symbol period
  int                         sym_n;           // integrate-and-dump: sample count over symbol period
  int                         timeout;
  int                         nonconsec;
  unsigned int                baud;          // Current baud rate
};

struct Flex_GroupHandler {
  int64_t                     GroupCodes[GROUP_BITS][1000];
  int                         GroupCycle[GROUP_BITS];
  int                         GroupFrame[GROUP_BITS];
};

struct Flex_Modulation {
  double                      symbol_rate;
  double                      envelope;
  double                      zero;
};


struct Flex_State {
  unsigned int                sync2_count;
  unsigned int                data_count;
  unsigned int                fiwcount;
  enum Flex_StateEnum         Current;
  enum Flex_StateEnum         Previous;
  // S2 C-pattern correlation (Section 3.2, Table 3.2-6)
  // C = 0xED84 (16 bits), inv.C = 0x127B
  uint16_t                    sync2_shiftreg;  // 16-bit shift register for C detection
  int                         sync2_c_found;   // 1 = C found, 2 = inv.C found
  int                         sync2_c_pos;     // symbol position where pattern was found
  unsigned char               sync2_sym_buf[4]; // buffered symbols near S2/DATA boundary
  int                         sync2_sym_buf_count;
  int                         sync2_sym_buf_start; // symbol index of first buffered symbol
};


struct Flex_Sync {
  unsigned int                sync;          // Outer synchronization code
  unsigned int                baud;          // Baudrate of SYNC2 and DATA
  unsigned int                levels;        // FSK encoding of SYNC2 and DATA
  unsigned int                polarity;      // 0=Positive (Normal) 1=Negative (Inverted)
  uint64_t                    syncbuf;
};


struct Flex_FIW {
  unsigned int                rawdata;
  unsigned int                checksum;
  unsigned int                cycleno;
  unsigned int                frameno;
  unsigned int                fix3;
  unsigned int                roaming;       // n bit: 1=roaming allowed
  unsigned int                repeat;        // r bit: 1=multiple transmission
  unsigned int                traffic;       // t3-t0 field
  unsigned int                num_tx;        // derived: 1,2,3,4
  unsigned int                td_collapse;   // t3t2 when r=1: collapse for repeat interval
};


struct Flex_Phase {
  unsigned int                buf[PHASE_WORDS];
  int                         bch_err[PHASE_WORDS]; // 0=ok, 1=uncorrectable
  int                         idle_count;
};


struct Flex_Data {
  int                         phase_toggle;
  unsigned int                data_bit_counter;
  struct Flex_Phase           PhaseA;
  struct Flex_Phase           PhaseB;
  struct Flex_Phase           PhaseC;
  struct Flex_Phase           PhaseD;
  /* Alternate phase buffers from integrate-and-dump slicer */
  struct Flex_Phase           AltA;
  struct Flex_Phase           AltB;
  struct Flex_Phase           AltC;
  struct Flex_Phase           AltD;
};


struct Flex_Decode {
  enum Flex_PageTypeEnum      type;
  int                         long_address;
  int64_t                     capcode;
  char                        addr_type;     // S=short, L=long, N=network, T=temporary, O=operator, I=info, R=reserved
  char                        phase;         // A/B/C/D - set by decode_phase
  int                         is_group;      // 1 if temporary group address
  int                         is_priority;   // 1 if in priority address range
  const char                 *sec_subtype;   // SEC sub-type string (NULL if not SEC)
  const char                 *opr_category;  // OPR category string (NULL if not OPR)
};


// Fragment reassembly buffer for multi-part messages (K/F/C flags)
#define FLEX_FRAG_MAX_SLOTS  16
#define FLEX_FRAG_MAX_LEN    2048
#define FLEX_FRAG_TIMEOUT    64   // frames before expiry

// Deduplication and word-level combining for complete (K) messages.
// Stores raw 21-bit words + BCH status so retransmissions can be
// compared at the word level. If a retransmission has fewer errors
// than the cached copy, the better words are merged in and the
// message is re-decoded from the improved word set.
#define FLEX_DEDUP_SLOTS     32
#define FLEX_DEDUP_TIMEOUT   128  // frames before cache entry expires
#define FLEX_DEDUP_MAX_WORDS 88   // max words per message (hdr + body)

struct Flex_Fragment {
  int                         active;
  int64_t                     capcode;
  int                         type;          // page type
  int                         msg_n;         // N field (message number, 0-63) from header
  int                         msg_r;         // R field (retrieval, from initial fragment, -1 if unknown)
  int                         msg_m;         // M field (maildrop, from initial fragment, -1 if unknown)
  unsigned char               data[FLEX_FRAG_MAX_LEN];
  unsigned int                data_len;
  unsigned int                frame_received; // absolute frame when first fragment arrived
  uint32_t                    sig_sum;       // accumulated signature sum across fragments
  uint32_t                    rx_sig;        // received signature from initial fragment
  int                         sig_valid;     // 1 if all fragment words were clean
  int                         k_fail;        // 1 if any fragment had K checksum failure
  int                         expected_f;    // next expected F value (mod 3 sequence: 11->00->01->10->00...)
  int                         frag_index;    // fragment counter (0=initial, 1=first cont, ...)
  int                         f_mismatch;    // 1 if any F sequence mismatch detected (missing fragment)
};

struct Flex_FragStore {
  struct Flex_Fragment         slots[FLEX_FRAG_MAX_SLOTS];
};

struct Flex_DedupEntry {
  int                         active;
  int64_t                     capcode;
  int                         type;          // page type (V field)
  int                         msg_n;
  unsigned int                hdr_off;       // header word offset within words[]
  unsigned int                mw1_off;       // first body word offset within words[]
  unsigned int                word_count;    // total words stored (hdr + body)
  unsigned int                body_len;      // number of body words (len)
  uint32_t                    words[FLEX_DEDUP_MAX_WORDS];
  int                         errs[FLEX_DEDUP_MAX_WORDS]; // 0=clean, 1=uncorrectable
  unsigned int                frame_seen;
};

struct Flex_DedupStore {
  struct Flex_DedupEntry      entries[FLEX_DEDUP_SLOTS];
  unsigned int                next_slot;     // round-robin insertion index
};

/* Timezone offset in minutes, indexed by 5-bit zone code (Z4-Z0).
 * Per ARIB STD-43A / Flex G1.9b specification.
 * Codes 0-15: whole-hour offsets.  Codes 16-31: fractional offsets.
 * Code 16 (10000) is reserved. */
static const int flex_tz_table[32] = {
  /*  0 (-0h)    */    0,  /*  1 (+1h)    */   60,
  /*  2 (+2h)    */  120,  /*  3 (+3h)    */  180,
  /*  4 (+4h)    */  240,  /*  5 (+5h)    */  300,
  /*  6 (+6h)    */  360,  /*  7 (+7h)    */  420,
  /*  8 (+8h)    */  480,  /*  9 (+9h)    */  540,  /* Japan */
  /* 10 (+10h)   */  600,  /* 11 (+11h)   */  660,
  /* 12 (+12h)   */  720,  /* 13 (+3h30m) */  210,
  /* 14 (+4h30m) */  270,  /* 15 (+5h30m) */  330,
  /* 16 (reserved) */  0,  /* 17 (+5h45m) */  345,
  /* 18 (+6h30m) */  390,  /* 19 (+9h30m) */  570,
  /* 20 (-3h30m) */ -210,  /* 21 (-11h)   */ -660,
  /* 22 (-10h)   */ -600,  /* 23 (-9h)    */ -540,
  /* 24 (-8h)    */ -480,  /* 25 (-7h)    */ -420,
  /* 26 (-6h)    */ -360,  /* 27 (-5h)    */ -300,
  /* 28 (-4h)    */ -240,  /* 29 (-3h)    */ -180,
  /* 30 (-2h)    */ -120,  /* 31 (-1h)    */  -60,
};

/* Over-the-air time from FLEX network BIW system info words ("flextime").
 * Each component is updated independently as BIW words arrive.
 * has_* flags track which components have been received at least once.
 * received_at_* stores gettimeofday() timestamp (microsecond precision)
 * when each component was last received.
 * frame_* stores the absolute frame number (cycle*128+frame) for age calc. */
struct Flex_OTA_Time {
  /* BIW type 001: Date */
  int has_date;
  unsigned int year;       // 1994 + raw 5-bit value
  unsigned int month;      // 1-12
  unsigned int day;        // 1-31
  unsigned int frame_date; // cycle*128+frame when date was received (0-1919)

  /* BIW type 010: Time (coarse, 7.5s resolution) */
  int has_time;
  unsigned int hour;       // 0-23
  unsigned int min;        // 0-59
  unsigned int sec_coarse; // 0-7 (S2-S0, each unit = 7.5 seconds)
  unsigned int frame_time; // cycle*128+frame when time was received (0-1919)

  /* BIW type 101 A=4/8: Timezone, DST, extended seconds */
  int has_tz;
  unsigned int tz_zone;    // 0-31 (5-bit zone code)
  int tz_offset_min;       // UTC offset in minutes (from lookup table)
  int tz_dst;              // 0=DST active, 1=standard time (per spec)
  unsigned int sec_ext;    // 0-7 (S5-S3, extends seconds to 0.9375s resolution)
  unsigned int frame_tz;   // cycle*128+frame when tz was received (0-1919)
};

/* Frame space: 15 cycles x 128 frames = 1920 frames per full hour cycle.
 * Wrap-aware forward distance between two frame positions. */
#define FLEX_FRAME_SPACE 1920
/* Expire flextime components after one full cycle + 5 frames margin.
 * If age exceeds this, the data is stale (we've gone around the full
 * cycle without seeing a fresh update). */
#define FLEX_FLEXTIME_EXPIRE (FLEX_FRAME_SPACE + 5)

static unsigned int flextime_age_frames(unsigned int cur, unsigned int stored) {
  return (cur - stored + FLEX_FRAME_SPACE) % FLEX_FRAME_SPACE;
}

/* Expire stale flextime components.  Called before emitting JSON.
 * If a component's age exceeds FLEX_FLEXTIME_EXPIRE, invalidate it. */
static void flextime_expire(struct Flex_OTA_Time *ot, unsigned int cur_frame) {
  if (ot->has_date && flextime_age_frames(cur_frame, ot->frame_date) >= FLEX_FLEXTIME_EXPIRE) {
    ot->has_date = 0;
  }
  if (ot->has_time && flextime_age_frames(cur_frame, ot->frame_time) >= FLEX_FLEXTIME_EXPIRE) {
    ot->has_time = 0;
  }
  if (ot->has_tz && flextime_age_frames(cur_frame, ot->frame_tz) >= FLEX_FLEXTIME_EXPIRE) {
    ot->has_tz = 0;
  }
}


struct Flex_Next {
  struct Flex_Demodulator     Demodulator;
  struct Flex_Modulation      Modulation;
  struct Flex_State           State;
  struct Flex_Sync            Sync;
  struct Flex_FIW             FIW;
  struct Flex_Data            Data;
  struct Flex_Decode          Decode;
        struct Flex_GroupHandler    GroupHandler;
  struct Flex_FragStore       FragStore;
  struct Flex_DedupStore     DedupStore;
  int                         biw_sysmsg_a_type;  // BIW101 A-type (-1 = not present)
  struct Flex_OTA_Time        ota_time;            // Last known good OTA time
};


// Identify address type from the raw address word value (before capcode conversion).
// Returns a single character: S=short, L=long, N=network, T=temporary, O=operator, I=info
static char addr_type_char(uint32_t aiw, int is_long) {
  if (is_long) return 'L';
  // Special address ranges (Section 3.8.2):
  if (aiw >= 0x1F0001L && aiw <= 0x1F77FFL) return 'N';  // Network
  if (aiw >= 0x1F7800L && aiw <= 0x1F780FL) return 'T';  // Temporary (group)
  if (aiw >= 0x1F7810L && aiw <= 0x1F781FL) return 'O';  // Operator Message
  if (aiw >= 0x1F7820L && aiw <= 0x1F7FEFL) return 'I';  // Info Service
  if (aiw >= 0x1F7FF0L && aiw <= 0x1F7FFEL) return 'R';  // Reserved
  return 'S';  // Normal short address
}

// JSON output helper: emit a complete JSON message object.
// Called from decode_phase after message parsing is complete.
// All fields are optional (pass NULL/negative to omit).
static void flex_next_json_emit(struct Flex_Next *flex, char phase,
                                int64_t capcode, char addr_type,
                                int is_group, int msg_type,
                                const char *type_tag,
                                const char *fragment,
                                int msg_n, int msg_r, int msg_m,
                                int k_ok, int sig_ok,
                                const char *message,
                                int64_t *group_capcodes, int group_count,
                                cJSON *extra)
{
  cJSON *json = cJSON_CreateObject();
  if (!json) return;

  time_t now = time(NULL);
  struct tm *gmt = gmtime(&now);
  char ts[64];
  snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
           gmt->tm_year+1900, gmt->tm_mon+1, gmt->tm_mday,
           gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
  cJSON_AddStringToObject(json, "timestamp", ts);
  cJSON_AddNumberToObject(json, "baud", flex->Sync.baud);
  cJSON_AddNumberToObject(json, "level", flex->Sync.levels);
  {
    char ph[2] = { phase, '\0' };
    cJSON_AddStringToObject(json, "phase", ph);
  }
  cJSON_AddNumberToObject(json, "cycle", flex->FIW.cycleno);
  cJSON_AddNumberToObject(json, "frame", flex->FIW.frameno);
  cJSON_AddNumberToObject(json, "capcode", (double)capcode);
  {
    char at[2] = { addr_type, '\0' };
    cJSON_AddStringToObject(json, "addr_type", at);
  }
  cJSON_AddBoolToObject(json, "is_group", is_group ? 1 : 0);
  if (msg_type >= 0) {
    // Human-readable message type name
    const char *mt_name = "unknown";
    switch (msg_type) {
      case 0: mt_name = "secure"; break;
      case 1: mt_name = "instruction"; break;
      case 2: mt_name = "short_msg"; break;
      case 3: mt_name = "numeric"; break;
      case 4: mt_name = "special_numeric"; break;
      case 5: mt_name = "alphanumeric"; break;
      case 6: mt_name = "binary"; break;
      case 7: mt_name = "numbered_numeric"; break;
      case 8: mt_name = "tone_only"; break;
    }
    cJSON_AddStringToObject(json, "msg_type", mt_name);
  }
  if (type_tag)
    cJSON_AddStringToObject(json, "type_tag", type_tag);
  // Add group_slot for temporary group address messages
  if (is_group && capcode >= 2029568 && capcode <= 2029583)
    cJSON_AddNumberToObject(json, "group_slot", (int)(capcode - 2029568));
  if (fragment)
    cJSON_AddStringToObject(json, "fragment", fragment);
  if (msg_n >= 0)
    cJSON_AddNumberToObject(json, "msg_number", msg_n);
  if (msg_r >= 0)
    cJSON_AddNumberToObject(json, "retrieval", msg_r);
  if (msg_m >= 0)
    cJSON_AddNumberToObject(json, "maildrop", msg_m);
  if (k_ok >= 0)
    cJSON_AddBoolToObject(json, "k_ok", k_ok ? 1 : 0);
  if (sig_ok >= 0)
    cJSON_AddBoolToObject(json, "sig_ok", sig_ok ? 1 : 0);
  if (message)
    cJSON_AddStringToObject(json, "message", message);
  if (group_capcodes && group_count > 0) {
    cJSON *arr = cJSON_CreateArray();
    for (int gi = 0; gi < group_count; gi++)
      cJSON_AddItemToArray(arr, cJSON_CreateNumber((double)group_capcodes[gi]));
    cJSON_AddItemToObject(json, "group_capcodes", arr);
  }
  // Merge caller-provided extra fields
  if (extra) {
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, extra) {
      cJSON_AddItemToObject(json, item->string, cJSON_Duplicate(item, 1));
    }
    cJSON_Delete(extra);
  }
  // Add sec_subtype and opr_category from Decode context if set
  if (flex->Decode.sec_subtype)
    cJSON_AddStringToObject(json, "sec_subtype", flex->Decode.sec_subtype);
  if (flex->Decode.opr_category)
    cJSON_AddStringToObject(json, "opr_category", flex->Decode.opr_category);

  // flextime: over-the-air timestamp from FLEX network BIW system info.
  // Structured object with per-component status, age, and received_at.
  // Only included when at least one component has been received.
  if (flex->ota_time.has_date || flex->ota_time.has_time || flex->ota_time.has_tz) {
    unsigned int cur_frame = flex->FIW.cycleno * 128 + flex->FIW.frameno;
    // Expire stale components before emitting
    flextime_expire(&flex->ota_time, cur_frame);
    // Re-check after expiry - might have nothing left
    if (flex->ota_time.has_date || flex->ota_time.has_time || flex->ota_time.has_tz) {
    cJSON *ft = cJSON_CreateObject();

    // Combined timestamp string (only when date+time both available)
    if (flex->ota_time.has_date && flex->ota_time.has_time) {
      double precise_sec;
      if (flex->ota_time.has_tz) {
        unsigned int combined = (flex->ota_time.sec_ext << 3) | flex->ota_time.sec_coarse;
        precise_sec = combined * 0.9375;
      } else {
        precise_sec = flex->ota_time.sec_coarse * 7.5;
      }
      char ota_ts[80];
      int ota_pos = snprintf(ota_ts, sizeof(ota_ts), "%04u-%02u-%02u %02u:%02u:%05.2f",
                             flex->ota_time.year, flex->ota_time.month, flex->ota_time.day,
                             flex->ota_time.hour, flex->ota_time.min, precise_sec);
      if (flex->ota_time.has_tz) {
        int off = flex->ota_time.tz_offset_min;
        const char *dst_str = flex->ota_time.tz_dst ? "" : " DST";
        int abs_off = off < 0 ? -off : off;
        if (abs_off % 60 == 0)
          snprintf(ota_ts + ota_pos, sizeof(ota_ts) - ota_pos, " %+dh%s", off / 60, dst_str);
        else
          snprintf(ota_ts + ota_pos, sizeof(ota_ts) - ota_pos, " %+dh%02dm%s", off / 60, abs_off % 60, dst_str);
      }
      cJSON_AddStringToObject(ft, "timestamp", ota_ts);
      cJSON_AddNumberToObject(ft, "precision_seconds", flex->ota_time.has_tz ? 0.9375 : 7.5);
    }

    // Date component
    if (flex->ota_time.has_date) {
      cJSON *d = cJSON_CreateObject();
      char dval[16];
      snprintf(dval, sizeof(dval), "%04u-%02u-%02u", flex->ota_time.year, flex->ota_time.month, flex->ota_time.day);
      cJSON_AddStringToObject(d, "value", dval);
      int af = (int)flextime_age_frames(cur_frame, flex->ota_time.frame_date);
      cJSON_AddNumberToObject(d, "age_frames", af);
      cJSON_AddNumberToObject(d, "age_seconds", ((int)(af * 187.5)) / 100.0);
      cJSON_AddItemToObject(ft, "date", d);
    }

    // Time component
    if (flex->ota_time.has_time) {
      cJSON *t = cJSON_CreateObject();
      char tval[16];
      snprintf(tval, sizeof(tval), "%02u:%02u", flex->ota_time.hour, flex->ota_time.min);
      cJSON_AddStringToObject(t, "value", tval);
      cJSON_AddNumberToObject(t, "sec_coarse", flex->ota_time.sec_coarse);
      int af = (int)flextime_age_frames(cur_frame, flex->ota_time.frame_time);
      cJSON_AddNumberToObject(t, "age_frames", af);
      cJSON_AddNumberToObject(t, "age_seconds", ((int)(af * 187.5)) / 100.0);
      cJSON_AddItemToObject(ft, "time", t);
    }

    // Timezone component (includes extended seconds)
    if (flex->ota_time.has_tz) {
      cJSON *tz = cJSON_CreateObject();
      char tzval[32];
      int off = flex->ota_time.tz_offset_min;
      const char *dst_str = flex->ota_time.tz_dst ? "" : " DST";
      int abs_off = off < 0 ? -off : off;
      if (abs_off % 60 == 0)
        snprintf(tzval, sizeof(tzval), "%+dh%s", off / 60, dst_str);
      else
        snprintf(tzval, sizeof(tzval), "%+dh%02dm%s", off / 60, abs_off % 60, dst_str);
      cJSON_AddStringToObject(tz, "value", tzval);
      cJSON_AddNumberToObject(tz, "offset_min", flex->ota_time.tz_offset_min);
      cJSON_AddBoolToObject(tz, "dst", flex->ota_time.tz_dst ? 0 : 1);
      cJSON_AddNumberToObject(tz, "zone_code", flex->ota_time.tz_zone);
      cJSON_AddNumberToObject(tz, "sec_ext", flex->ota_time.sec_ext);
      // sec_combined: precise seconds when both time and tz available
      if (flex->ota_time.has_time) {
        unsigned int combined = (flex->ota_time.sec_ext << 3) | flex->ota_time.sec_coarse;
        cJSON_AddNumberToObject(tz, "sec_combined", combined * 0.9375);
      }
      int af = (int)flextime_age_frames(cur_frame, flex->ota_time.frame_tz);
      cJSON_AddNumberToObject(tz, "age_frames", af);
      cJSON_AddNumberToObject(tz, "age_seconds", ((int)(af * 187.5)) / 100.0);
      cJSON_AddItemToObject(ft, "tz", tz);
    }

    cJSON_AddItemToObject(json, "flextime", ft);
    } // end re-check after expiry
  }
  char *out = cJSON_PrintUnformatted(json);
  if (out) {
    fprintf(stdout, "%s\n", out);
    free(out);
  }
  cJSON_Delete(json);
}


static unsigned int count_bits(struct Flex_Next * flex, unsigned int data) {
  if (flex==NULL) return 0;
#ifdef USE_BUILTIN_POPCOUNT
  return __builtin_popcount(data);
#else
  unsigned int n = (data >> 1) & 0x77777777;
  data = data - n;
  n = (n >> 1) & 0x77777777;
  data = data - n;
  n = (n >> 1) & 0x77777777;
  data = data - n;
  data = (data + (data >> 4)) & 0x0f0f0f0f;
  data = data * 0x01010101;
  return data >> 24;
#endif
}



static int bch3121_fix_errors(struct Flex_Next * flex, uint32_t * data_to_fix, char PhaseNo) {
  if (flex==NULL) return -1;

  unsigned int original = *data_to_fix;
  unsigned int data = original;
  
  /*Decode and correct using bch library with even parity check*/
  int result = bch_flex_next_correct(&data);

  /*Decode successful?*/
  if (result >= 0) {
    /*Count the number of fixed errors*/
    if (result > 0) {
      verbprintf(3, "FLEX_NEXT: Phase %c Fixed %i errors @ 0x%08x  (0x%08x -> 0x%08x)\n", PhaseNo, result, original ^ data, original, data );
    }

    /*Write the fixed data back to the caller*/
    *data_to_fix = data;
    return 0;

  } else {
    verbprintf(3, "FLEX_NEXT: Phase %c Data corruption - Unable to fix errors.\n", PhaseNo);
    return 1;
  }
}

static unsigned int flex_sync_check(struct Flex_Next * flex, uint64_t buf) {
  if (flex==NULL) return 0;
  // 64-bit FLEX sync code:
  // AAAA:BBBBBBBB:CCCC
  //
  // Where BBBBBBBB is always 0xA6C6AAAA
  // and AAAA^CCCC is 0xFFFF
  //
  // Specific values of AAAA determine what bps and encoding the
  // packet is beyond the frame information word
  //
  // First we match on the marker field with a hamming distance < 4
  // Then we match on the outer code with a hamming distance < 4

  unsigned int marker =      (buf & 0x0000FFFFFFFF0000ULL) >> 16;
  unsigned short codehigh =  (buf & 0xFFFF000000000000ULL) >> 48;
  unsigned short codelow  = ~(buf & 0x000000000000FFFFULL);

  int retval=0;
  if (count_bits(flex, marker ^ FLEX_SYNC_MARKER) < 4  && count_bits(flex, codelow ^ codehigh) < 4 ) {
    retval=codehigh;
  } else {
    retval=0;
  }

  return retval;
}


static unsigned int flex_sync(struct Flex_Next * flex, unsigned char sym) {
  if (flex==NULL) return 0;
  int retval=0;
  flex->Sync.syncbuf = (flex->Sync.syncbuf << 1) | ((sym < 2)?1:0);

  retval=flex_sync_check(flex, flex->Sync.syncbuf);
  if (retval!=0) {
    flex->Sync.polarity=0;
  } else {
    /*If a positive sync pattern was not found, look for a negative (inverted) one*/
    retval=flex_sync_check(flex, ~flex->Sync.syncbuf);
    if (retval!=0) {
      flex->Sync.polarity=1;
    }
  }

  return retval;
}


static void decode_mode(struct Flex_Next * flex, unsigned int sync_code) {
  if (flex==NULL) return;

  // Sync codes per ARIB STD-43A Table 3.2-5:
  //   A1 (0x870C): 1600bps / 2-level FSK (1600 baud)
  //   A2 (0x7B18): 3200bps / 2-level FSK (3200 baud)
  //   A3 (0xB068): 3200bps / 4-level FSK (1600 baud, 2 phases)
  //   A4 (0xDEA0): 6400bps / 4-level FSK (3200 baud, 4 phases)
  //   A7 (0x4C7C): ReFLEX / 6400bps / 4-level FSK (same as A4)
  struct {
    int sync;
    unsigned int baud;
    unsigned int levels;
  } flex_modes[] = {
    { 0x870C, 1600, 2 },   // A1: 1600bps/2FSK
    { 0xB068, 1600, 4 },   // A3: 3200bps/4FSK (1600 baud symbol rate)
    { 0x7B18, 3200, 2 },   // A2: 3200bps/2FSK
    { 0xDEA0, 3200, 4 },   // A4: 6400bps/4FSK (3200 baud symbol rate)
    { 0x4C7C, 3200, 4 },   // A7: ReFLEX (same physical layer as A4)
    {0,0,0}
  };
  
  int x=0;
  int i=0;
  for (i=0; flex_modes[i].sync!=0; i++) {
    if (count_bits(flex, flex_modes[i].sync ^ sync_code) < 4) {
      flex->Sync.sync   = sync_code;
      flex->Sync.baud   = flex_modes[i].baud;
      flex->Sync.levels = flex_modes[i].levels;
      x = 1;
      break;
    }
  }
  
  if(x==0){
    verbprintf(3, "FLEX_NEXT: Sync Code not found, defaulting to 1600bps 2FSK\n");
  }
}


static void read_2fsk(struct Flex_Next * flex, unsigned int sym, unsigned int * dat) {
  if (flex==NULL) return;
  *dat = (*dat >> 1) | ((sym > 1)?0x80000000:0);
}


static int decode_fiw(struct Flex_Next * flex) {
  if (flex==NULL) return -1;
  unsigned int fiw = flex->FIW.rawdata;
  int decode_error = bch3121_fix_errors(flex, &fiw, 'F');

  if (decode_error) {
    verbprintf(3, "FLEX_NEXT: Unable to decode FIW, too much data corruption\n");
    return 1;
  }

  // The only relevant bits in the FIW word for the purpose of this function
  // are those masked by 0x001FFFFF.
  flex->FIW.checksum = fiw & 0xF;
  flex->FIW.cycleno = (fiw >> 4) & 0xF;
  flex->FIW.frameno = (fiw >> 8) & 0x7F;
  flex->FIW.roaming = (fiw >> 15) & 0x1;
  flex->FIW.repeat  = (fiw >> 16) & 0x1;
  flex->FIW.traffic = (fiw >> 17) & 0xF;
  flex->FIW.fix3 = (fiw >> 15) & 0x3F;  // kept for backward compat

  // Derive number of transmissions from r and t fields
  if (flex->FIW.repeat) {
    unsigned int t10 = flex->FIW.traffic & 0x3;
    unsigned int t32 = (flex->FIW.traffic >> 2) & 0x3;
    flex->FIW.td_collapse = t32;  // collapse cycle for repeat interval
    switch (t10) {
      case 0x01: flex->FIW.num_tx = 2; break;
      case 0x02: flex->FIW.num_tx = 3; break;
      case 0x03: flex->FIW.num_tx = 4; break;
      default:   flex->FIW.num_tx = 1; break; // reserved
    }
  } else {
    flex->FIW.num_tx = 1;
    flex->FIW.td_collapse = 0;
  }

  unsigned int checksum = (fiw & 0xF);
  checksum += ((fiw >> 4) & 0xF);
  checksum += ((fiw >> 8) & 0xF);
  checksum += ((fiw >> 12) & 0xF);
  checksum += ((fiw >> 16) & 0xF);
  checksum += ((fiw >> 20) & 0x01);

  checksum &= 0xF;

  if (checksum == 0xF) {
    int timeseconds = flex->FIW.cycleno*4*60 + flex->FIW.frameno*4*60/128;
    if (flex->FIW.repeat) {
      verbprintf(2, "FLEX_NEXT: FrameInfoWord: cycleno=%02i frameno=%03i roaming=%u repeat=%ux time=%02i:%02i\n",
          flex->FIW.cycleno,
          flex->FIW.frameno,
          flex->FIW.roaming,
          flex->FIW.num_tx,
          timeseconds/60,
          timeseconds%60);
    } else {
      verbprintf(2, "FLEX_NEXT: FrameInfoWord: cycleno=%02i frameno=%03i roaming=%u low_traffic=0x%x time=%02i:%02i\n",
          flex->FIW.cycleno,
          flex->FIW.frameno,
          flex->FIW.roaming,
          flex->FIW.traffic,
          timeseconds/60,
          timeseconds%60);
    }
    // Lets check the FrameNo against the expected group message frames, if we have 'Missed a group message' tell the user and clear the Cap Codes
    for(int g = 0; g < GROUP_BITS ;g++) {
      // Do we have a group message pending for this groupbit?
      if(flex->GroupHandler.GroupFrame[g] >= 0)
      {
        int Reset = 0;
        verbprintf(4, "FLEX_NEXT: GroupBit %i, FrameNo: %i, Cycle No: %i target Cycle No: %i\n", g, flex->GroupHandler.GroupFrame[g], flex->GroupHandler.GroupCycle[g], (int)flex->FIW.cycleno); 
        // Now lets check if its expected in this frame..
        if((int)flex->FIW.cycleno == flex->GroupHandler.GroupCycle[g])
        {
          if(flex->GroupHandler.GroupFrame[g] < (int)flex->FIW.frameno)
          {
            Reset = 1;
          }
        }
                                // Check if we should have sent a group message in the previous cycle 
        else if(flex->FIW.cycleno == 0) 
        {
          if(flex->GroupHandler.GroupCycle[g] == 15)
          {
            Reset = 1;
          }
        }
                                // If we are waiting for the cycle to roll over then move onto the next for loop item 
        else if(flex->FIW.cycleno == 15 && flex->GroupHandler.GroupCycle[g] == 0)
        {
          continue;
        } 
        // Otherwise if the target cycle is less than the current cycle, reset the data
        else if(flex->GroupHandler.GroupCycle[g] < (int)flex->FIW.cycleno)
        {
          Reset = 1;
        }
      

        if(Reset == 1)
        {
                              
                      int endpoint = flex->GroupHandler.GroupCodes[g][CAPCODES_INDEX];
          if(REPORT_GROUP_CODES > 0)
          {
            verbprintf(3,"FLEX_NEXT: Group messages seem to have been missed; Groupbit: %i; Total Capcodes: %i; Clearing Data; Capcodes: ", g, endpoint);
          }
          
                      for(int capIndex = 1; capIndex <= endpoint; capIndex++)
          {
            if(REPORT_GROUP_CODES == 0)
            {
              verbprintf(3,"FLEX_NEXT: Group messages seem to have been missed; Groupbit: %i; Clearing data; Capcode: [%010" PRId64 "]\n", g, flex->GroupHandler.GroupCodes[g][capIndex]);
            }
            else
            {
              if(capIndex > 1)
              {
                verbprintf(3,",");
              }
              verbprintf(3,"[%010" PRId64 "]", flex->GroupHandler.GroupCodes[g][capIndex]);
            }
          }

          if(REPORT_GROUP_CODES > 0)
                                        {
                                                verbprintf(3,"\n");
                                        }

                      // reset the value
                      flex->GroupHandler.GroupCodes[g][CAPCODES_INDEX] = 0;
                      flex->GroupHandler.GroupFrame[g] = -1;
                      flex->GroupHandler.GroupCycle[g] = -1;
        }
      }
                }
    return 0;
  } else {
    verbprintf(3, "FLEX_NEXT: Bad Checksum 0x%x\n", checksum);

    return 1;
  }
}


/* Add a character to ALN messages, but avoid buffer overflows and special characters */
static unsigned int add_ch(unsigned char ch, unsigned char* buf, unsigned int idx) {
    // avoid buffer overflow that has been happening
    if (idx >= MAX_ALN) {
        verbprintf(3, "FLEX_NEXT: idx %u >= MAX_ALN %u\n", idx, MAX_ALN);
        return 0;
    }
    // TODO sanitize % or you will have uncontrolled format string vuln
    // Originally, this only avoided storing ETX (end of text, 0x03).
    // At minimum you'll also want to avoid storing NULL (str term, 0x00),
    // otherwise verbprintf will truncate the message.
    //   ex: if (ch != 0x03 && ch != 0x00) { buf[idx] = ch; return 1; }
    // But while we are here, make it print friendly and get it onto a single line
    //   * remove awkward ctrl chars (del, bs, bell, vertical tab, etc)
    //   * encode valuable ctrl chars (new line/line feed, carriage ret, tab)
    // NOTE: if you post process FLEX ALN output by sed/grep/awk etc on non-printables
    //   then double check this doesn't mess with your pipeline
    if (ch == 0x09 && idx < (MAX_ALN - 2)) {  // '\t'
        buf[idx] = '\\';
        buf[idx + 1] = 't';
        return 2;
    }
    if (ch == 0x0a && idx < (MAX_ALN - 2)) {  // '\n'
        buf[idx] = '\\';
        buf[idx + 1] = 'n';
        return 2;
    }
    if (ch == 0x0d && idx < (MAX_ALN - 2)) {  // '\r'
        buf[idx] = '\\';
        buf[idx + 1] = 'r';
        return 2;
    }
    // unixinput.c::_verbprintf uses this output as a format string
    // which introduces an uncontrolled format string vulnerability
    // and also, generally, risks stack corruption
    if (ch == '%') {
        if (idx < (MAX_ALN - 2)) {
            buf[idx] = '%';
            buf[idx + 1] = '%';
            return 2;
        }
        return 0;
    }
    // only store ASCII printable
    if (ch >= 32 && ch <= 126) {
        buf[idx] = ch;
        return 1;
    }
    // if you want all non-printables, show as hex, but also make MAX_ALN 1024
    /* if (idx < (MAX_ALN - 4)) {
        sprintf(buf + idx, "\\x%02x", ch);
        return 4;
    }*/
    return 0;
}


/* ---------------------------------------------------------------------- */
/* Fragment reassembly helpers                                             */
/* ---------------------------------------------------------------------- */

// Find an existing fragment slot for a capcode/type/msg_n, or -1 if not found.
// msg_n identifies the fragment stream (Section 3.10.1.3 bits 13-18).
static int frag_find(struct Flex_Next * flex, int64_t capcode, int type, int msg_n) {
  int i;
  for (i = 0; i < FLEX_FRAG_MAX_SLOTS; i++) {
    if (flex->FragStore.slots[i].active &&
        flex->FragStore.slots[i].capcode == capcode &&
        flex->FragStore.slots[i].type == type &&
        flex->FragStore.slots[i].msg_n == msg_n)
      return i;
  }
  return -1;
}

// Allocate a new fragment slot, evicting the oldest if full
static int frag_alloc(struct Flex_Next * flex, int64_t capcode, int type, int msg_n, unsigned int frame) {
  int i;
  // Find a free slot
  for (i = 0; i < FLEX_FRAG_MAX_SLOTS; i++) {
    if (!flex->FragStore.slots[i].active) {
      flex->FragStore.slots[i].active = 1;
      flex->FragStore.slots[i].capcode = capcode;
      flex->FragStore.slots[i].type = type;
      flex->FragStore.slots[i].msg_n = msg_n;
      flex->FragStore.slots[i].msg_r = -1;
      flex->FragStore.slots[i].msg_m = -1;
      flex->FragStore.slots[i].data_len = 0;
      flex->FragStore.slots[i].frame_received = frame;
      flex->FragStore.slots[i].sig_sum = 0;
      flex->FragStore.slots[i].rx_sig = 0;
      flex->FragStore.slots[i].sig_valid = 0;
      flex->FragStore.slots[i].k_fail = 0;
      flex->FragStore.slots[i].expected_f = 0;  // after F=11 (initial), next expected is F=00
      flex->FragStore.slots[i].frag_index = 0;
      flex->FragStore.slots[i].f_mismatch = 0;
      return i;
    }
  }
  // Evict oldest
  {
    int oldest = 0;
    unsigned int oldest_frame = flex->FragStore.slots[0].frame_received;
    for (i = 1; i < FLEX_FRAG_MAX_SLOTS; i++) {
      if (flex->FragStore.slots[i].frame_received < oldest_frame) {
        oldest = i;
        oldest_frame = flex->FragStore.slots[i].frame_received;
      }
    }
    verbprintf(3, "FLEX_NEXT: Fragment store full, evicting slot %d (cap=%" PRId64 ")\n", oldest, flex->FragStore.slots[oldest].capcode);
    flex->FragStore.slots[oldest].active = 1;
    flex->FragStore.slots[oldest].capcode = capcode;
    flex->FragStore.slots[oldest].type = type;
    flex->FragStore.slots[oldest].msg_n = msg_n;
    flex->FragStore.slots[oldest].msg_r = -1;
    flex->FragStore.slots[oldest].msg_m = -1;
    flex->FragStore.slots[oldest].data_len = 0;
    flex->FragStore.slots[oldest].frame_received = frame;
    flex->FragStore.slots[oldest].sig_sum = 0;
    flex->FragStore.slots[oldest].rx_sig = 0;
    flex->FragStore.slots[oldest].sig_valid = 0;
    flex->FragStore.slots[oldest].k_fail = 0;
    flex->FragStore.slots[oldest].expected_f = 0;
    flex->FragStore.slots[oldest].frag_index = 0;
    flex->FragStore.slots[oldest].f_mismatch = 0;
    return oldest;
  }
}

// Append data to a fragment slot
static void frag_append(struct Flex_Next * flex, int slot, const unsigned char *data, unsigned int len) {
  unsigned int space = FLEX_FRAG_MAX_LEN - flex->FragStore.slots[slot].data_len;
  if (len > space) len = space;
  if (len > 0) {
    memcpy(flex->FragStore.slots[slot].data + flex->FragStore.slots[slot].data_len, data, len);
    flex->FragStore.slots[slot].data_len += len;
  }
}

// Release a fragment slot
static void frag_release(struct Flex_Next * flex, int slot) {
  flex->FragStore.slots[slot].active = 0;
  flex->FragStore.slots[slot].data_len = 0;
  flex->FragStore.slots[slot].msg_n = -1;
  flex->FragStore.slots[slot].msg_r = -1;
  flex->FragStore.slots[slot].msg_m = -1;
  flex->FragStore.slots[slot].sig_sum = 0;
  flex->FragStore.slots[slot].rx_sig = 0;
  flex->FragStore.slots[slot].sig_valid = 0;
  flex->FragStore.slots[slot].k_fail = 0;
  flex->FragStore.slots[slot].expected_f = 0;
  flex->FragStore.slots[slot].frag_index = 0;
  flex->FragStore.slots[slot].f_mismatch = 0;
}

// Expire old fragment slots
static void frag_expire(struct Flex_Next * flex, unsigned int current_frame) {
  int i;
  for (i = 0; i < FLEX_FRAG_MAX_SLOTS; i++) {
    if (flex->FragStore.slots[i].active) {
      /* abs_frame is cycleno*128+frameno and wraps at 2048 (4-bit cycle, 7-bit frame).
         Mask the subtraction so a wrap-around gives the correct forward distance. */
      unsigned int age = (current_frame - flex->FragStore.slots[i].frame_received) & 0x7FF;
      if (age > FLEX_FRAG_TIMEOUT) {
        verbprintf(3, "FLEX_NEXT: Fragment expired slot %d cap=%" PRId64 " age=%u\n", i, flex->FragStore.slots[i].capcode, age);
        frag_release(flex, i);
      }
    }
  }
}

/* ---------------------------------------------------------------------- */
/* Message deduplication helpers                                           */
/* ---------------------------------------------------------------------- */

// Check a complete (K) message against the dedup cache.
// Returns:
//   0 = new message, not seen before. Cached and caller should decode+output.
//   1 = exact duplicate (all clean words match). Caller should suppress.
//   2 = improved retransmission (some previously-errored words now clean).
//       Cache updated with merged words. Caller should re-decode from
//       the cache entry's words[] and output the improved version.
//
// The cache entry index is written to *out_slot on return 2 so the
// caller can access the merged words.
//
// word_src/err_src point into the phase's phaseptr/bch_err arrays.
// word_off is the index of the first word to store (header word).
// n_words is the total number of words (1 header + body_len body words).
static int dedup_check_words(struct Flex_Next * flex, int64_t capcode, int type,
                             int msg_n, const uint32_t *word_src, const int *err_src,
                             unsigned int word_off, unsigned int n_words,
                             unsigned int hdr_off_in_msg, unsigned int mw1_off_in_msg,
                             unsigned int body_len, int *out_slot) {
  unsigned int frame = (flex->FIW.cycleno * 128 + flex->FIW.frameno);
  int i;

  if (n_words > FLEX_DEDUP_MAX_WORDS)
    n_words = FLEX_DEDUP_MAX_WORDS;

  // Expire old entries and search for a match
  for (i = 0; i < FLEX_DEDUP_SLOTS; i++) {
    if (!flex->DedupStore.entries[i].active)
      continue;
    unsigned int age = (frame - flex->DedupStore.entries[i].frame_seen) & 0x7FF;
    if (age > FLEX_DEDUP_TIMEOUT) {
      flex->DedupStore.entries[i].active = 0;
      continue;
    }
    if (flex->DedupStore.entries[i].capcode != capcode ||
        flex->DedupStore.entries[i].type != type ||
        flex->DedupStore.entries[i].msg_n != msg_n ||
        flex->DedupStore.entries[i].word_count != n_words)
      continue;

    // Same key and word count - compare at the word level.
    // For each word position:
    //   both clean, same value  -> match
    //   both clean, diff value  -> different message, not a dup
    //   cached clean, new error -> still a match (new is worse)
    //   cached error, new clean -> improvement, merge
    //   both error              -> match (both unknown)
    int all_match = 1;
    int improved = 0;
    unsigned int w;
    for (w = 0; w < n_words; w++) {
      int cached_err = flex->DedupStore.entries[i].errs[w];
      int new_err = err_src[word_off + w];
      if (!cached_err && !new_err) {
        // Both clean - must have same value
        if (flex->DedupStore.entries[i].words[w] != word_src[word_off + w]) {
          all_match = 0;
          break;
        }
      } else if (cached_err && !new_err) {
        // Cached was bad, new is clean - improvement
        improved = 1;
      }
      // Other cases (cached clean + new error, both error): compatible
    }

    if (!all_match)
      continue;

    if (!improved) {
      // Exact duplicate or no improvement
      verbprintf(3, "FLEX_NEXT: Dedup suppressed cap=%" PRId64 " type=%d N=%d words=%u\n",
                 capcode, type, msg_n, n_words);
      return 1;
    }

    // Merge improved words into cache
    for (w = 0; w < n_words; w++) {
      if (flex->DedupStore.entries[i].errs[w] && !err_src[word_off + w]) {
        flex->DedupStore.entries[i].words[w] = word_src[word_off + w];
        flex->DedupStore.entries[i].errs[w] = 0;
      }
    }
    flex->DedupStore.entries[i].frame_seen = frame;
    *out_slot = i;
    verbprintf(3, "FLEX_NEXT: Dedup merged improved words for cap=%" PRId64 " type=%d N=%d\n",
               capcode, type, msg_n);
    return 2;
  }

  // Not found - cache it
  int slot = (int)flex->DedupStore.next_slot;
  flex->DedupStore.entries[slot].active = 1;
  flex->DedupStore.entries[slot].capcode = capcode;
  flex->DedupStore.entries[slot].type = type;
  flex->DedupStore.entries[slot].msg_n = msg_n;
  flex->DedupStore.entries[slot].hdr_off = hdr_off_in_msg;
  flex->DedupStore.entries[slot].mw1_off = mw1_off_in_msg;
  flex->DedupStore.entries[slot].word_count = n_words;
  flex->DedupStore.entries[slot].body_len = body_len;
  flex->DedupStore.entries[slot].frame_seen = frame;
  for (i = 0; i < (int)n_words; i++) {
    flex->DedupStore.entries[slot].words[i] = word_src[word_off + i];
    flex->DedupStore.entries[slot].errs[i] = err_src[word_off + i];
  }
  flex->DedupStore.next_slot = (slot + 1) % FLEX_DEDUP_SLOTS;
  *out_slot = slot;
  return 0;
}


static void parse_alphanumeric(struct Flex_Next * flex, unsigned int * phaseptr, int * bch_err, unsigned int hdr_idx, unsigned int mw1, unsigned int len, int frag, int cont, int msg_n, int msg_r, int msg_m, int dedup_flag, int flex_groupmessage, int flex_groupbit) {
        if (flex==NULL) return;

        // Header word is at mw1-1 (short addr) or in the vector field (long addr).
        // The caller already extracted frag (F) and cont (C) from the header.
        // Header layout per Section 3.10.1.3:
        //   bits 0-9:   K (10-bit fragment checksum)
        //   bit  10:    C (continuation: 1=more fragments, 0=last/only)
        //   bits 11-12: F (fragment number: 11=initial, 00/01/10=continuation)
        //   bits 13-18: N (message number, 6 bits, identifies fragment stream)
        //   bit  19:    R (retrieval flag, initial only) / U0 (continuation)
        //   bit  20:    M (mail drop flag, initial only) / V0 (continuation)

        char frag_flag = '?';
        if (cont == 0 && frag == 3) frag_flag = 'K'; // complete, ready to send
        if (cont == 0 && frag != 3) frag_flag = 'C'; // last fragment, completes the message
        if (cont == 1             ) frag_flag = 'F'; // fragment, more coming
        int  is_initial = (frag == 0x03);  // F=11 means initial/only fragment
        // Frag flags output is deferred to each branch (F/C/K) so that
        // reassembled messages can carry R/M from the initial fragment.

        unsigned char message[MAX_ALN];
        memset(message, '\0', MAX_ALN);
        int  currentChar = 0;

        // K checksum verification (Section 3.10.1.3):
        // 1's complement of binary sum of all message words in 3 groups:
        //   group1 = bits 0-7, group2 = bits 8-15, group3 = bits 16-20
        // K field (bits 0-9 of header) is zeroed before summing.
        // Covers: header word (at hdr_idx) + all content words (mw1..mw1+len-1).
        int k_fail = 0;
        {
          uint32_t k_sum = 0;
          int k_ok = 1;
          unsigned int ki;
          // Include header word with K field zeroed
          if (hdr_idx < PHASE_WORDS && !bch_err[hdr_idx]) {
            uint32_t dw = phaseptr[hdr_idx] & ~0x3FFu;
            k_sum += dw & 0xFFu;
            k_sum += (dw >> 8) & 0xFFu;
            k_sum += (dw >> 16) & 0x1Fu;
          } else {
            k_ok = 0;
          }
          // Include content words
          for (ki = 0; ki < len; ki++) {
            unsigned int wi = mw1 + ki;
            if (wi >= PHASE_WORDS || bch_err[wi]) {
              k_ok = 0;
              continue;
            }
            uint32_t dw = phaseptr[wi];
            k_sum += dw & 0xFFu;
            k_sum += (dw >> 8) & 0xFFu;
            k_sum += (dw >> 16) & 0x1Fu;
          }
          if (k_ok && hdr_idx < PHASE_WORDS) {
            uint32_t rx_k = phaseptr[hdr_idx] & 0x3FFu;
            uint32_t expected_k = (~k_sum) & 0x3FFu;
            if (rx_k != expected_k) {
              verbprintf(3, "FLEX_NEXT: Alpha K checksum FAIL: rx=0x%03X expected=0x%03X\n", rx_k, expected_k);
              k_fail = 1;
            }
          } else {
            /* BCH errors prevented K verification - treat as fail */
            k_fail = 1;
          }
        }

        // Extract 7-bit ASCII characters, 3 per word.
        //
        // By the time we get here, the caller (decode_phase) has already
        // adjusted mw1 and len:
        //   Short addr: mw1 = first content word (past header), len = content words
        //   Long addr:  mw1 = MF start (body[1]), len = MF words (body[0] is in Vy)
        //
        // Initial fragment (F=11): first content word (phaseptr[mw1]) has
        //   bits 0-6 = Signature S, bits 7-13 = char1, bits 14-20 = char2
        // Continuation fragments (F!=11): all three 7-bit slots are characters.
        //
        // Signature S (Section 3.10.1.3): 7-bit, 1's complement of binary sum
        // of all 7-bit character slots (excluding signature itself).
        // ETX (0x03) fill characters are excluded from the sum per spec.
        // (Standard Fragmentation mode - Enhanced Fragmentation also
        // excludes NUL, but that's not implemented.)
        uint32_t sig_sum = 0;
        uint32_t rx_sig = 0;
        int sig_valid = 1;

        for (unsigned int i = 0; i < len; i++) {
            if ((mw1 + i) >= PHASE_WORDS || bch_err[mw1 + i]) {
                currentChar += add_ch('?', message, currentChar);
                currentChar += add_ch('?', message, currentChar);
                currentChar += add_ch('?', message, currentChar);
                sig_valid = 0;
                continue;
            }
            unsigned int dw = phaseptr[mw1 + i];
            unsigned char ch;

            if (i == 0 && is_initial) {
                // First content word on initial fragment:
                // bits 0-6 = signature (extract but don't output)
                // bits 7-13 = char1, bits 14-20 = char2
                rx_sig = dw & 0x7Fu;
                ch = (dw >> 7) & 0x7Fu;
                if (ch != 0x03) sig_sum += ch;
                currentChar += add_ch(ch, message, currentChar);
                ch = (dw >> 14) & 0x7Fu;
                if (ch != 0x03) sig_sum += ch;
                currentChar += add_ch(ch, message, currentChar);
            } else {
                // Normal word or continuation fragment: 3 chars per word
                ch = dw & 0x7Fu;
                if (ch != 0x03) sig_sum += ch;
                currentChar += add_ch(ch, message, currentChar);
                ch = (dw >> 7) & 0x7Fu;
                if (ch != 0x03) sig_sum += ch;
                currentChar += add_ch(ch, message, currentChar);
                ch = (dw >> 14) & 0x7Fu;
                if (ch != 0x03) sig_sum += ch;
                currentChar += add_ch(ch, message, currentChar);
            }
        }
        message[currentChar] = '\0';

        // Verify signature on complete (non-fragmented) messages
        int sig_fail = 0;
        if (is_initial && cont == 0 && len > 0) {
          if (sig_valid) {
            uint32_t expected_sig = (~sig_sum) & 0x7Fu;
            if (rx_sig != expected_sig) {
              verbprintf(3, "FLEX_NEXT: Alpha signature FAIL: rx=0x%02X expected=0x%02X\n", rx_sig, expected_sig);
              sig_fail = 1;
            }
          } else {
            /* BCH errors prevented signature verification - treat as fail */
            sig_fail = 1;
          }
        }

        // Fragment reassembly
        if (frag_flag == 'F') {
          // First/middle fragment: buffer it
          unsigned int abs_frame = flex->FIW.cycleno * 128 + flex->FIW.frameno;
          int slot = frag_find(flex, flex->Decode.capcode, flex->Decode.type, msg_n);
          if (slot >= 0 && is_initial) {
            /* New initial fragment for same capcode: emit old partial, then release */
            if (flex->FragStore.slots[slot].data_len > 0) {
              if (json_mode) {
                flex_next_json_emit(flex, flex->Decode.phase,
                                    flex->FragStore.slots[slot].capcode,
                                    flex->Decode.addr_type, 0,
                                    flex->FragStore.slots[slot].type,
                                    "ALN", "reassembled_partial",
                                    flex->FragStore.slots[slot].msg_n, -1, -1,
                                    flex->FragStore.slots[slot].k_fail ? 0 : -1, -1,
                                    (const char *)flex->FragStore.slots[slot].data,
                                    NULL, 0, NULL);
              } else {
                verbprintf(0, "FLEX_NEXT|%u/%u|%02u.%03u.%c|%010" PRId64 "|LS|5|ALN|0.0.C.N%d|%.*s\n",
                           flex->Sync.baud, flex->Sync.levels,
                           flex->FIW.cycleno, flex->FIW.frameno, flex->Decode.phase,
                           flex->FragStore.slots[slot].capcode,
                           flex->FragStore.slots[slot].msg_n,
                           (int)flex->FragStore.slots[slot].data_len,
                           flex->FragStore.slots[slot].data);
              }
            }
            frag_release(flex, slot);
            slot = -1;
          }
          if (slot < 0)
            slot = frag_alloc(flex, flex->Decode.capcode, flex->Decode.type, msg_n, abs_frame);
          if (slot >= 0) {
            frag_append(flex, slot, message, (unsigned int)currentChar);
            if (is_initial) {
              flex->FragStore.slots[slot].rx_sig = rx_sig;
              flex->FragStore.slots[slot].sig_sum = sig_sum;
              flex->FragStore.slots[slot].sig_valid = sig_valid;
              flex->FragStore.slots[slot].k_fail = k_fail;
              flex->FragStore.slots[slot].msg_r = msg_r;
              flex->FragStore.slots[slot].msg_m = msg_m;
              // F=11 (initial): next expected is F=00
              flex->FragStore.slots[slot].expected_f = 0;
              flex->FragStore.slots[slot].frag_index = 0;
            } else {
              flex->FragStore.slots[slot].sig_sum += sig_sum;
              if (!sig_valid) flex->FragStore.slots[slot].sig_valid = 0;
              if (k_fail) flex->FragStore.slots[slot].k_fail = 1;
              // Check F sequence: expected_f should match received frag
              if (frag != flex->FragStore.slots[slot].expected_f) {
                verbprintf(3, "FLEX_NEXT: F sequence mismatch for cap %" PRId64 ": expected F=%d got F=%d (missing fragment?)\n",
                           flex->Decode.capcode, flex->FragStore.slots[slot].expected_f, frag);
                flex->FragStore.slots[slot].f_mismatch = 1;
              }
              // Advance expected_f: mod 3 cycle (0->1->2->0->1->2...)
              flex->FragStore.slots[slot].expected_f = (frag + 1) % 3;
              flex->FragStore.slots[slot].frag_index++;
            }
          }
          // Output complete level-0 line FIRST (before any debug)
          if (!json_mode) {
            int out_r = is_initial ? msg_r : (slot >= 0 ? flex->FragStore.slots[slot].msg_r : -1);
            int out_m = is_initial ? msg_m : (slot >= 0 ? flex->FragStore.slots[slot].msg_m : -1);
            const char *k_str = k_fail ? ".K-" : "";
            if (out_r >= 0)
              verbprintf(0, "%1d.%1d.%c.N%d.R%d%s%s|%s", frag, cont, frag_flag, msg_n, out_r, out_m ? ".M" : "", k_str, message);
            else
              verbprintf(0, "%1d.%1d.%c.N%d%s|%s", frag, cont, frag_flag, msg_n, k_str, message);
          } else {
            int out_r = is_initial ? msg_r : (slot >= 0 ? flex->FragStore.slots[slot].msg_r : -1);
            int out_m = is_initial ? msg_m : (slot >= 0 ? flex->FragStore.slots[slot].msg_m : -1);
            cJSON *extra = cJSON_CreateObject();
            cJSON_AddNumberToObject(extra, "frag_seq", frag);
            if (slot >= 0) {
              cJSON_AddNumberToObject(extra, "frag_index", flex->FragStore.slots[slot].frag_index);
              cJSON_AddBoolToObject(extra, "frag_seq_error", flex->FragStore.slots[slot].f_mismatch ? 1 : 0);
            }
            cJSON_AddNumberToObject(extra, "frag_words", (int)len);
            cJSON_AddNumberToObject(extra, "frag_chars", currentChar);
            flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode,
                                flex->Decode.addr_type, flex_groupmessage, flex->Decode.type,
                                "ALN", is_initial ? "fragment_start" : "fragment_mid",
                                msg_n, out_r, out_m, k_fail ? 0 : -1, -1,
                                (const char *)message, NULL, 0, extra);
          }
          // Debug logging AFTER the level-0 line is complete
          if (is_initial)
            verbprintf(3, "FLEX_NEXT: Frag F initial: rx_sig=0x%02X sig_sum=0x%04X chars=%d len=%u\n",
                       rx_sig, sig_sum, currentChar, len);
          else
            verbprintf(3, "FLEX_NEXT: Frag F cont: sig_sum=0x%04X chars=%d len=%u\n",
                       sig_sum, currentChar, len);
          if (slot >= 0)
            verbprintf(3, "FLEX_NEXT: Buffered fragment for cap %" PRId64 " (%d bytes in slot %d)\n",
                       flex->Decode.capcode, flex->FragStore.slots[slot].data_len, slot);
          return;
        }

        if (frag_flag == 'C') {
          // Continuation/last fragment: combine with buffered F fragments
          int slot = frag_find(flex, flex->Decode.capcode, flex->Decode.type, msg_n);
          if (slot >= 0 && flex->FragStore.slots[slot].data_len > 0) {
            // Validate signature across all fragments
            int reassembled_sig_fail = 0;
            if (flex->FragStore.slots[slot].sig_valid && sig_valid) {
              uint32_t total_sig_sum = flex->FragStore.slots[slot].sig_sum + sig_sum;
              uint32_t expected_sig = (~total_sig_sum) & 0x7Fu;
              if (flex->FragStore.slots[slot].rx_sig != expected_sig)
                reassembled_sig_fail = 1;
            } else {
              /* BCH errors prevented signature verification - treat as fail */
              reassembled_sig_fail = 1;
            }
            // Check F sequence on final fragment
            if (frag != flex->FragStore.slots[slot].expected_f) {
              verbprintf(3, "FLEX_NEXT: F sequence mismatch on final frag for cap %" PRId64 ": expected F=%d got F=%d\n",
                         flex->Decode.capcode, flex->FragStore.slots[slot].expected_f, frag);
              flex->FragStore.slots[slot].f_mismatch = 1;
            }
            int total_frags = flex->FragStore.slots[slot].frag_index + 2; // +1 for initial, +1 for this final
            int total_chars = (int)flex->FragStore.slots[slot].data_len + currentChar;
            // Output complete level-0 line atomically (message + group capcodes in prefix)
            if (!json_mode) {
              int out_r = flex->FragStore.slots[slot].msg_r;
              int out_m = flex->FragStore.slots[slot].msg_m;
              const char *k_str = k_fail ? ".K-" : "";
              const char *sig_str = reassembled_sig_fail ? ".SIGN-" : "";
              if (out_r >= 0)
                verbprintf(0, "%1d.%1d.%c.N%d.R%d%s%s%s|%.*s%s", frag, cont, frag_flag, msg_n, out_r, out_m ? ".M" : "", k_str, sig_str,
                           (int)flex->FragStore.slots[slot].data_len, flex->FragStore.slots[slot].data, message);
              else
                verbprintf(0, "%1d.%1d.%c.N%d%s%s|%.*s%s", frag, cont, frag_flag, msg_n, k_str, sig_str,
                           (int)flex->FragStore.slots[slot].data_len, flex->FragStore.slots[slot].data, message);
            } else {
              char reassembled[MAX_ALN * 2];
              snprintf(reassembled, sizeof(reassembled), "%.*s%s",
                       (int)flex->FragStore.slots[slot].data_len,
                       flex->FragStore.slots[slot].data, message);
              int out_r = flex->FragStore.slots[slot].msg_r;
              int out_m = flex->FragStore.slots[slot].msg_m;
              cJSON *extra = cJSON_CreateObject();
              cJSON_AddNumberToObject(extra, "total_fragments", total_frags);
              cJSON_AddNumberToObject(extra, "total_chars", total_chars);
              cJSON_AddBoolToObject(extra, "frag_seq_error", flex->FragStore.slots[slot].f_mismatch ? 1 : 0);
              int combined_k_fail = k_fail || flex->FragStore.slots[slot].k_fail;
              flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode,
                                  flex->Decode.addr_type, flex_groupmessage, flex->Decode.type,
                                  "ALN", "reassembled",
                                  msg_n, out_r, out_m,
                                  combined_k_fail ? 0 : 1, reassembled_sig_fail ? 0 : 1,
                                  reassembled,
                                  flex_groupmessage ? &flex->GroupHandler.GroupCodes[flex_groupbit][1] : NULL,
                                  flex_groupmessage ? (int)flex->GroupHandler.GroupCodes[flex_groupbit][CAPCODES_INDEX] : 0, extra);
            }
            // Debug logging AFTER level-0 line
            verbprintf(3, "FLEX_NEXT: Reassembled %u + %d bytes for cap %" PRId64 "\n",
                       flex->FragStore.slots[slot].data_len, currentChar, flex->Decode.capcode);
            frag_release(flex, slot);
            if (!json_mode) goto group_output;
            if (flex_groupmessage) {
              flex->GroupHandler.GroupCodes[flex_groupbit][CAPCODES_INDEX] = 0;
              flex->GroupHandler.GroupFrame[flex_groupbit] = -1;
              flex->GroupHandler.GroupCycle[flex_groupbit] = -1;
            }
            return;
          }
          // No buffered fragment found, output what we have
          if (!json_mode) {
            verbprintf(0, "%1d.%1d.%c.N%d%s|%s", frag, cont, frag_flag, msg_n, k_fail ? ".K-" : "", message);
          } else {
            flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode,
                                flex->Decode.addr_type, flex_groupmessage, flex->Decode.type,
                                "ALN", "fragment_end",
                                msg_n, -1, -1, k_fail ? 0 : -1, -1,
                                (const char *)message, NULL, 0, NULL);
          }
          if (!json_mode) goto group_output;
          if (flex_groupmessage) {
            flex->GroupHandler.GroupCodes[flex_groupbit][CAPCODES_INDEX] = 0;
            flex->GroupHandler.GroupFrame[flex_groupbit] = -1;
            flex->GroupHandler.GroupCycle[flex_groupbit] = -1;
          }
          return;
        }

        // K (complete) or unknown: output directly
        if (!json_mode) {
          const char *dup_str = (dedup_flag == 2) ? ".DUP+" : (dedup_flag == 1) ? ".DUP" : "";
          const char *k_str = k_fail ? ".K-" : "";
          const char *sig_str = sig_fail ? ".SIGN-" : "";
          verbprintf(0, "%1d.%1d.%c.N%d.R%d%s%s%s%s|%s", frag, cont, frag_flag, msg_n, msg_r, msg_m ? ".M" : "", k_str, sig_str, dup_str, message);
        } else {
          flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode,
                              flex->Decode.addr_type, flex_groupmessage, flex->Decode.type,
                              "ALN", "complete",
                              msg_n, msg_r, msg_m,
                              k_fail ? 0 : 1, sig_fail ? 0 : 1,
                              (const char *)message,
                              flex_groupmessage ? &flex->GroupHandler.GroupCodes[flex_groupbit][1] : NULL,
                              flex_groupmessage ? (int)flex->GroupHandler.GroupCodes[flex_groupbit][CAPCODES_INDEX] : 0, NULL);
        }

group_output:
// Implemented bierviltje code from ticket: https://github.com/EliasOenal/multimon-ng/issues/123# 
        if(flex_groupmessage == 1) {
                int endpoint = flex->GroupHandler.GroupCodes[flex_groupbit][CAPCODES_INDEX];
                // Debug logging AFTER the level-0 line is complete
                for(int g = 1; g <= endpoint;g++)
                {
                        verbprintf(1, "FLEX Group message output: Groupbit: %i Total Capcodes; %i; index %i; Capcode: [%010" PRId64 "]\n", flex_groupbit, endpoint, g, flex->GroupHandler.GroupCodes[flex_groupbit][g]);
                }

                // reset the value
                flex->GroupHandler.GroupCodes[flex_groupbit][CAPCODES_INDEX] = 0;
                flex->GroupHandler.GroupFrame[flex_groupbit] = -1;
                flex->GroupHandler.GroupCycle[flex_groupbit] = -1;
        } 
}

static void parse_numeric(struct Flex_Next * flex, unsigned int * phaseptr, int * bch_err, int j, int frag, int cont, int msg_n, int msg_r, int msg_m, int dedup_flag) {
  if (flex==NULL) return;
  // BCD table per ARIB STD-43A Section 3.10.1.1:
  //   0-9 = digits, A = spare('.'), B = urgency('U'),
  //   C = space(' '), D = hyphen('-'), E = ']', F = '['
  unsigned const char flex_bcd[17] = "0123456789.U -][";

  // Frag flags output is deferred until after K checksum verification.
  int num_k_fail = 0;

  // Numeric vector layout (Section 3.9.5):
  //   bits 7-13:  b (message start word)
  //   bits 14-16: n (word count - 1, 3 bits, max 7 = 8 words)
  //   bits 17-20: K3-K0 (lower 4 bits of 6-bit K checksum)
  int w1 = phaseptr[j] >> 7;
  int w2 = w1 >> 7;
  w1 = w1 & 0x7f;
  w2 = (w2 & 0x07) + w1;  // w2 = start + word_count - 1

  // Validate w1 and w2 against frame bounds
  if (w1 >= PHASE_WORDS || w2 >= PHASE_WORDS) {
    verbprintf(3, "FLEX_NEXT: Numeric w1=%d w2=%d out of frame bounds (%d), skipping\n", w1, w2, PHASE_WORDS);
    return;
  }

  // K3-K0 from vector word
  unsigned int vec_k30 = (phaseptr[j] >> 17) & 0x0F;

  // Get first dataword from message field or from second
  // vector word if long address
  int dw;
  int dw_bad = 0;
  if(!flex->Decode.long_address) {
    dw_bad = (w1 < PHASE_WORDS && bch_err[w1]);
    dw = phaseptr[w1];
    w1++;
    w2++;
  } else {
    dw_bad = ((j+1) < PHASE_WORDS && bch_err[j+1]);
    dw = phaseptr[j+1];
  }

  // For numbered numeric (V=111), extract header fields before BCD digits
  int num_special_format = -1;  // S flag: 0=standard, 1=ID-ROM display (-1=N/A)
  if(flex->Decode.type == FLEX_PAGETYPE_NUMBERED_NUMERIC && !dw_bad) {
    // bits 0-1: K5K4 (part of checksum)
    // bits 2-7: N (message number, 6 bits)
    // bit 8:    R (retrieval: 1=new, 0=retransmit)
    // bit 9:    S (special format: 0=standard, 1=ID-ROM)
    unsigned int nnum_n = (dw >> 2) & 0x3F;
    unsigned int nnum_r = (dw >> 8) & 0x01;
    num_special_format = (dw >> 9) & 0x01;
    verbprintf(3, "FLEX_NEXT: Numbered numeric: N=%u R=%u S=%u\n", nnum_n, nnum_r, num_special_format);
  }

  // K checksum verification (Section 3.10.1.1.1):
  // K3-K0 from vector word bits 17-20, K5K4 from body word 0 bits 0-1.
  // Recompute: sum 3 groups per word (bits 0-7, 8-15, 16-20),
  // with K5K4 bits zeroed in the body word that contains them.
  // Fold: take lower 8 bits, add (low6) + (high2), 1's complement lower 6.
  {
    uint32_t k_sum = 0;
    int k_ok = 1;
    int ki;
    // body0 is the first body word: j+1 for long addr, w1-1 for short addr
    int body0 = flex->Decode.long_address ? (j + 1) : (w1 - 1);

    // Include body0 with K5K4 zeroed
    if (body0 >= 0 && body0 < PHASE_WORDS && !bch_err[body0]) {
      uint32_t dw = phaseptr[body0] & ~0x03u;  // zero K5K4 (bits 0-1)
      k_sum += dw & 0xFFu;
      k_sum += (dw >> 8) & 0xFFu;
      k_sum += (dw >> 16) & 0x1Fu;
    } else {
      k_ok = 0;
    }

    // Include remaining body words (w1 to w2-1).
    // For short addr, body0 is at w1-1 (already summed above), data at w1..w2-1.
    // For long addr, body0 is at j+1 (Vy, already summed above), MF at w1..w2-1.
    for (ki = w1; ki < w2 && ki < PHASE_WORDS; ki++) {
      if (bch_err[ki]) { k_ok = 0; continue; }
      k_sum += phaseptr[ki] & 0xFFu;
      k_sum += (phaseptr[ki] >> 8) & 0xFFu;
      k_sum += (phaseptr[ki] >> 16) & 0x1Fu;
    }

    if (k_ok && !dw_bad) {
      k_sum &= 0xFFu;
      uint32_t k6 = (~((k_sum & 0x3F) + (k_sum >> 6))) & 0x3Fu;
      unsigned int rx_k54 = dw_bad ? 0 : (phaseptr[body0] & 0x03u);
      unsigned int rx_k = (rx_k54 << 4) | vec_k30;
      unsigned int expected_k = k6;
      if (rx_k != expected_k) {
        verbprintf(3, "FLEX_NEXT: Numeric K checksum FAIL: rx=0x%02X exp=0x%02X\n",
                   rx_k, expected_k);
        num_k_fail = 1;
      }
    } else {
      /* BCH errors prevented K verification - treat as fail */
      num_k_fail = 1;
    }
  }

  // Output frag flags with N/R/M/K-/DUP
  if (!json_mode) {
    char frag_flag = '?';
    if (cont == 0 && frag == 3) frag_flag = 'K';
    else if (cont == 1)         frag_flag = 'F';
    else if (cont == 0)         frag_flag = 'C';
    int is_initial = (frag == 0x03);
    const char *dup_str = (dedup_flag == 2) ? ".DUP+" : (dedup_flag == 1) ? ".DUP" : "";
    const char *k_str = num_k_fail ? ".K-" : "";
    if (is_initial)
      verbprintf(0, "%1d.%1d.%c.N%d.R%d%s%s%s|", frag, cont, frag_flag, msg_n, msg_r, msg_m ? ".M" : "", k_str, dup_str);
    else
      verbprintf(0, "%1d.%1d.%c.N%d%s%s|", frag, cont, frag_flag, msg_n, k_str, dup_str);
  }

  // BCD digit extraction
  char num_msg[256];
  int num_pos = 0;
  unsigned char digit = 0;
  int count = 4;
  if(flex->Decode.type == FLEX_PAGETYPE_NUMBERED_NUMERIC) {
    count += 10;        // Skip 10 header bits (K5K4 + N + R + S)
  } else {
    count += 2;         // Skip 2 header bits (K5K4)
  }
  int i;
  for(i = w1; i <= w2; i++) {
    int k;
    for(k = 0; k < 21; k++) {
      digit = (digit >> 1) & 0x0F;
      if(dw & 0x01) {
        digit ^= 0x08;
      }
      dw >>= 1;
      if(--count == 0) {
        if(dw_bad) {
          if (!json_mode) { verbprintf(0, "?"); }
          else { if (num_pos < 255) num_msg[num_pos++] = '?'; }
        } else {
          // Output all BCD digits including space fill (0x0C).
          // Do NOT skip any digits here - the K checksum covers
          // all BCD positions in the message words, so dropping
          // characters would cause the checksum to appear wrong.
          if (!json_mode) { verbprintf(0, "%c", flex_bcd[digit]); }
          else { if (num_pos < 255) num_msg[num_pos++] = flex_bcd[digit]; }
        }
        count = 4;
      }
    }
    // Load next word, check BCH status.
    // Guard: only load when another iteration follows (i+1 <= w2)
    // to avoid reading one word past the message.
    if (i + 1 <= w2 && i < PHASE_WORDS) {
      dw_bad = bch_err[i];
      dw = phaseptr[i];
    }
  }

  if (json_mode) {
    num_msg[num_pos] = '\0';
    const char *tag = (flex->Decode.type == FLEX_PAGETYPE_SPECIAL_NUMERIC) ? "SNUM" :
                      (flex->Decode.type == FLEX_PAGETYPE_NUMBERED_NUMERIC) ? "NNUM" : "NUM";
    const char *frag_str;
    if (cont == 0 && frag == 3) frag_str = "complete";
    else if (cont == 1)         frag_str = "fragment";
    else                        frag_str = "fragment_end";
    cJSON *extra = NULL;
    if (num_special_format >= 0) {
      extra = cJSON_CreateObject();
      cJSON_AddStringToObject(extra, "special_format", num_special_format ? "id_rom" : "standard");
    }
    flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode, flex->Decode.addr_type,
                        0, flex->Decode.type, tag, frag_str,
                        msg_n, msg_r, msg_m, num_k_fail ? 0 : 1, -1,
                        num_msg, NULL, 0, extra);
  }
}


static void parse_short_message(struct Flex_Next * flex, unsigned int * phaseptr, int * bch_err, int j) {
  if (flex==NULL) return;
  // BCD table per ARIB STD-43A Section 3.10.1.1
  unsigned const char flex_bcd[17] = "0123456789.U -][";

  // Short Message Vector layout (Section 3.9.2, Table 3.9.2-1):
  //   bits 4-6:   V = 010 (tone/short message type)
  //   bits 7-8:   t1,t0 (sub-type)
  //   bits 9-20:  d (data field, meaning depends on sub-type)
  //
  // Sub-types:
  //   t=00: Numeric - 3 BCD digits (short) or 8 digits (long)
  //         All-space digits = tone-only alert (no data content)
  //   t=01: Source - S2S1S0 source code (0-7)
  //   t=10: Numbered - S2S1S0 + N5-N0 + R0
  //   t=11: Reserved

  unsigned int sub_type = (phaseptr[j] >> 7) & 0x03;

  switch (sub_type) {
  case 0: {
    // t=00: Short Numeric Message
    // Short addr: 3 BCD digits in d0-d11 (bits 9-20 of vector)
    //   d0-d3 = digit a, d4-d7 = digit b, d8-d11 = digit c
    // Long addr: 3 digits in 1st vector + 5 digits in 2nd vector = 8 digits
    //   d12-d15 = digit d, d16-d19 = digit e, d20-d23 = digit f,
    //   d24-d27 = digit g, d28-d31 = digit h, d32 = spare (0)
    // Unused digit positions filled with space (0xC).
    // If ALL digits are space, this is a pure tone-only alert.
    char digits[9];
    int ndigits = 0;
    int all_space = 1;
    int i;

    for (i = 9; i <= 17; i += 4) {
      unsigned char d = (phaseptr[j] >> i) & 0x0F;
      digits[ndigits++] = flex_bcd[d];
      if (d != 0x0C) all_space = 0;
    }
    if (flex->Decode.long_address) {
      if ((j+1) < PHASE_WORDS && !bch_err[j+1]) {
        for (i = 0; i <= 16; i += 4) {
          unsigned char d = (phaseptr[j+1] >> i) & 0x0F;
          digits[ndigits++] = flex_bcd[d];
          if (d != 0x0C) all_space = 0;
        }
      } else {
        // 2nd vector word uncorrectable
        for (i = 0; i < 5; i++)
          digits[ndigits++] = '?';
        all_space = 0;
      }
    }
    digits[ndigits] = '\0';

    if (all_space) {
      // Pure tone-only: all digits are space fill, no data content
      if (!json_mode) {
        verbprintf(0, "TON|");
      } else {
        flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode, flex->Decode.addr_type,
                            0, FLEX_PAGETYPE_SHORT_MESSAGE, "TON", "complete",
                            -1, -1, -1, -1, -1, NULL, NULL, 0, NULL);
      }
    } else {
      // Short numeric message with actual digit content
      if (!json_mode) {
        verbprintf(0, "SMSG|%s", digits);
      } else {
        cJSON *extra = cJSON_CreateObject();
        cJSON_AddStringToObject(extra, "smsg_sub_type", "numeric");
        flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode, flex->Decode.addr_type,
                            0, FLEX_PAGETYPE_SHORT_MESSAGE, "SMSG", "complete",
                            -1, -1, -1, -1, -1, digits, NULL, 0, extra);
      }
    }
    break;
  }
  case 1: {
    // t=01: Source Code
    // d0-d2 = S2S1S0 (source code 0-7)
    unsigned int source = (phaseptr[j] >> 9) & 0x07;
    if (!json_mode) {
      verbprintf(0, "SMSG|SRC=%u", source);
    } else {
      cJSON *extra = cJSON_CreateObject();
      cJSON_AddStringToObject(extra, "smsg_sub_type", "source");
      cJSON_AddNumberToObject(extra, "source_code", source);
      char src_msg[32];
      snprintf(src_msg, sizeof(src_msg), "SRC=%u", source);
      flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode, flex->Decode.addr_type,
                          0, FLEX_PAGETYPE_SHORT_MESSAGE, "SMSG", "complete",
                          -1, -1, -1, -1, -1, src_msg, NULL, 0, extra);
    }
    break;
  }
  case 2: {
    // t=10: Numbered Short Message
    // d0-d2 = S2S1S0 (source code 0-7)
    // d3-d8 = N5-N0 (message number 0-63)
    // d9    = R0 (retrieval flag: 1=new, 0=retransmit)
    unsigned int source = (phaseptr[j] >> 9) & 0x07;
    unsigned int msg_n  = (phaseptr[j] >> 12) & 0x3F;
    unsigned int msg_r  = (phaseptr[j] >> 18) & 0x01;
    if (!json_mode) {
      verbprintf(0, "SMSG|S=%u N=%u R=%u", source, msg_n, msg_r);
    } else {
      cJSON *extra = cJSON_CreateObject();
      cJSON_AddStringToObject(extra, "smsg_sub_type", "numbered");
      cJSON_AddNumberToObject(extra, "source_code", source);
      char num_msg[64];
      snprintf(num_msg, sizeof(num_msg), "S=%u N=%u R=%u", source, msg_n, msg_r);
      flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode, flex->Decode.addr_type,
                          0, FLEX_PAGETYPE_SHORT_MESSAGE, "SMSG", "complete",
                          (int)msg_n, (int)msg_r, -1, -1, -1, num_msg, NULL, 0, extra);
    }
    break;
  }
  default:
    // t=11: Reserved
    if (!json_mode) {
      verbprintf(0, "SMSG|RSVD t=%u d=0x%03X", sub_type, (phaseptr[j] >> 9) & 0xFFF);
    } else {
      cJSON *extra = cJSON_CreateObject();
      cJSON_AddStringToObject(extra, "smsg_sub_type", "reserved");
      char rsvd_msg[64];
      snprintf(rsvd_msg, sizeof(rsvd_msg), "RSVD t=%u d=0x%03X", sub_type, (phaseptr[j] >> 9) & 0xFFF);
      flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode, flex->Decode.addr_type,
                          0, FLEX_PAGETYPE_SHORT_MESSAGE, "SMSG", "complete",
                          -1, -1, -1, -1, -1, rsvd_msg, NULL, 0, extra);
    }
    break;
  }
}

static void parse_binary(struct Flex_Next * flex, unsigned int * phaseptr, int * bch_err, unsigned int mw1, unsigned int len, int frag, int cont, int msg_n, int msg_r, int msg_m, int dedup_flag) {
  if (flex==NULL) return;

  // HEX/Binary message body layout (Section 3.10.1.2, Fig 3.10.1.2-1):
  //
  // Initial fragment (F=11):
  //   Word at mw1 = Header word 2 (hdr2):
  //     bit  0:     R (retrieval: 1=new, 0=retransmit)
  //     bit  1:     M (maildrop)
  //     bit  2:     D (display direction: 0=LTR, 1=RTL)
  //     bit  3:     H (header message flag)
  //     bits 4-7:   B (blocking length, 0=16 bits/char)
  //     bit  8:     I (status info field enabler)
  //     bits 9-12:  s (reserved, default 0000)
  //     bits 13-20: S (8-bit signature)
  //   Words mw1+1 .. mw1+len-1 = data words (21 bits each)
  //
  // Continuation fragment (F!=11):
  //   All words mw1 .. mw1+len-1 are data words (21 bits each)
  //
  // Data is a continuous bit stream packed across 21-bit words.
  // Nibbles (4 bits each) are extracted LSB-first within each word.
  // Total data bits = number_of_data_words * 21 + partial_bits_from_hdr2.
  //
  // Termination fill (Section 3.10.1.2):
  //   After the last data nibble, remaining bits in the last word
  //   are filled with the inverse of the last data bit.
  //   If the last data nibble is all-0 or all-1, an extra fill word
  //   (all-0 or all-1) is appended per rule (3).
  //   We detect fill by scanning backwards from bit 20 of the last
  //   word: consecutive identical bits from the top are fill.

  int is_initial = (frag == 3);
  unsigned int data_start = mw1;

  int hex_blocking = 0;   // B field: bits per character (0=16)
  uint32_t hex_rx_sig = 0; // S field: 8-bit signature
  int hex_has_sig = 0;
  int hex_sig_fail = 0;

  // Parse hdr2 on initial fragments and extract its 8 data bits
  // HEX hdr2 layout (Section 3.10.1.2, Fig 3.10.1.2-1):
  //   bit  0:     R (retrieval) - already extracted by caller
  //   bit  1:     M (maildrop) - already extracted by caller
  //   bit  2:     D (display direction: 0=LTR, 1=RTL)
  //   bit  3:     H (header message flag)
  //   bits 4-7:   B (blocking length, bits per char; 0000=16)
  //   bit  8:     I (status info field enabler)
  //   bits 9-12:  s (reserved, default 0000)
  //   bits 13-20: S (8-bit signature)
  if (is_initial && len > 0) {
    if (mw1 < PHASE_WORDS && !bch_err[mw1]) {
      unsigned int hdr2 = phaseptr[mw1];
      hex_blocking = (hdr2 >> 4) & 0xF;
      hex_rx_sig = (hdr2 >> 13) & 0xFF;
      hex_has_sig = 1;
      verbprintf(3, "FLEX_NEXT: HEX hdr2=0x%05X R=%u B=%u(%d bits/char) S=0x%02X\n",
                 hdr2, hdr2 & 1, hex_blocking,
                 hex_blocking ? hex_blocking : 16, hex_rx_sig);
    }
    data_start = mw1 + 1;
    len--;
    // hdr2 contains only control fields (R/M/D/H/B/I/s/S).
    // Data starts in the next word. No data bits in hdr2.
  }

  char hex[512];
  int hi = 0;
  int bit_count = 0;
  unsigned char nibble_acc = 0;
  int total_bits = 0;

  // Extract data bits from data words (all 21 bits each)
  // Extract data bits from data words (all 21 bits each)
  for (unsigned int w = data_start; w < data_start + len && w < PHASE_WORDS; w++) {
    if (bch_err[w]) {
      // Lost word: emit '?' placeholders for 5 nibbles (21 bits / 4 rounded)
      for (int b = 0; b < 21; b++) {
        int nibble_pos = bit_count % 4;
        if (nibble_pos == 0) nibble_acc = 0;
        if (nibble_pos == 3 && hi < (int)sizeof(hex) - 1)
          hex[hi++] = '?';
        bit_count++;
        total_bits++;
      }
      continue;
    }
    unsigned int dw = phaseptr[w];
    for (int b = 0; b < 21; b++) {
      int nibble_pos = bit_count % 4;
      if (nibble_pos == 0)
        nibble_acc = 0;
      nibble_acc |= ((dw >> b) & 1) << nibble_pos;
      if (nibble_pos == 3 && hi < (int)sizeof(hex) - 1)
        hex[hi++] = "0123456789ABCDEF"[nibble_acc & 0xF];
      bit_count++;
      total_bits++;
    }
  }

  // Strip termination fill from last/complete fragment (C=0).
  //
  // Per Section 3.10.1.2, termination fill rules:
  //   (2) When data ends mid-word, remaining bits are filled with
  //       the inverse of the last data bit.
  //   (3) When data ends exactly at a word boundary AND the last
  //       character is all-0s or all-1s, an extra fill word is
  //       appended (all bits = inverse of last data bit).
  //
  // Stripping: either strip a whole extra fill word, or strip
  // partial fill bits from the last word.  Never both.
  if (cont == 0 && len > 0) {
    unsigned int last_w = data_start + len - 1;

    // Rule (3): if the last word is entirely fill (0x000000 or
    // 0x1FFFFF), discard it and truncate the hex output to the
    // nibble count before that word.
    if (last_w > data_start && last_w < PHASE_WORDS && !bch_err[last_w]) {
      unsigned int lw = phaseptr[last_w] & 0x1FFFFF;
      if (lw == 0x000000 || lw == 0x1FFFFF) {
        int bits_before = (int)(last_w - data_start) * 21;
        int nibs_before = bits_before / 4;
        if (nibs_before > 0 && nibs_before <= hi) {
          hi = nibs_before;
          last_w = (unsigned int)-1;  // done, skip step 2
        }
      }
    }

    // Rule (2): partial fill in last word.  Scan backwards from
    // bit 20 - consecutive identical bits from the top are fill.
    // The first differing bit marks the end of real data.
    if (last_w != (unsigned int)-1 && last_w < PHASE_WORDS && !bch_err[last_w]) {
      unsigned int lw = phaseptr[last_w];
      unsigned int top_bit = (lw >> 20) & 1;
      int fill_start = 21;
      for (int b = 20; b >= 0; b--) {
        if (((lw >> b) & 1) != top_bit)
          break;
        fill_start = b;
      }
      if (fill_start < 21 && fill_start > 0) {
        int bits_before = (int)(last_w - data_start) * 21;
        int real_bits = bits_before + fill_start;
        int real_nibbles = (real_bits + 3) / 4;
        if (real_nibbles < hi)
          hi = real_nibbles;
      }
    }
  }

  hex[hi] = '\0';

  // HEX signature validation (Section 3.10.1.2):
  // S is the 1's complement of the binary sum of all data bytes
  // (8 bits at a time), starting after the S field.  Termination
  // bits are NOT included.  Only validate on complete messages (K).
  if (is_initial && cont == 0) {
    if (hex_has_sig) {
    int total_data_bits = hi * 4;
    uint32_t sig_sum = 0;
    int bit_pos = 0;
    uint8_t accum = 0;
    int accum_bits = 0;
    // Sum data bits from data words only (hdr2 contains S, not data)
    for (unsigned int w = data_start; w < data_start + len && w < PHASE_WORDS && bit_pos < total_data_bits; w++) {
      if (bch_err[w]) break;
      unsigned int dw = phaseptr[w];
      for (int b = 0; b < 21 && bit_pos < total_data_bits; b++) {
        accum |= ((dw >> b) & 1) << accum_bits;
        accum_bits++;
        bit_pos++;
        if (accum_bits == 8) { sig_sum += accum; accum = 0; accum_bits = 0; }
      }
    }
    // Include partial last byte if any
    if (accum_bits > 0) sig_sum += accum;
    uint32_t expected_sig = (~sig_sum) & 0xFF;
    if (hex_rx_sig != expected_sig) {
      verbprintf(3, "FLEX_NEXT: HEX signature FAIL: rx=0x%02X expected=0x%02X\n",
                 hex_rx_sig, expected_sig);
      hex_sig_fail = 1;
    }
    } else {
      /* BCH errors prevented signature verification - treat as fail */
      hex_sig_fail = 1;
    }
  }

  // Fragment reassembly for HEX/Binary messages.
  // Uses the same F/K/C flags as alpha (from hdr1):
  //   frag==3, cont==0: 'K' - complete message, output directly
  //   cont==1:          'F' - first/middle fragment, buffer it
  //   cont==0, frag!=3: 'C' - final fragment, combine and output
  char frag_flag = '?';
  if (cont == 0 && frag == 3) frag_flag = 'K';
  else if (cont == 1)         frag_flag = 'F';
  else if (cont == 0)         frag_flag = 'C';

  int is_initial_hex = (frag == 0x03);

  if (frag_flag == 'F') {
    // First/middle fragment: buffer it
    unsigned int abs_frame = flex->FIW.cycleno * 128 + flex->FIW.frameno;
    int fslot = frag_find(flex, flex->Decode.capcode, flex->Decode.type, msg_n);
    // R=1 on initial fragment means new message; discard stale slot
    if (fslot >= 0 && is_initial_hex && msg_r == 1) {
      verbprintf(3, "FLEX_NEXT: HEX R=1 new message, releasing stale slot %d for cap %" PRId64 " N=%d\n",
                 fslot, flex->Decode.capcode, msg_n);
      frag_release(flex, fslot);
      fslot = -1;
    }
    if (fslot < 0)
      fslot = frag_alloc(flex, flex->Decode.capcode, flex->Decode.type, msg_n, abs_frame);
    if (fslot >= 0) {
      frag_append(flex, fslot, (const unsigned char *)hex, (unsigned int)hi);
      if (is_initial_hex) {
        flex->FragStore.slots[fslot].msg_r = msg_r;
        flex->FragStore.slots[fslot].msg_m = msg_m;
      }
      verbprintf(3, "FLEX_NEXT: HEX buffered fragment for cap %" PRId64 " (%d nibbles in slot %d)\n",
                 flex->Decode.capcode, flex->FragStore.slots[fslot].data_len, fslot);
    }
    // Output frag flags. For continuations, carry R/M from stored initial.
    if (!json_mode) {
      int out_r = is_initial_hex ? msg_r : (fslot >= 0 ? flex->FragStore.slots[fslot].msg_r : -1);
      int out_m = is_initial_hex ? msg_m : (fslot >= 0 ? flex->FragStore.slots[fslot].msg_m : -1);
      if (out_r >= 0)
        verbprintf(0, "%c.N%d.R%d%s|", frag_flag, msg_n, out_r, out_m ? ".M" : "");
      else
        verbprintf(0, "%c.N%d|", frag_flag, msg_n);
      verbprintf(0, "%s", hex);
    } else {
      flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode, flex->Decode.addr_type,
                          0, flex->Decode.type, "HEX", is_initial_hex ? "fragment_start" : "fragment",
                          msg_n, msg_r, msg_m, -1,
                          hex_sig_fail ? 0 : (hex_has_sig ? 1 : -1),
                          hex, NULL, 0, NULL);
    }
    return;
  }

  if (frag_flag == 'C') {
    // Final fragment: combine with buffered data
    int fslot = frag_find(flex, flex->Decode.capcode, flex->Decode.type, msg_n);
    if (fslot >= 0 && flex->FragStore.slots[fslot].data_len > 0) {
      if (!json_mode) {
        // Output frag flags with R/M carried from initial fragment
        {
          int out_r = flex->FragStore.slots[fslot].msg_r;
          int out_m = flex->FragStore.slots[fslot].msg_m;
          if (out_r >= 0)
            verbprintf(0, "%c.N%d.R%d%s|", frag_flag, msg_n, out_r, out_m ? ".M" : "");
          else
            verbprintf(0, "%c.N%d|", frag_flag, msg_n);
        }
        verbprintf(0, "%.*s%s",
                   (int)flex->FragStore.slots[fslot].data_len,
                   flex->FragStore.slots[fslot].data,
                   hex);
      } else {
        // Build reassembled hex string for JSON
        char reassembled[1024];
        int rlen = (int)flex->FragStore.slots[fslot].data_len;
        if (rlen > (int)sizeof(reassembled) - (int)sizeof(hex) - 1)
          rlen = (int)sizeof(reassembled) - (int)sizeof(hex) - 1;
        memcpy(reassembled, flex->FragStore.slots[fslot].data, (unsigned)rlen);
        memcpy(reassembled + rlen, hex, (unsigned)(hi + 1));
        flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode, flex->Decode.addr_type,
                            0, flex->Decode.type, "HEX", "reassembled",
                            msg_n, flex->FragStore.slots[fslot].msg_r,
                            flex->FragStore.slots[fslot].msg_m, -1,
                            hex_sig_fail ? 0 : (hex_has_sig ? 1 : -1),
                            reassembled, NULL, 0, NULL);
      }
      verbprintf(3, "FLEX_NEXT: HEX reassembled %u + %d nibbles for cap %" PRId64 "\n",
                 flex->FragStore.slots[fslot].data_len, hi, flex->Decode.capcode);
      frag_release(flex, fslot);
      return;
    }
    // No buffered fragment, output what we have
    if (!json_mode) {
      verbprintf(0, "%c.N%d|%s", frag_flag, msg_n, hex);
    } else {
      flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode, flex->Decode.addr_type,
                          0, flex->Decode.type, "HEX", "fragment_end",
                          msg_n, msg_r, msg_m, -1,
                          hex_sig_fail ? 0 : (hex_has_sig ? 1 : -1),
                          hex, NULL, 0, NULL);
    }
    return;
  }

  // K (complete): output with frag flags and DUP status
  if (!json_mode) {
    const char *dup_str = (dedup_flag == 2) ? ".DUP+" : (dedup_flag == 1) ? ".DUP" : "";
    const char *sig_str = hex_sig_fail ? ".SIGN-" : "";
    if (is_initial_hex)
      verbprintf(0, "%c.N%d.R%d%s%s%s|%s", frag_flag, msg_n, msg_r, msg_m ? ".M" : "", sig_str, dup_str, hex);
    else
      verbprintf(0, "%c.N%d%s%s|%s", frag_flag, msg_n, sig_str, dup_str, hex);
  } else {
    cJSON *extra = NULL;
    if (hex_has_sig) {
      extra = cJSON_CreateObject();
      cJSON_AddNumberToObject(extra, "blocking", hex_blocking ? hex_blocking : 16);
    }
    flex_next_json_emit(flex, flex->Decode.phase, flex->Decode.capcode, flex->Decode.addr_type,
                        0, flex->Decode.type, "HEX", "complete",
                        msg_n, msg_r, msg_m, -1,
                        hex_sig_fail ? 0 : (hex_has_sig ? 1 : -1),
                        hex, NULL, 0, extra);
  }
}


static void decode_phase(struct Flex_Next * flex, char PhaseNo) {
  if (flex==NULL) return;
  verbprintf(3, "FLEX_NEXT: Decoding phase %c\n", PhaseNo);

  uint32_t *phaseptr=NULL;

  switch (PhaseNo) {
    case 'A': phaseptr=flex->Data.PhaseA.buf; break;
    case 'B': phaseptr=flex->Data.PhaseB.buf; break;
    case 'C': phaseptr=flex->Data.PhaseC.buf; break;
    case 'D': phaseptr=flex->Data.PhaseD.buf; break;
  }

  // BCH decode all 88 words first
  for (unsigned int i = 0; i < PHASE_WORDS; i++) {
    int decode_error=bch3121_fix_errors(flex, &phaseptr[i], PhaseNo);

    if (decode_error) {
      verbprintf(3, "FLEX_NEXT: BCH error at word %u (phase %c), marking uncorrectable\n", i, PhaseNo);

      switch (PhaseNo) {
        case 'A': flex->Data.PhaseA.bch_err[i]=1; break;
        case 'B': flex->Data.PhaseB.bch_err[i]=1; break;
        case 'C': flex->Data.PhaseC.bch_err[i]=1; break;
        case 'D': flex->Data.PhaseD.bch_err[i]=1; break;
      }
      continue;
    }

    phaseptr[i]&=0x1FFFFFL;
  }

  int *bch_err = NULL;
  switch (PhaseNo) {
    case 'A': bch_err=flex->Data.PhaseA.bch_err; break;
    case 'B': bch_err=flex->Data.PhaseB.bch_err; break;
    case 'C': bch_err=flex->Data.PhaseC.bch_err; break;
    case 'D': bch_err=flex->Data.PhaseD.bch_err; break;
  }

  // Multiple transmission (Section 3.4.2):
  // Subframe splitting ignored - always decode full 88-word frame.
  int num_tx = (int)flex->FIW.num_tx;
  int sf_size = (num_tx == 2) ? 44 : (num_tx == 3) ? 29 : (num_tx == 4) ? 22 : 88;
  verbprintf(num_tx > 1 ? 0 : 3, "FLEX_NEXT: num_tx=%d sf_size=%d, decoding full frame (subframe retransmission ignored)\n", num_tx, sf_size);

  // Block information word is the first data word
  flex->biw_sysmsg_a_type = -1;
  flex->Decode.phase = PhaseNo;  // store for parse functions to access
  flex->Decode.sec_subtype = NULL;
  flex->Decode.opr_category = NULL;
  uint32_t biw = phaseptr[0];

  // If BIW itself is uncorrectable, we cannot parse this phase
  if (bch_err[0]) {
    verbprintf(3, "FLEX_NEXT: BIW uncorrectable (phase %c), skipping\n", PhaseNo);
    return;
  }

  // Nothing to see here, please move along
  // A valid BIW can never be all-zeros or all-ones because the
  // 4-bit checksum prevents it. Use voffset==aoffset for idle detection.
  if (biw == 0 || (biw & 0x1FFFFFL) == 0x1FFFFFL) {
    verbprintf(3, "FLEX_NEXT: BIW is all-zeros or all-ones, likely idle fill (not a valid BIW)\n");
    return;
  }

  // Address start address is bits 9-8, plus one for offset (to account for biw)
  unsigned int aoffset = ((biw >> 8) & 0x3L) + 1;
  // Vector start index is bits 15-10
  unsigned int voffset = (biw >> 10) & 0x3fL;
  // Priority address count is bits 7-4
  unsigned int prio = (biw >> 4) & 0xFL;
  // Carry-on is bits 17-16
  unsigned int carry = (biw >> 16) & 0x3L;
  // Collapse cycle is bits 20-18
  unsigned int collapse = (biw >> 18) & 0x7L;

  if (voffset < aoffset) {
      verbprintf(3, "FLEX_NEXT: Invalid biw\n");
      return;
  }

  // Parse BIW2/3/4 (words 1 through aoffset-1) before idle check.
  // These carry date, time, SSID etc. and are present even on idle frames.
  // BIW type is identified by bits 6-4 of each extra BIW word.
  {
    unsigned int bw;
    for (bw = 1; bw < aoffset && bw < (unsigned)PHASE_WORDS; bw++) {
      unsigned int bword;
      unsigned int btype;

      if (bch_err[bw]) {
        verbprintf(3, "FLEX_NEXT: BIW[%u] uncorrectable, skipping\n", bw);
        continue;
      }

      bword = phaseptr[bw];
      btype = (bword >> 4) & 0x7;

      switch (btype) {
        case 0: { // SSID1 (type 000): Local ID and Coverage Zone
          unsigned int lid = (bword >> 7) & 0x1FF;
          unsigned int cov = (bword >> 16) & 0x1F;
          verbprintf(2, "FLEX_NEXT: BIW SSID1: LID=%u CZ=%u (phase %c)\n", lid, cov, PhaseNo);
          if (json_mode) {
            cJSON *json = cJSON_CreateObject();
            if (json) {
              time_t now = time(NULL);
              struct tm *gmt = gmtime(&now);
              char ts[64];
              snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
                       gmt->tm_year+1900, gmt->tm_mon+1, gmt->tm_mday,
                       gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
              cJSON_AddStringToObject(json, "timestamp", ts);
              cJSON_AddNumberToObject(json, "baud", flex->Sync.baud);
              cJSON_AddNumberToObject(json, "level", flex->Sync.levels);
              char ph[2] = { PhaseNo, '\0' };
              cJSON_AddStringToObject(json, "phase", ph);
              cJSON_AddNumberToObject(json, "cycle", flex->FIW.cycleno);
              cJSON_AddNumberToObject(json, "frame", flex->FIW.frameno);
              cJSON_AddStringToObject(json, "msg_type", "biw_sysid");
              cJSON_AddNumberToObject(json, "biw_position", bw);
              cJSON_AddStringToObject(json, "type_tag", "BIW_SSID1");
              cJSON_AddNumberToObject(json, "lid", lid);
              cJSON_AddNumberToObject(json, "cov", cov);
              char *out = cJSON_PrintUnformatted(json);
              if (out) { fprintf(stdout, "%s\n", out); free(out); }
              cJSON_Delete(json);
            }
          }
          break;
        }
        case 1: { // Date (type 001): year, day, month
          unsigned int year_raw = (bword >> 7) & 0x1F;
          unsigned int day = (bword >> 12) & 0x1F;
          unsigned int mon = (bword >> 17) & 0xF;
          unsigned int year = year_raw + 1994;
          verbprintf(2, "FLEX_NEXT: BIW DATE: %04u-%02u-%02u (phase %c)\n", year, mon, day, PhaseNo);
          // Store as last known good OTA date
          // Validate fields - month 0 or day 0 indicates corrupt data
          if (mon >= 1 && mon <= 12 && day >= 1 && day <= 31) {
            flex->ota_time.year = year;
            flex->ota_time.month = mon;
            flex->ota_time.day = day;
            flex->ota_time.has_date = 1;
            flex->ota_time.frame_date = flex->FIW.cycleno * 128 + flex->FIW.frameno;
          } else {
            verbprintf(3, "FLEX_NEXT: BIW DATE out of range: year=%u mon=%u day=%u, discarding\n", year, mon, day);
            break;
          }
          if (json_mode) {
            cJSON *json = cJSON_CreateObject();
            if (json) {
              time_t now = time(NULL);
              struct tm *gmt = gmtime(&now);
              char ts[64];
              snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
                       gmt->tm_year+1900, gmt->tm_mon+1, gmt->tm_mday,
                       gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
              cJSON_AddStringToObject(json, "timestamp", ts);
              cJSON_AddNumberToObject(json, "baud", flex->Sync.baud);
              cJSON_AddNumberToObject(json, "level", flex->Sync.levels);
              char ph[2] = { PhaseNo, '\0' };
              cJSON_AddStringToObject(json, "phase", ph);
              cJSON_AddNumberToObject(json, "cycle", flex->FIW.cycleno);
              cJSON_AddNumberToObject(json, "frame", flex->FIW.frameno);
              cJSON_AddStringToObject(json, "msg_type", "biw_date");
              cJSON_AddNumberToObject(json, "biw_position", bw);
              cJSON_AddStringToObject(json, "type_tag", "BIW_DATE");
              cJSON_AddNumberToObject(json, "year", year);
              cJSON_AddNumberToObject(json, "month", mon);
              cJSON_AddNumberToObject(json, "day", day);
              char *out = cJSON_PrintUnformatted(json);
              if (out) { fprintf(stdout, "%s\n", out); free(out); }
              cJSON_Delete(json);
            }
          }
          break;
        }
        case 2: { // Time (type 010): hour, minute, second
          unsigned int hour = (bword >> 7) & 0x1F;
          unsigned int min = (bword >> 12) & 0x3F;
          unsigned int sec = (bword >> 18) & 0x7;
          verbprintf(2, "FLEX_NEXT: BIW TIME: %02u:%02u:%04.1f (phase %c)\n", hour, min, sec * 7.5, PhaseNo);
          // Store as last known good OTA time (coarse, 7.5s resolution)
          // Validate fields before storing - corrupted BCH words can produce
          // out-of-range values (e.g. hour=24, min=63)
          if (hour <= 23 && min <= 59 && sec <= 7) {
            flex->ota_time.hour = hour;
            flex->ota_time.min = min;
            flex->ota_time.sec_coarse = sec;
            flex->ota_time.has_time = 1;
            flex->ota_time.frame_time = flex->FIW.cycleno * 128 + flex->FIW.frameno;
          } else {
            verbprintf(3, "FLEX_NEXT: BIW TIME out of range: hour=%u min=%u sec=%u, discarding\n", hour, min, sec);
            break;
          }
          if (json_mode) {
            cJSON *json = cJSON_CreateObject();
            if (json) {
              time_t now = time(NULL);
              struct tm *gmt = gmtime(&now);
              char ts[64];
              snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
                       gmt->tm_year+1900, gmt->tm_mon+1, gmt->tm_mday,
                       gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
              cJSON_AddStringToObject(json, "timestamp", ts);
              cJSON_AddNumberToObject(json, "baud", flex->Sync.baud);
              cJSON_AddNumberToObject(json, "level", flex->Sync.levels);
              char ph[2] = { PhaseNo, '\0' };
              cJSON_AddStringToObject(json, "phase", ph);
              cJSON_AddNumberToObject(json, "cycle", flex->FIW.cycleno);
              cJSON_AddNumberToObject(json, "frame", flex->FIW.frameno);
              cJSON_AddStringToObject(json, "msg_type", "biw_time");
              cJSON_AddNumberToObject(json, "biw_position", bw);
              cJSON_AddStringToObject(json, "type_tag", "BIW_TIME");
              cJSON_AddNumberToObject(json, "hour", hour);
              cJSON_AddNumberToObject(json, "min", min);
              cJSON_AddNumberToObject(json, "sec", sec * 7.5);
              char *out = cJSON_PrintUnformatted(json);
              if (out) { fprintf(stdout, "%s\n", out); free(out); }
              cJSON_Delete(json);
            }
          }
          break;
        }
        case 5: { // SysInfo (type 101): timezone, system messages
          unsigned int a_type = (bword >> 7) & 0xF;
          unsigned int info = (bword >> 11) & 0x3FF;
          // Store A-type for system message vector decode (Section 3.9.2)
          if (a_type <= 3) {
            // A=0000-0011: system message (all/home/roaming/SSID pagers)
            flex->biw_sysmsg_a_type = (int)a_type;
            verbprintf(3, "FLEX_NEXT: BIW SYSINFO: SysMsg A=%u I=0x%03X (phase %c)\n", a_type, info, PhaseNo);
          } else if (a_type == 4 || a_type == 8) {
            // Time-related: timezone, DST flag, and extended seconds.
            // I4-I0: Z4-Z0 timezone zone code (5 bits)
            // I5:    L0 DST flag (0=DST active, 1=standard time)
            // I7-I9: S5-S3 extended seconds (3 bits, combines with
            //        BIW TIME S2-S0 for 0.9375s resolution)
            unsigned int zone = info & 0x1F;
            unsigned int dst = (info >> 5) & 0x1;
            unsigned int esec = (info >> 7) & 0x7;
            int tz_min = (zone < 32) ? flex_tz_table[zone] : 0;
            verbprintf(2, "FLEX_NEXT: BIW SYSINFO: timezone zone=%u (%+dmin) DST=%u extsec=%u (phase %c)\n",
                       zone, tz_min, dst, esec, PhaseNo);
            // Store as last known good OTA timezone
            flex->ota_time.tz_zone = zone;
            flex->ota_time.tz_offset_min = tz_min;
            flex->ota_time.tz_dst = (int)dst;
            flex->ota_time.sec_ext = esec;
            flex->ota_time.has_tz = 1;
            flex->ota_time.frame_tz = flex->FIW.cycleno * 128 + flex->FIW.frameno;
          } else {
            verbprintf(3, "FLEX_NEXT: BIW SYSINFO: A=%u I=0x%03X (phase %c)\n", a_type, info, PhaseNo);
          }
          if (json_mode) {
            cJSON *json = cJSON_CreateObject();
            if (json) {
              time_t now = time(NULL);
              struct tm *gmt = gmtime(&now);
              char ts[64];
              snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
                       gmt->tm_year+1900, gmt->tm_mon+1, gmt->tm_mday,
                       gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
              cJSON_AddStringToObject(json, "timestamp", ts);
              cJSON_AddNumberToObject(json, "baud", flex->Sync.baud);
              cJSON_AddNumberToObject(json, "level", flex->Sync.levels);
              char ph[2] = { PhaseNo, '\0' };
              cJSON_AddStringToObject(json, "phase", ph);
              cJSON_AddNumberToObject(json, "cycle", flex->FIW.cycleno);
              cJSON_AddNumberToObject(json, "frame", flex->FIW.frameno);
              cJSON_AddStringToObject(json, "msg_type", "biw_sysinfo");
              cJSON_AddNumberToObject(json, "biw_position", bw);
              cJSON_AddStringToObject(json, "type_tag", "BIW_SYSINFO");
              cJSON_AddNumberToObject(json, "a_type", a_type);
              cJSON_AddNumberToObject(json, "info", info);
              char *out = cJSON_PrintUnformatted(json);
              if (out) { fprintf(stdout, "%s\n", out); free(out); }
              cJSON_Delete(json);
            }
          }
          break;
        }
        case 7: { // SSID2 (type 111): Country Code and TMF
          unsigned int tmf = (bword >> 7) & 0xF;
          unsigned int country = (bword >> 11) & 0x3FF;
          verbprintf(2, "FLEX_NEXT: BIW SSID2: CC=%u TMF=0x%X (phase %c)\n", country, tmf, PhaseNo);
          if (json_mode) {
            cJSON *json = cJSON_CreateObject();
            if (json) {
              time_t now = time(NULL);
              struct tm *gmt = gmtime(&now);
              char ts[64];
              snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
                       gmt->tm_year+1900, gmt->tm_mon+1, gmt->tm_mday,
                       gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
              cJSON_AddStringToObject(json, "timestamp", ts);
              cJSON_AddNumberToObject(json, "baud", flex->Sync.baud);
              cJSON_AddNumberToObject(json, "level", flex->Sync.levels);
              char ph[2] = { PhaseNo, '\0' };
              cJSON_AddStringToObject(json, "phase", ph);
              cJSON_AddNumberToObject(json, "cycle", flex->FIW.cycleno);
              cJSON_AddNumberToObject(json, "frame", flex->FIW.frameno);
              cJSON_AddStringToObject(json, "msg_type", "biw_countrycode");
              cJSON_AddNumberToObject(json, "biw_position", bw);
              cJSON_AddStringToObject(json, "type_tag", "BIW_SSID2");
              cJSON_AddNumberToObject(json, "country", country);
              cJSON_AddNumberToObject(json, "tmf", tmf);
              char *out = cJSON_PrintUnformatted(json);
              if (out) { fprintf(stdout, "%s\n", out); free(out); }
              cJSON_Delete(json);
            }
          }
          break;
        }
        default:
          verbprintf(3, "FLEX_NEXT: BIW[%u] reserved type=%u data=0x%05X\n", bw, btype, bword);
          break;
      }
    }
  }

  // No addresses if voffset == aoffset (idle frame with BIW only)
  if (voffset == aoffset) {
    verbprintf(3, "FLEX_NEXT: Idle frame, no addresses (voffset==aoffset=%u, collapse=%u)\n", voffset, collapse);
    return;
  }

  // long addresses use double AW and VW, so there are anywhere between ceil(v-a/2) to v-a pages in this frame
  verbprintf(3, "FLEX_NEXT: BlockInfoWord: (Phase %c) BIW:%08X AW %02u VW %02u prio=%u carry=%u collapse=%u (up to %u pages)\n", PhaseNo, biw, aoffset, voffset, prio, carry, collapse, voffset-aoffset);

  int flex_groupmessage = 0;
  int flex_groupbit = 0;

  // Pre-scan: count valid vector words using 4-bit nibble checksum
  // (Section 3.5.1) to determine where tone-only addresses begin.
  //
  // Tone-only addresses sit at the end of the address field with no
  // corresponding vector word (Section 3.8.1(6)).  The vector field
  // starts at voffset; we scan forward to find the last vector word
  // that passes the checksum.  Words beyond that are not real vectors
  // - the addresses that would pair with them are tone-only.
  //
  // IMPORTANT: BCH-uncorrectable vector words are treated as
  // potentially valid (not counted as checksum failures).  Only
  // BCH-clean words that FAIL the checksum prove there is no real
  // vector at that slot.  This avoids misclassifying real messages
  // as tone-only when a vector word is temporarily corrupted.
  //
  // n_valid_vecs = index+1 of the last slot that is either
  // BCH-uncorrectable OR passes the checksum.
  int n_valid_vecs;
  {
    int max_vec = (int)(voffset - aoffset);
    if (max_vec > (int)((unsigned)PHASE_WORDS - voffset))
      max_vec = (int)((unsigned)PHASE_WORDS - voffset);
    int last_valid = -1;
    for (int vi = 0; vi < max_vec; vi++) {
      int wi = (int)voffset + vi;
      if (bch_err[wi]) {
        // Can't verify - assume valid to avoid dropping real messages
        last_valid = vi;
        continue;
      }
      uint32_t vw = phaseptr[wi];
      // Check vector type first: Short Instruction vectors (V=001)
      // use a different field layout where bits 7-20 carry instruction
      // data, not message word pointers.  The 4-bit nibble checksum
      // (Section 3.5.1) does NOT apply to instruction vectors - the
      // checksum field (bits 0-3) is part of the instruction encoding.
      // Always treat instruction vectors as valid.
      int vtype = (vw >> 4) & 0x7;
      if (vtype == FLEX_PAGETYPE_SHORT_INSTRUCTION) {
        last_valid = vi;
        continue;
      }
      uint32_t csum = (vw & 0xF) + ((vw >> 4) & 0xF) + ((vw >> 8) & 0xF) +
                      ((vw >> 12) & 0xF) + ((vw >> 16) & 0xF) + ((vw >> 20) & 0x1);
      if ((csum & 0xF) == 0xF)
        last_valid = vi;
      // else: BCH-clean but checksum fails - not a real vector
    }
    n_valid_vecs = last_valid + 1;
  }

  // Track how many vector slots have been consumed.
  // When vec_used reaches n_valid_vecs, remaining addresses are tone-only.
  unsigned int vec_used = 0;

  // Iterate through pages and dispatch to appropriate handler.
  for (unsigned int i = aoffset; i < voffset; i++) {
    // Skip address words with BCH errors
    if (bch_err[i]) {
      verbprintf(3, "FLEX_NEXT: Address word %u uncorrectable, skipping page\n", i);
      continue;
    }
    verbprintf(3, "FLEX_NEXT: Processing page offset #%u AW:%08X (vec_used=%u)\n", i - aoffset + 1, phaseptr[i], vec_used);
    if (phaseptr[i] == 0 ||
        (phaseptr[i] & 0x1FFFFFL) == 0x1FFFFFL) {
      verbprintf(3, "FLEX_NEXT: Idle codewords, invalid address\n");
      continue;
    }
    /*********************
     * Parse AW
     *
     * Address word classification per ARIB STD-43A Table 3.8.2-1:
     *   Short address (SA):  0x8001 - 0x1E0000  (capcode = aw - 0x8000)
     *   Long Address 1 (LA1): 0x000001 - 0x008000
     *   Long Address 2 (LA2): 0x1F7FFF - 0x1FFFFE
     *   Long Address 3 (LA3): 0x1E0001 - 0x1E8000
     *   Long Address 4 (LA4): 0x1E8001 - 0x1F0000
     *   Temporary Address:    0x1F7800 - 0x1F780F (16 group slots)
     *   Network Address:      0x1F0001 - 0x1F7799 (system info)
     *   Operator Msg Address: 0x1F7810 - 0x1F781F
     *   Info Service Address: 0x1F7820 - 0x1F7FEF
     *   Reserved:             0x1F7FF0 - 0x1F7FFE
     *
     * Long addresses use 2 consecutive address words.
     * The first word determines the type (LA1 or LA2).
     * The second word determines the set (LA2, LA3, or LA4).
     */
    uint32_t aiw = phaseptr[i];

    // Classify address word type
    // LA1: 0x000001 - 0x008000 (first word of long address sets 1-2, 1-3, 1-4)
    // SA:  0x008001 - 0x1E0000 (short address, capcode = aw - 0x8000, range 1-1933312)
    // LA3: 0x1E0001 - 0x1E8000 (second word only, never first)
    // LA4: 0x1E8001 - 0x1F0000 (second word only, never first)
    // Special addresses (short, capcode = aw - 0x8000):
    //   Network:  0x1F0001 - 0x1F77FF
    //   Temporary: 0x1F7800 - 0x1F780F (16 group slots)
    //   Operator:  0x1F7810 - 0x1F781F
    //   Info Svc:  0x1F7820 - 0x1F7FEF
    //   Reserved:  0x1F7FF0 - 0x1F7FFE
    // LA2: 0x1F7FFF - 0x1FFFFE (first word of long address sets 2-3, 2-4)
    flex->Decode.long_address = (aiw >= 0x000001L && aiw <= 0x008000L) ||  // LA1
                                (aiw >= 0x1F7FFFL && aiw <= 0x1FFFFEL);    // LA2

    flex->Decode.addr_type = addr_type_char(aiw, flex->Decode.long_address);
    flex->Decode.capcode = aiw - 0x8000L;  // short address default
    if (flex->Decode.long_address) {
      // Long address decoding using all address sets per ARIB STD-43A Table 3.8.2.2-1.
      // Two address words: w1 = phaseptr[i], w2 = phaseptr[i+1]
      // The set is determined by which range w1 and w2 fall into.
      uint32_t w1 = aiw;
      uint32_t w2;
      // Bounds check: second address word must be within the frame
      if (i + 1 >= voffset) {
        verbprintf(3, "FLEX_NEXT: Long address at end of AF, no room for word 2\n");
        continue;
      }
      // Check for BCH error on second address word
      if (bch_err[i + 1]) {
        verbprintf(3, "FLEX_NEXT: Long address word 2 uncorrectable, skipping\n");
        i++;
        continue;
      }
      w2 = phaseptr[i + 1];

      flex->Decode.capcode = 0;

      // Set 1-2: w1 in LA1 (1-32768), w2 in LA2 (2064383-2097150)
      if (w1 >= 1 && w1 <= 32768 &&
          w2 >= 2064383L && w2 <= 2097150L) {
        flex->Decode.capcode = (int64_t)w1
          + (int64_t)(2097151L - w2) * 32768LL
          + 2068480LL;
      }
      // Set 1-3 / 1-4: w1 in LA1 (1-32768), w2 in LA3/LA4 (1966081-2031616)
      else if (w1 >= 1 && w1 <= 32768 &&
               w2 >= 1966081L && w2 <= 2031616L) {
        flex->Decode.capcode = (int64_t)w1
          + (int64_t)(w2 - 1933312L) * 32768LL
          + 2068480LL;
      }
      // Set 2-3 / 2-4: w1 in LA2 (2064383-2097150), w2 in LA3/LA4 (1966081-2031616)
      else if (w1 >= 2064383L && w1 <= 2097150L &&
               w2 >= 1966081L && w2 <= 2031616L) {
        flex->Decode.capcode = (int64_t)(w1 - 2064383L)
          + (int64_t)(w2 - 1867776L) * 32768LL
          + 2068479LL;
      }
      else {
        verbprintf(3, "FLEX_NEXT: Unknown long address set w1=0x%05X w2=0x%05X\n", w1, w2);
        i++;
        continue;
      }
    }
    if (flex->Decode.capcode > 4297068542LL || flex->Decode.capcode < 0) {
      // Invalid address (by spec, maximum address)
      verbprintf(3, "FLEX_NEXT: Invalid address, capcode out of range %" PRId64 "\n", flex->Decode.capcode);
      continue;
    }
    verbprintf(3, "FLEX_NEXT: CAPCODE:%016" PRIx64 " %" PRId64 "\n", flex->Decode.capcode, flex->Decode.capcode);

    flex_groupmessage = 0;
    flex_groupbit = 0;
    flex->Decode.sec_subtype = NULL;   // reset per page to prevent leaking between messages
    flex->Decode.opr_category = NULL;
          // Temporary Address range per Section 3.8.2.3:
          // aw = 0x1F7800 - 0x1F780F (16 group delivery slots)
          // capcode = aw - 0x8000 = 2029568 - 2029583
          if ((flex->Decode.capcode >= 2029568) && (flex->Decode.capcode <= 2029583)) {
             flex_groupmessage = 1;
             flex_groupbit = flex->Decode.capcode - 2029568;
             if(flex_groupbit < 0) continue;
          }
    if (flex_groupmessage && flex->Decode.long_address) {
      // Invalid (by spec)
      verbprintf(3, "FLEX_NEXT: Don't process group messages if a long address\n");
      return;
    }
    verbprintf(3, "FLEX_NEXT: AIW %u: capcode:%" PRId64 " long:%d group:%d groupbit:%d\n", i, flex->Decode.capcode, flex->Decode.long_address, flex_groupmessage, flex_groupbit);

    /*********************
     * Parse VW
     *
     * Vector word layout (21 data bits) per ARIB STD-43A Section 3.9:
     *   bits 0-3:   checksum
     *   bits 4-6:   V (message type)
     *   bits 7-13:  b (message start word / data field, depends on type)
     *   bits 14-20: n (message word count / data field, depends on type)
     *
     * For alpha/hex/secure (V=000,101,110):
     *   b = first message word index, n = message word count
     *
     * Note on tone-only addresses (Section 3.8.1(6)):
     *   Tone-only addresses sit at the end of the address field with
     *   NO corresponding vector word. They are always short addresses.
     *   We detect them by checking the 4-bit checksum (Section 3.5.1)
     *   on the would-be vector word. Valid vector words always have a
     *   passing checksum. If it fails, this address is tone-only.
     *
     * For long addresses: the 2nd vector word (Vy) holds the first
     * message body word per Section 3.9.1: "the 1st word of the
     * message is placed at the 2nd word of the vector."
     * So the header word is at Vy (j+1), and n is decremented by 1
     * because one body word is already in the vector field.
     *
     * For short addresses: the header word is the first message word
     * (at mw1), and mw1 is incremented past it for content parsing.
     * n is decremented by 1 to account for the header word being
     * part of the message word count.
     */
    // Parse vector information word for address @ offset 'i'
    unsigned int j = voffset + vec_used;   // Vector slot for this address

    // Tone-only detection (Section 3.8.1(6)):
    // Tone-only addresses sit at the end of the address field with no
    // corresponding vector word. They have no vector, so they cannot
    // be long addresses (which require two vector words).
    // The pre-scan counted n_valid_vecs: the number of vector slots that
    // pass the 4-bit checksum.  Once vec_used reaches that count, all
    // remaining addresses are tone-only - no vector consumed.
    if ((int)vec_used >= n_valid_vecs || j >= (unsigned)PHASE_WORDS) {
      if (flex->Decode.long_address) {
        // Long addresses cannot be tone-only - skip as invalid
        verbprintf(3, "FLEX_NEXT: Long address past valid vectors, skipping cap %" PRId64 "\n", flex->Decode.capcode);
        i++;
        continue;
      }
      // Tone-only: address with no vector, output at debug level
      if (flex->Decode.capcode != 1) {  // skip idle artifact capcode 1
        if (!json_mode)
          verbprintf(1, "FLEX_NEXT|%i/%i|%02i.%03i.%c|%010" PRId64 "|%c%c|%d|TON|\n",
                   flex->Sync.baud, flex->Sync.levels,
                   flex->FIW.cycleno, flex->FIW.frameno, PhaseNo,
                   flex->Decode.capcode,
                   addr_type_char(phaseptr[i], flex->Decode.long_address),
                   (flex_groupmessage ? 'G' : 'S'),
                   FLEX_PAGETYPE_TONE_ONLY);
        if (json_mode)
          flex_next_json_emit(flex, PhaseNo, flex->Decode.capcode, flex->Decode.addr_type,
                              0, FLEX_PAGETYPE_TONE_ONLY, "TON", "complete",
                              -1, -1, -1, -1, -1, NULL, NULL, 0, NULL);
      }
      continue;
    }

    // Skip if vector word has BCH error
    if (bch_err[j]) {
      verbprintf(3, "FLEX_NEXT: Vector word %u uncorrectable, skipping page\n", j);
      vec_used += flex->Decode.long_address ? 2 : 1;
      if (flex->Decode.long_address) i++;
      continue;
    }
    uint32_t viw = phaseptr[j];
    flex->Decode.type = ((viw >> 4) & 0x7L);

    // Short Instruction (V=001) must be handled BEFORE hdr/len
    // calculation because instruction vectors use bits 7-20 for
    // instruction data, not message word pointers.  Extracting
    // mw1/len from an instruction vector gives garbage values
    // that can cause "Invalid VIW" false positives.
    if (flex->Decode.type == FLEX_PAGETYPE_SHORT_INSTRUCTION)
                {
                    // Short Instruction Vector (Section 3.9.6):
                    // The 14-bit instruction data is at bits 7-20 of the vector word.
                    // Within the 14-bit field:
                    //   bits 0-2 (vec bits 7-9):   i2i1i0 instruction type
                    //     000 = Temporary Address activation (group setup)
                    //     001 = System Event Notification
                    //     010-111 = reserved
                    //   bits 3-9 (vec bits 10-16):  f6-f0 target frame number
                    //   bits 10-13 (vec bits 17-20): a3-a0 temp address slot (0-15)
                    unsigned int instr_type = (viw >> 7) & 0x07;       // 3-bit instruction type
                    unsigned int iAssignedFrame = (viw >> 10) & 0x7f;  // 7-bit frame number
                    int groupbit = (viw >> 17) & 0x0f;                 // 4-bit slot index

                    // Output the instruction for visibility
                    if (!json_mode) {
                      verbprintf(0, "FLEX_NEXT|%i/%i|%02i.%03i.%c|%010" PRId64 "|%c%c|%1d|INS|i=%u frame=%u group=%d\n",
                               flex->Sync.baud, flex->Sync.levels,
                               flex->FIW.cycleno, flex->FIW.frameno, PhaseNo,
                               flex->Decode.capcode,
                               addr_type_char(phaseptr[i], flex->Decode.long_address),
                               (flex_groupmessage ? 'G' : 'S'),
                               flex->Decode.type,
                               instr_type, iAssignedFrame, groupbit);
                    } else {
                      cJSON *json = cJSON_CreateObject();
                      if (json) {
                        time_t now = time(NULL);
                        struct tm *gmt = gmtime(&now);
                        char ts[64];
                        snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
                                 gmt->tm_year+1900, gmt->tm_mon+1, gmt->tm_mday,
                                 gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
                        cJSON_AddStringToObject(json, "timestamp", ts);
                        cJSON_AddNumberToObject(json, "baud", flex->Sync.baud);
                        cJSON_AddNumberToObject(json, "level", flex->Sync.levels);
                        char ph[2] = { PhaseNo, '\0' };
                        cJSON_AddStringToObject(json, "phase", ph);
                        cJSON_AddNumberToObject(json, "cycle", flex->FIW.cycleno);
                        cJSON_AddNumberToObject(json, "frame", flex->FIW.frameno);
                        cJSON_AddNumberToObject(json, "capcode", (double)flex->Decode.capcode);
                        cJSON_AddStringToObject(json, "msg_type", "instruction");
                        cJSON_AddStringToObject(json, "type_tag", "INS");
                        {
                          const char *itype_name = "reserved";
                          if (instr_type == 0) itype_name = "temp_addr";
                          else if (instr_type == 1) itype_name = "sys_event";
                          cJSON_AddStringToObject(json, "instruction_type", itype_name);
                        }
                        cJSON_AddNumberToObject(json, "target_frame", iAssignedFrame);
                        cJSON_AddNumberToObject(json, "group_slot", groupbit);
                        char *out = cJSON_PrintUnformatted(json);
                        if (out) { fprintf(stdout, "%s\n", out); free(out); }
                        cJSON_Delete(json);
                      }
                    }

                    // Only process temp address activation (i=000)
                    if (instr_type != 0) {
                      vec_used += flex->Decode.long_address ? 2 : 1;
                      if (flex->Decode.long_address) i++;
                      continue;
                    }
                    
                    flex->GroupHandler.GroupCodes[groupbit][CAPCODES_INDEX]++;
                    int CapcodePlacement = flex->GroupHandler.GroupCodes[groupbit][CAPCODES_INDEX];
                    verbprintf(1, "FLEX_NEXT: Temp group setup: bit=%i capcodes=%i adding=[%010" PRId64 "] deliver_frame=%u\n", groupbit, CapcodePlacement, flex->Decode.capcode, iAssignedFrame);

                    flex->GroupHandler.GroupCodes[groupbit][CapcodePlacement] = flex->Decode.capcode;
                    flex->GroupHandler.GroupFrame[groupbit] = iAssignedFrame;

        if(iAssignedFrame > flex->FIW.frameno)
        {
      flex->GroupHandler.GroupCycle[groupbit] = (int)flex->FIW.cycleno;
      verbprintf(4, "FLEX_NEXT: Message frame is in this cycle: %i\n", flex->GroupHandler.GroupCycle[groupbit]);

        }
        else
        {
      if(flex->FIW.cycleno == 15)
                        {
        flex->GroupHandler.GroupCycle[groupbit] = 0;
      }
      else
      {
        flex->GroupHandler.GroupCycle[groupbit] = (int)flex->FIW.cycleno + 1;
          }
      verbprintf(4, "FLEX_NEXT: Message frame is in the next cycle: %i\n", flex->GroupHandler.GroupCycle[groupbit]);
        }


                    // Nothing else to do with this word.. move on!!
                    vec_used += flex->Decode.long_address ? 2 : 1;
                    if (flex->Decode.long_address) i++;
                    continue;
                }

    unsigned int mw1 = (viw >> 7) & 0x7FL;
    unsigned int len;
    unsigned int hdr;

    // Vector n field extraction depends on type (Section 3.9):
    //   Numeric types (V=011,100,111): bits 14-16 = 3-bit n, word_count = n+1
    //     bits 17-20 = K3-K0 checksum (NOT part of word count)
    //   Alpha/Hex/Secure (V=000,101,110): bits 14-20 = 7-bit word count
    //   Short Message (V=010): no word count (data in vector itself)
    //   Instruction (V=001): no word count (instruction data in vector)
    if (flex->Decode.type == FLEX_PAGETYPE_STANDARD_NUMERIC ||
        flex->Decode.type == FLEX_PAGETYPE_SPECIAL_NUMERIC ||
        flex->Decode.type == FLEX_PAGETYPE_NUMBERED_NUMERIC) {
      len = ((viw >> 14) & 0x07) + 1;  // 3-bit n field, word_count = n+1
    } else {
      len = (viw >> 14) & 0x7FL;       // 7-bit word count
    }
    if (flex->Decode.long_address) {
      // Long address: header is in the 2nd vector word (Vy)
      // per Section 3.9.1 / 3.9.3 / 3.9.4
      hdr = j + 1;
      if (len >= 1) {
        // 1st body word is in Vy, so message field has len-1 words
        len--;
      }
    } else {  // short address
      // Short address: header is the first message word
      hdr = mw1;
      mw1++;
      if (len >= 1) {
        // Header word is counted in n, so content is len-1 words.
        // This applies to ALL short address messages including group
        // messages - the header word layout is the same regardless
        // of whether the address is a temporary group delivery slot.
        len--;
      }
    }
    if (hdr >= (unsigned)PHASE_WORDS) {
      verbprintf(3, "FLEX_NEXT: Invalid VIW\n");
      continue;
    }
    // Check BCH status of header word
    if (bch_err[hdr]) {
      verbprintf(3, "FLEX_NEXT: Header word %u uncorrectable, skipping page\n", hdr);
      if (flex->Decode.long_address) i++;
      continue;
    }
    // Fragment flags from the message header word.
    // Bit layout is TYPE-DEPENDENT:
    //
    // Alpha/Secure (V=000,101): Section 3.10.1.3
    //   bits 0-9:   K (10-bit checksum)
    //   bit  10:    C (continuation)
    //   bits 11-12: F (fragment number)
    //   bits 13-18: N (message number)
    //   bit  19:    R (retrieval, initial only)
    //   bit  20:    M (maildrop, initial only)
    //
    // HEX/Binary (V=110): Section 3.10.1.2
    //   bits 0-11:  K (12-bit checksum)
    //   bit  12:    C (continuation)
    //   bits 13-14: F (fragment number)
    //   bits 15-20: N (message number)
    //   R and M are in hdr2 (second message word), not hdr1.
    //
    // Numeric (V=011,100,111): F/C from hdr1 same as alpha layout.
    //   N and R are in the first data word (numbered numeric only).
    //
    // Combined F/C interpretation:
    //   frag==3, cont==0: 'K' - complete message
    //   frag!=3, cont==1: 'F' - fragment, more coming
    //   frag!=3, cont==0: 'C' - continuation/last fragment
    int frag, cont, msg_n, msg_r, msg_m;

    if (flex->Decode.type == FLEX_PAGETYPE_BINARY) {
      // HEX/Binary: 12-bit K, C at bit 12, F at bits 13-14, N at bits 15-20
      frag  = (int) (phaseptr[hdr] >> 13) & 0x3;
      cont  = (int) (phaseptr[hdr] >> 12) & 0x1;
      msg_n = (int) (phaseptr[hdr] >> 15) & 0x3F;
      // R and M are in hdr2 (initial fragment only)
      int is_initial_hex = (frag == 0x03);
      if (is_initial_hex && mw1 < (unsigned)PHASE_WORDS && !bch_err[mw1]) {
        msg_r = (int) (phaseptr[mw1] >> 0) & 0x1;
        msg_m = (int) (phaseptr[mw1] >> 1) & 0x1;
      } else {
        msg_r = -1;
        msg_m = -1;
      }
    } else {
      // Alpha/Secure/Numeric: 10-bit K, C at bit 10, F at bits 11-12, N at bits 13-18
      frag  = (int) (phaseptr[hdr] >> 11) & 0x3;
      cont  = (int) (phaseptr[hdr] >> 10) & 0x1;
      msg_n = (int) (phaseptr[hdr] >> 13) & 0x3F;
      msg_r = (int) (phaseptr[hdr] >> 19) & 0x1;
      msg_m = (int) (phaseptr[hdr] >> 20) & 0x1;
    }
    int is_initial = (frag == 0x03);
    verbprintf(3, "FLEX_NEXT: VIW %u: type:%d mw1:%u len:%u frag:%d N:%d R:%d M:%d\n", j, flex->Decode.type, mw1, len, frag, msg_n, is_initial ? msg_r : -1, is_initial ? msg_m : -1);

    // mw1 == 0 is invalid (word 0 is always BIW), and must be within the frame.
    // The reference decoder only checks mw1 <= 87 - the vector b field can
    // legitimately point anywhere in the frame including the vector field
    // (e.g. long addresses where Vy holds body[0]).
    // For short message (type 2) and numeric types, len can be 0 (all data in vector).
    if (flex->Decode.type == FLEX_PAGETYPE_SHORT_MESSAGE)
      mw1 = len = 0;

    if (mw1 == 0 && len == 0 &&
        flex->Decode.type != FLEX_PAGETYPE_SHORT_MESSAGE &&
        flex->Decode.type != FLEX_PAGETYPE_STANDARD_NUMERIC &&
        flex->Decode.type != FLEX_PAGETYPE_SPECIAL_NUMERIC &&
        flex->Decode.type != FLEX_PAGETYPE_NUMBERED_NUMERIC) {
      verbprintf(3, "FLEX_NEXT: Invalid VIW\n");
      continue;
    }
    if (mw1 >= (unsigned)PHASE_WORDS) {
      verbprintf(3, "FLEX_NEXT: Invalid VIW\n");
      continue;
    }
    // mw1 + len == 89 was observed, but still contained valid page, so truncate
    if ((mw1 + len) > (unsigned)PHASE_WORDS){
      len = (unsigned)PHASE_WORDS - mw1;
    }

    // Log message body BCH errors (damaged words will show as '?' in output)
    {
      unsigned int body_errors = 0;
      unsigned int k;
      for (k = 0; k < len; k++) {
        if ((mw1 + k) < (unsigned)PHASE_WORDS && bch_err[mw1 + k])
          body_errors++;
      }
      if (body_errors > 0) {
        verbprintf(3, "FLEX_NEXT: %u/%u message body words uncorrectable for cap %" PRId64 "\n", body_errors, len, flex->Decode.capcode);
      }
    }

    // Word-level deduplication for complete (K) messages.
    // For fragmented messages (F/C), skip dedup - just reassemble.
    int is_complete = (frag == 3 && cont == 0);
    // 0=new, 1=exact duplicate (DUP), 2=improved retransmission (DUP+)
    int dedup_flag = 0;
    // Pointer/error arrays used for decode. Normally point at the
    // phase data, but may be redirected to merged dedup cache words.
    uint32_t *decode_words = phaseptr;
    int      *decode_errs  = bch_err;
    // Temporary arrays for decoding from dedup cache (merged words).
    // Sized to PHASE_WORDS so all existing index math works unchanged.
    uint32_t  merged_words[PHASE_WORDS];
    int       merged_errs[PHASE_WORDS];

    if (is_complete && len > 0) {
      // Pack message words: words[0]=hdr, words[1..len]=body at mw1
      // Store them contiguously for the dedup cache comparison.
      unsigned int n_msg_words = 1 + len;
      // Build a packed array for the dedup check. The cache stores
      // words packed as [hdr, body0, body1, ...] regardless of their
      // original positions in the frame.
      uint32_t packed_words[FLEX_DEDUP_MAX_WORDS];
      int      packed_errs[FLEX_DEDUP_MAX_WORDS];
      if (n_msg_words <= FLEX_DEDUP_MAX_WORDS) {
        packed_words[0] = phaseptr[hdr];
        packed_errs[0]  = bch_err[hdr];
        unsigned int pw;
        for (pw = 0; pw < len; pw++) {
          packed_words[1 + pw] = phaseptr[mw1 + pw];
          packed_errs[1 + pw]  = bch_err[mw1 + pw];
        }

        int dedup_slot = -1;
        int dedup_rc = dedup_check_words(flex, flex->Decode.capcode,
                                         flex->Decode.type, msg_n,
                                         packed_words, packed_errs,
                                         0, n_msg_words,
                                         0, 1, len, &dedup_slot);
        if (dedup_rc == 1) {
          // Exact duplicate - still output, tagged DUP
          dedup_flag = 1;
        }
        if (dedup_rc == 2 && dedup_slot >= 0) {
          // Improved retransmission - decode from merged cache words.
          dedup_flag = 2;
          memcpy(merged_words, phaseptr, (unsigned)PHASE_WORDS * sizeof(uint32_t));
          memcpy(merged_errs, bch_err, (unsigned)PHASE_WORDS * sizeof(int));
          struct Flex_DedupEntry *de = &flex->DedupStore.entries[dedup_slot];
          merged_words[hdr] = de->words[0];
          merged_errs[hdr]  = de->errs[0];
          for (pw = 0; pw < len; pw++) {
            merged_words[mw1 + pw] = de->words[1 + pw];
            merged_errs[mw1 + pw]  = de->errs[1 + pw];
          }
          decode_words = merged_words;
          decode_errs  = merged_errs;
          verbprintf(3, "FLEX_NEXT: Decoding from merged words for cap %" PRId64 "\n",
                     flex->Decode.capcode);
        }
        // dedup_rc == 0: new message, cached, decode normally
      }
    }

    if (!json_mode) {
      // Build group member capcodes for the capcode field (space-separated)
      // per FLEX output format: capcode member1 member2|...
      char cap_field[1024];
      int cap_pos = snprintf(cap_field, sizeof(cap_field), "%010" PRId64, flex->Decode.capcode);
      if (flex_groupmessage == 1) {
        int endpoint = flex->GroupHandler.GroupCodes[flex_groupbit][CAPCODES_INDEX];
        for (int g = 1; g <= endpoint; g++)
          cap_pos += snprintf(cap_field + cap_pos, sizeof(cap_field) - cap_pos,
                              " %010" PRId64, flex->GroupHandler.GroupCodes[flex_groupbit][g]);
      }
      verbprintf(0, "FLEX_NEXT|%i/%i|%02i.%03i.%c|%s|%c%c|%1d|",
               flex->Sync.baud, flex->Sync.levels,
               flex->FIW.cycleno, flex->FIW.frameno, PhaseNo,
               cap_field,
               flex->Decode.addr_type,
               (flex_groupmessage ? 'G' : 'S'),
               flex->Decode.type);
    }

    // Special address handling per ARIB STD-43A Section 3.8.2.
    // Network, Operator, Info Service, and Reserved addresses carry
    // system-level data that is distinct from normal pager messages.
    // We log them with their address type and fall through to normal
    // message decode for the body content.

    // Network Address (Section 3.8.2.1): carries Service Area ID,
    // Coverage Zone Count, and Traffic Management Flags in the first
    // message word.  Uses Secure (V=000) vector type.
    if (flex->Decode.addr_type == 'N' &&
        flex->Decode.type == FLEX_PAGETYPE_SECURE &&
        mw1 < (unsigned)PHASE_WORDS && !decode_errs[mw1]) {
      uint32_t net_mw = decode_words[mw1];
      unsigned int area_id = net_mw & 0x3F;
      unsigned int zones   = (net_mw >> 6) & 0x1F;
      unsigned int traffic = (net_mw >> 11) & 0x3FF;
      if (!json_mode) {
        verbprintf(0, "NET|area=%u zones=%u traffic=0x%03X\n", area_id, zones, traffic);
      } else {
        cJSON *json = cJSON_CreateObject();
        if (json) {
          time_t now = time(NULL);
          struct tm *gmt = gmtime(&now);
          char ts[64];
          snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
                   gmt->tm_year+1900, gmt->tm_mon+1, gmt->tm_mday,
                   gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
          cJSON_AddStringToObject(json, "timestamp", ts);
          cJSON_AddNumberToObject(json, "baud", flex->Sync.baud);
          cJSON_AddNumberToObject(json, "level", flex->Sync.levels);
          char ph[2] = { PhaseNo, '\0' };
          cJSON_AddStringToObject(json, "phase", ph);
          cJSON_AddNumberToObject(json, "cycle", flex->FIW.cycleno);
          cJSON_AddNumberToObject(json, "frame", flex->FIW.frameno);
          cJSON_AddNumberToObject(json, "capcode", (double)flex->Decode.capcode);
          char at[2] = { flex->Decode.addr_type, '\0' };
          cJSON_AddStringToObject(json, "addr_type", at);
          cJSON_AddStringToObject(json, "msg_type", "secure");
          cJSON_AddStringToObject(json, "type_tag", "NET");
          cJSON_AddNumberToObject(json, "area_id", area_id);
          cJSON_AddNumberToObject(json, "zones", zones);
          cJSON_AddNumberToObject(json, "traffic", traffic);
          char *out = cJSON_PrintUnformatted(json);
          if (out) { fprintf(stdout, "%s\n", out); free(out); }
          cJSON_Delete(json);
        }
      }
      goto page_done;
    }

    // Operator Message Address (Section 3.8.2.5): sub-type in LSB of
    // address word.  Categories: SysMsg (0-3), SSIDChange (0xE),
    // SysEvent (0xF).  Body decoded normally after logging category.
    if (flex->Decode.addr_type == 'O') {
      unsigned int lsb = aiw & 0x0F;
      const char *cat = "unknown";
      if (lsb <= 3)       cat = "SysMsg";
      else if (lsb == 0xE) cat = "SSIDChange";
      else if (lsb == 0xF) cat = "SysEvent";
      flex->Decode.opr_category = cat;
      if (!json_mode) verbprintf(0, "OPR/%s|", cat);
      // Fall through to normal message decode for body content
    }

    // Info Service Address (Section 3.8.2, under study):
    // No defined protocol yet.  Log raw hex payload.
    if (flex->Decode.addr_type == 'I') {
      if (!json_mode) verbprintf(0, "ISV|");
      parse_binary(flex, decode_words, decode_errs, mw1, len, frag, cont, msg_n, msg_r, msg_m, dedup_flag);
      if (!json_mode) verbprintf(0, "\n");
      goto page_done;
    }

    // Reserved Short Address: log and skip (no defined behavior).
    if (flex->Decode.addr_type == 'R') {
      verbprintf(3, "FLEX_NEXT: Reserved short address aw=0x%05X cap=%" PRId64 ", skipping\n",
                 aiw, flex->Decode.capcode);
      goto page_done;
    }

    // Message type dispatch per ARIB STD-43A Section 3.9:
    //   V=000 (0): Secure - encrypted/proprietary content
    //   V=001 (1): Short Instruction - handled above (group setup)
    //   V=010 (2): Short Message Vector
    //   V=011 (3): Standard Numeric - BCD digits
    //   V=100 (4): Special Numeric - BCD with extended header
    //   V=101 (5): Alphanumeric - 7-bit ASCII
    //   V=110 (6): Binary/Hex - raw data
    //   V=111 (7): Numbered Numeric - BCD with message number
    switch (flex->Decode.type) {
    case FLEX_PAGETYPE_ALPHANUMERIC:
      if (!json_mode) verbprintf(0, "ALN|");
      parse_alphanumeric(flex, decode_words, decode_errs, hdr, mw1, len, frag, cont, msg_n, msg_r, msg_m, dedup_flag, flex_groupmessage, flex_groupbit);
      break;
    case FLEX_PAGETYPE_SECURE: {
      // Secure messages (Section 3.9.4, Fig 3.10.1.4-1):
      // Same header layout as alpha, but bits 19-20 = t1t0 sub-type:
      //   t=00: 7-bit alphanumeric (JIS X 0201) - decode as alpha
      //   t=10: binary data - decode as hex
      //   t=01: data defined separately
      //   t=11: reserved
      // Registration Acknowledgment: t=00 with opcode '=' (0x3D) in 2nd word.
      int sec_t = -1;
      if (hdr < (unsigned)PHASE_WORDS && !decode_errs[hdr]) {
        sec_t = (decode_words[hdr] >> 19) & 0x3;
      }
      if (sec_t == 0) {
        // t=00: alphanumeric content - decode like alpha
        if (!json_mode) verbprintf(0, "SEC|");
        flex->Decode.sec_subtype = "alpha";
        parse_alphanumeric(flex, decode_words, decode_errs, hdr, mw1, len, frag, cont, msg_n, msg_r, msg_m, dedup_flag, flex_groupmessage, flex_groupbit);
      } else if (sec_t == 2) {
        // t=10: binary data
        if (!json_mode) verbprintf(0, "SEC:BIN|");
        flex->Decode.sec_subtype = "binary";
        parse_binary(flex, decode_words, decode_errs, mw1, len, frag, cont, msg_n, msg_r, msg_m, dedup_flag);
      } else {
        // t=01, t=11, or unknown: dump as hex
        if (!json_mode) verbprintf(0, "SEC:t%d|", sec_t >= 0 ? sec_t : -1);
        flex->Decode.sec_subtype = (sec_t == 1) ? "vendor" : "reserved";
        parse_binary(flex, decode_words, decode_errs, mw1, len, frag, cont, msg_n, msg_r, msg_m, dedup_flag);
      }
      break;
    }
    case FLEX_PAGETYPE_STANDARD_NUMERIC:
      if (!json_mode) verbprintf(0, "NUM|");
      parse_numeric(flex, decode_words, decode_errs, j, frag, cont, msg_n, msg_r, msg_m, dedup_flag);
      break;
    case FLEX_PAGETYPE_SPECIAL_NUMERIC:
      if (!json_mode) verbprintf(0, "SNUM|");
      parse_numeric(flex, decode_words, decode_errs, j, frag, cont, msg_n, msg_r, msg_m, dedup_flag);
      break;
    case FLEX_PAGETYPE_NUMBERED_NUMERIC:
      if (!json_mode) verbprintf(0, "NNUM|");
      parse_numeric(flex, decode_words, decode_errs, j, frag, cont, msg_n, msg_r, msg_m, dedup_flag);
      break;
    case FLEX_PAGETYPE_SHORT_MESSAGE:
      parse_short_message(flex, decode_words, decode_errs, j);
      break;
    case FLEX_PAGETYPE_BINARY:
      if (!json_mode) verbprintf(0, "HEX|");
      parse_binary(flex, decode_words, decode_errs, mw1, len, frag, cont, msg_n, msg_r, msg_m, dedup_flag);
      break;
    default:
      if (!json_mode) verbprintf(0, "UNK|");
      parse_binary(flex, decode_words, decode_errs, mw1, len, frag, cont, msg_n, msg_r, msg_m, dedup_flag);
      break;
    }
    if (!json_mode) verbprintf(0, "\n");

page_done:
    // long addresses eat 2 aw and 2 vw, so skip the next aw-vw pair
    if (flex->Decode.long_address) {
      vec_used += 2;
      i++;
    } else {
      vec_used++;
    }
  }

  // BIW101 System Message Vector at end of VF (Section 3.9.2, method (a)/(b)).
  // When BIW101 A=0000-0011 is present, a system message vector sits at the
  // END of the vector field (after all normal address/vector pairs).  This
  // vector points to message body words in the MF, same format as a normal
  // alpha/secure vector.  Decode it as a synthetic operator message.
  if (flex->biw_sysmsg_a_type >= 0 && flex->biw_sysmsg_a_type <= 3) {
    int sv_idx = (int)voffset + n_valid_vecs - 1;
    if (sv_idx > (int)voffset + (int)vec_used - 1 &&
        sv_idx < PHASE_WORDS && !bch_err[sv_idx]) {
      uint32_t sv = phaseptr[sv_idx];
      int sv_type = (sv >> 4) & 0x7;
      int sv_mw1 = (sv >> 7) & 0x7F;
      int sv_len = (sv >> 14) & 0x7F;
      if (sv_len > 0 && sv_mw1 < PHASE_WORDS) {
        if (!json_mode) {
          verbprintf(0, "FLEX_NEXT|%i/%i|%02i.%03i.%c|SysMsg_A%d||%1d|SYS|",
                     flex->Sync.baud, flex->Sync.levels,
                     flex->FIW.cycleno, flex->FIW.frameno, PhaseNo,
                     flex->biw_sysmsg_a_type, sv_type);
        }
        if (sv_type == FLEX_PAGETYPE_ALPHANUMERIC && !bch_err[sv_mw1]) {
          int sv_frag = (phaseptr[sv_mw1] >> 11) & 0x3;
          int sv_cont = (phaseptr[sv_mw1] >> 10) & 0x1;
          int sv_msg_n = (phaseptr[sv_mw1] >> 13) & 0x3F;
          int sv_msg_r = (phaseptr[sv_mw1] >> 19) & 0x1;
          int sv_msg_m = (phaseptr[sv_mw1] >> 20) & 0x1;
          int sv_hdr = sv_mw1;
          sv_mw1++;
          if (sv_len > 0) sv_len--;
          if (!json_mode) verbprintf(0, "ALN|");
          parse_alphanumeric(flex, phaseptr, bch_err, sv_hdr, sv_mw1, sv_len, sv_frag, sv_cont, sv_msg_n, sv_msg_r, sv_msg_m, 0, 0, 0);
        } else {
          int sv_frag = 3;
          int sv_cont = 0;
          if (!json_mode) verbprintf(0, "SEC|");
          parse_binary(flex, phaseptr, bch_err, sv_mw1, sv_len, sv_frag, sv_cont, -1, -1, -1, 0);
        }
        if (!json_mode) verbprintf(0, "\n");
      }
    }
  }
}


static void clear_phase_data(struct Flex_Next * flex) {
  if (flex==NULL) return;
  int i;
  for (i = 0; i < PHASE_WORDS; i++) {
    flex->Data.PhaseA.buf[i]=0;
    flex->Data.PhaseB.buf[i]=0;
    flex->Data.PhaseC.buf[i]=0;
    flex->Data.PhaseD.buf[i]=0;
    flex->Data.PhaseA.bch_err[i]=0;
    flex->Data.PhaseB.bch_err[i]=0;
    flex->Data.PhaseC.bch_err[i]=0;
    flex->Data.PhaseD.bch_err[i]=0;
    flex->Data.AltA.buf[i]=0;
    flex->Data.AltB.buf[i]=0;
    flex->Data.AltC.buf[i]=0;
    flex->Data.AltD.buf[i]=0;
    flex->Data.AltA.bch_err[i]=0;
    flex->Data.AltB.bch_err[i]=0;
    flex->Data.AltC.bch_err[i]=0;
    flex->Data.AltD.bch_err[i]=0;
  }

  flex->Data.PhaseA.idle_count=0;
  flex->Data.PhaseB.idle_count=0;
  flex->Data.PhaseC.idle_count=0;
  flex->Data.PhaseD.idle_count=0;
  flex->Data.AltA.idle_count=0;
  flex->Data.AltB.idle_count=0;
  flex->Data.AltC.idle_count=0;
  flex->Data.AltD.idle_count=0;

  flex->Data.phase_toggle=0;
  flex->Data.data_bit_counter=0;

}


static void decode_data(struct Flex_Next * flex) {
  if (flex==NULL) return;

  // Expire stale fragment reassembly slots
  {
    unsigned int abs_frame = flex->FIW.cycleno * 128 + flex->FIW.frameno;
    frag_expire(flex, abs_frame);
  }

  // Phase decode per ARIB STD-43A Section 3.3:
  //   A1 (1600/2FSK): Phase A only
  //   A3 (1600/4FSK): Phase A + Phase C
  //   A2 (3200/2FSK): Phase A + Phase C
  //   A4 (3200/4FSK): Phase A + Phase B + Phase C + Phase D
  if (flex->Sync.baud == 1600) {
    if (flex->Sync.levels==2) {
      decode_phase(flex, 'A');
    } else {
      decode_phase(flex, 'A');
      decode_phase(flex, 'C');
    }
  } else {
    if (flex->Sync.levels==2) {
      decode_phase(flex, 'A');
      decode_phase(flex, 'C');
    } else {
      /* 3200/4FSK: BCH-decode alternate buffers, then substitute
       * alt words into primary where alt BCH succeeds but primary
       * would fail. Primary BCH happens inside decode_phase. */
      {
        struct { struct Flex_Phase *pri; struct Flex_Phase *alt; } pairs[] = {
          { &flex->Data.PhaseA, &flex->Data.AltA },
          { &flex->Data.PhaseB, &flex->Data.AltB },
          { &flex->Data.PhaseC, &flex->Data.AltC },
          { &flex->Data.PhaseD, &flex->Data.AltD },
        };
        char phase_names[] = "ABCD";

        int improved = 0;
        for (int p = 0; p < 4; p++) {
          /* Parse BIW from primary to find frame structure. */
          uint32_t biw_tmp = pairs[p].pri->buf[0];
          int biw_ok = (bch3121_fix_errors(flex, &biw_tmp, phase_names[p]) >= 0);
          unsigned int voffset = PHASE_WORDS;
          unsigned int aoffset_val = 1;
          if (biw_ok) {
            biw_tmp &= 0x1FFFFFL;
            voffset = (biw_tmp >> 10) & 0x3fL;
            aoffset_val = ((biw_tmp >> 8) & 0x3L) + 1;
            if (voffset == 0) voffset = PHASE_WORDS;
          }

          /* Substitute safe regions: BIW region (< aoffset) + body (>= voffset).
           * Address words (aoffset to voffset-1) are skipped to preserve
           * frame parsing integrity. When primary BIW is uncorrectable,
           * voffset=PHASE_WORDS and aoffset=1, so only word 0 (BIW) is
           * substituted — this recovers the phase for decode_phase. */
          for (unsigned int w = 0; w < PHASE_WORDS; w++) {
            uint32_t alt_word = pairs[p].alt->buf[w];
            int alt_rc = bch3121_fix_errors(flex, &alt_word, phase_names[p]);
            uint32_t pri_word = pairs[p].pri->buf[w];
            int pri_rc = bch3121_fix_errors(flex, &pri_word, phase_names[p]);

            if (pri_rc != 0 && alt_rc >= 0 && (w < aoffset_val || w >= voffset)) {
              pairs[p].pri->buf[w] = pairs[p].alt->buf[w];
              improved++;
            }
          }
        }
        if (improved)
          verbprintf(3, "FLEX_NEXT: I&D merge improved %d words\n", improved);
      }
      decode_phase(flex, 'A');
      decode_phase(flex, 'B');
      decode_phase(flex, 'C');
      decode_phase(flex, 'D');
    }
  }
}


static int read_data(struct Flex_Next * flex, unsigned char sym) {
  if (flex==NULL) return -1;
  // Decode one symbol into phase data bits and store into the
  // correct phase buffer(s) per ARIB STD-43A Section 3.3.
  //
  // Mode summary (baud = symbol rate, levels = FSK levels):
  //   A1 (1600 baud, 2FSK):  1600bps, Phase A only
  //   A3 (1600 baud, 4FSK):  3200bps, Phase A (MSB) + Phase C (LSB)
  //   A2 (3200 baud, 2FSK):  3200bps, Phase A + Phase C (interleaved)
  //   A4 (3200 baud, 4FSK):  6400bps, Phase A/B + Phase C/D (interleaved)
  //
  // 4FSK Gray code (Section 3.3.2):
  //   Symbol  bit_a(MSB)  bit_b(LSB)
  //     0        1           1
  //     1        1           0
  //     2        0           0
  //     3        0           1
  //
  // At 1600 baud (A1/A3), every symbol goes to the same phase pair:
  //   A1 (2FSK): bit_a -> Phase A only
  //   A3 (4FSK): bit_a -> Phase A,  bit_b -> Phase C
  // At 3200 baud (A2/A4), symbols alternate between two phase pairs:
  //   A2 (2FSK): even sym bit_a -> Phase A, odd sym bit_a -> Phase C
  //   A4 (4FSK): even sym bit_a -> Phase A, bit_b -> Phase B
  //              odd sym  bit_a -> Phase C, bit_b -> Phase D
  //
  // Bitrates: A1=1600bps, A2=3200bps, A3=3200bps, A4=6400bps.

  int bit_a = (sym > 1);
  int bit_b = 0;
  if (flex->Sync.levels == 4) {
    bit_b = (sym == 1) || (sym == 2);
  }

  if (flex->Sync.baud == 1600) {
    flex->Data.phase_toggle=0;
  }

  // De-interleave index: bits 0-2 map straight through, bits 5+
  // select the word.  This undoes the block interleaving.
  unsigned int idx= ((flex->Data.data_bit_counter>>5)&0xFFF8) |  (flex->Data.data_bit_counter&0x0007);

  if (flex->Data.phase_toggle==0) {
    // At 1600 baud: every symbol.  At 3200 baud: even symbols.
    // bit_a -> Phase A always.
    // bit_b -> Phase C at 1600 baud (A3), Phase B at 3200 baud (A4).
    flex->Data.PhaseA.buf[idx] = (flex->Data.PhaseA.buf[idx]>>1) | (bit_a?(0x80000000):0);
    if (flex->Sync.baud == 1600) {
      flex->Data.PhaseC.buf[idx] = (flex->Data.PhaseC.buf[idx]>>1) | (bit_b?(0x80000000):0);
    } else {
      flex->Data.PhaseB.buf[idx] = (flex->Data.PhaseB.buf[idx]>>1) | (bit_b?(0x80000000):0);
    }
    flex->Data.phase_toggle=1;

    if ((flex->Data.data_bit_counter & 0xFF) == 0xFF) {
      if (flex->Data.PhaseA.buf[idx] == 0x00000000 || flex->Data.PhaseA.buf[idx] == 0xffffffff) flex->Data.PhaseA.idle_count++;
      if (flex->Sync.baud == 1600) {
        if (flex->Data.PhaseC.buf[idx] == 0x00000000 || flex->Data.PhaseC.buf[idx] == 0xffffffff) flex->Data.PhaseC.idle_count++;
      } else {
        if (flex->Data.PhaseB.buf[idx] == 0x00000000 || flex->Data.PhaseB.buf[idx] == 0xffffffff) flex->Data.PhaseB.idle_count++;
      }
    }
  } else {
    // 3200 baud only: odd symbols.
    // bit_a -> Phase C,  bit_b -> Phase D.
    flex->Data.PhaseC.buf[idx] = (flex->Data.PhaseC.buf[idx]>>1) | (bit_a?(0x80000000):0);
    flex->Data.PhaseD.buf[idx] = (flex->Data.PhaseD.buf[idx]>>1) | (bit_b?(0x80000000):0);
    flex->Data.phase_toggle=0;

    if ((flex->Data.data_bit_counter & 0xFF) == 0xFF) {
      if (flex->Data.PhaseC.buf[idx] == 0x00000000 || flex->Data.PhaseC.buf[idx] == 0xffffffff) flex->Data.PhaseC.idle_count++;
      if (flex->Data.PhaseD.buf[idx] == 0x00000000 || flex->Data.PhaseD.buf[idx] == 0xffffffff) flex->Data.PhaseD.idle_count++;
    }
  }

  if (flex->Sync.baud == 1600 || flex->Data.phase_toggle==0) {
    flex->Data.data_bit_counter++;
  }

  // Report if all active phases have gone idle
  int idle=0;
  if (flex->Sync.baud == 1600) {
    if (flex->Sync.levels==2) {
      idle=(flex->Data.PhaseA.idle_count>IDLE_THRESHOLD);
    } else {
      idle=((flex->Data.PhaseA.idle_count>IDLE_THRESHOLD) && (flex->Data.PhaseC.idle_count>IDLE_THRESHOLD));
    }
  } else {
    if (flex->Sync.levels==2) {
      idle=((flex->Data.PhaseA.idle_count>IDLE_THRESHOLD) && (flex->Data.PhaseC.idle_count>IDLE_THRESHOLD));
    } else {
      idle=((flex->Data.PhaseA.idle_count>IDLE_THRESHOLD) && (flex->Data.PhaseB.idle_count>IDLE_THRESHOLD) && (flex->Data.PhaseC.idle_count>IDLE_THRESHOLD) && (flex->Data.PhaseD.idle_count>IDLE_THRESHOLD));
    }
  }

  return idle;
}


static void report_state(struct Flex_Next * flex) {
  if (flex->State.Current != flex->State.Previous) {
    flex->State.Previous = flex->State.Current;

    char * state="Unknown";
    switch (flex->State.Current) {
      case FLEX_STATE_SYNC1:
        state="SYNC1";
        break;
      case FLEX_STATE_FIW:
        state="FIW";
        break;
      case FLEX_STATE_SYNC2:
        state="SYNC2";
        break;
      case FLEX_STATE_DATA:
        state="DATA";
        break;
      default:
        break;

    }
    verbprintf(1, "FLEX_NEXT: State: %s\n", state);
  }
}

//Called for each received symbol
static void flex_sym(struct Flex_Next * flex, unsigned char sym) {
  if (flex==NULL) return;
  /*If the signal has a negative polarity, the symbols must be inverted*/
  /*Polarity is determined during the IDLE/sync word checking phase*/
  unsigned char sym_rectified;
  if (flex->Sync.polarity) {
    sym_rectified=3-sym;
  } else {
    sym_rectified=sym;
  }

  switch (flex->State.Current) {
    case FLEX_STATE_SYNC1:
      {
        // Continually compare the received symbol stream
        // against the known FLEX sync words.
        unsigned int sync_code=flex_sync(flex, sym); //Unrectified version of the symbol must be used here
        if (sync_code!=0) {
          decode_mode(flex,sync_code);

          if (flex->Sync.baud!=0 && flex->Sync.levels!=0) {
            flex->State.Current=FLEX_STATE_FIW;

            verbprintf(2, "FLEX_NEXT: SyncInfoWord: sync_code=0x%04x baud=%i levels=%i polarity=%s zero=%f envelope=%f symrate=%f\n",
                sync_code, flex->Sync.baud, flex->Sync.levels, flex->Sync.polarity?"NEG":"POS", flex->Modulation.zero, flex->Modulation.envelope, flex->Modulation.symbol_rate);
          } else {
            verbprintf(2, "FLEX_NEXT: Unknown Sync code = 0x%04x\n", sync_code);
            flex->State.Current=FLEX_STATE_SYNC1;
          }
        } else {
          flex->State.Current=FLEX_STATE_SYNC1;
        }

        flex->State.fiwcount=0;
        flex->FIW.rawdata=0;
        break;
      }
    case FLEX_STATE_FIW:
      {
        // Skip 16 bits of dotting, then accumulate 32 bits
        // of Frame Information Word.
        // FIW is accumulated, call BCH to error correct it
        flex->State.fiwcount++;
        if (flex->State.fiwcount>=16) {
          read_2fsk(flex, sym_rectified, &flex->FIW.rawdata);
        }

        if (flex->State.fiwcount==48) {
          if (decode_fiw(flex)==0) {
            flex->State.sync2_count=0;
            flex->State.sync2_shiftreg=0;
            flex->State.sync2_c_found=0;
            flex->State.sync2_c_pos=0;
            flex->State.sync2_sym_buf_count=0;
            flex->State.sync2_sym_buf_start=0;
            flex->Demodulator.baud = flex->Sync.baud;
            flex->State.Current=FLEX_STATE_SYNC2;
          } else {
            flex->State.Current=FLEX_STATE_SYNC1;
          }
        }
        break;
      }
    case FLEX_STATE_SYNC2:
      {
        // S2 structure per Section 3.2:
        //   BS2 + C(16 bits) + inv.BS2 + inv.C(16 bits) = 25ms total
        //   At 1600bps/2FSK: 4+16+4+16 = 40 symbols  (1 bit/sym)
        //   At 3200bps/2FSK: 24+16+24+16 = 80 symbols (1 bit/sym)
        //   At 3200bps/4FSK: 12+8+12+8 = 40 symbols   (2 bits/sym)
        //   At 6400bps/4FSK: 32+8+32+8 = 80 symbols   (2 bits/sym)
        //
        // C ends at s2_symbols/2, inv.C ends at s2_symbols.
        // We correlate the 16-bit shift register against both patterns
        // and use the detected position to correct the S2/DATA boundary.
        unsigned int s2_symbols = flex->Sync.baud*25/1000;
        unsigned int bits_per_sym = (flex->Sync.levels == 4) ? 2 : 1;
        unsigned int c_sym_len = 16 / bits_per_sym;  // C pattern width in symbols
        int bit_a = (sym_rectified > 1);

        if (flex->Sync.levels == 4) {
          int bit_b = (sym_rectified == 1) || (sym_rectified == 2);
          flex->State.sync2_shiftreg = (uint16_t)(
            (flex->State.sync2_shiftreg << 2) | (bit_a << 1) | bit_b);
        } else {
          flex->State.sync2_shiftreg = (uint16_t)(
            (flex->State.sync2_shiftreg << 1) | bit_a);
        }

        flex->State.sync2_count++;

        // Check for C and inv.C after enough symbols for 16 bits
        if (flex->State.sync2_count >= c_sym_len && !flex->State.sync2_c_found) {
          unsigned int c_errs = count_bits(flex, flex->State.sync2_shiftreg ^ FLEX_S2_C);
          unsigned int cinv_errs = count_bits(flex, flex->State.sync2_shiftreg ^ FLEX_S2_C_INV);
          if (c_errs <= 2) {
            flex->State.sync2_c_found = 1;  // C
            flex->State.sync2_c_pos = flex->State.sync2_count;
            verbprintf(3, "FLEX_NEXT: S2 C-pattern detected at symbol %u/%u (%u errors)\n",
                       flex->State.sync2_count, s2_symbols, c_errs);
          } else if (cinv_errs <= 2) {
            flex->State.sync2_c_found = 2;  // inv.C
            flex->State.sync2_c_pos = flex->State.sync2_count;
            verbprintf(3, "FLEX_NEXT: S2 inv.C detected at symbol %u/%u (%u errors)\n",
                       flex->State.sync2_count, s2_symbols, cinv_errs);
          }
        }

        // Buffer symbols near the nominal boundary [nominal-2 .. nominal+2).
        // These may be data symbols if the boundary is earlier than nominal.
        if ((int)flex->State.sync2_count >= (int)s2_symbols - 2 &&
            flex->State.sync2_sym_buf_count < 4) {
          if (flex->State.sync2_sym_buf_count == 0)
            flex->State.sync2_sym_buf_start = flex->State.sync2_count;
          flex->State.sync2_sym_buf[flex->State.sync2_sym_buf_count++] = sym_rectified;
        }

        // Scan past the nominal boundary (+2 symbols) to catch inv.C
        if (flex->State.sync2_count >= s2_symbols + 2) {
          int boundary = (int)s2_symbols;  // default: blind count

          if (!flex->State.sync2_c_found) {
            verbprintf(3, "FLEX_NEXT: S2 ended at %u symbols, NO C/inv.C found (baud=%u levels=%u last_reg=0x%04X)\n",
                       flex->State.sync2_count, flex->Sync.baud, flex->Sync.levels,
                       flex->State.sync2_shiftreg);
          } else {
            // Use C position to determine actual boundary.
            // C ends at s2_symbols/2, inv.C ends at s2_symbols.
            unsigned int expected = (flex->State.sync2_c_found == 1)
              ? s2_symbols / 2
              : s2_symbols;
            int offset = (int)flex->State.sync2_c_pos - (int)expected;
            if (offset != 0 && offset >= -2 && offset <= 2) {
              boundary = (int)s2_symbols + offset;
              verbprintf(3, "FLEX_NEXT: S2 boundary correction: %+d symbols (boundary=%d)\n", offset, boundary);
            }
          }

          // Transition to DATA
          flex->State.data_count = 0;
          clear_phase_data(flex);
          flex->State.Current=FLEX_STATE_DATA;

          // Replay buffered symbols that fall at or after the boundary.
          // These are data symbols that arrived while we were still in SYNC2.
          {
            int k;
            for (k = 0; k < flex->State.sync2_sym_buf_count; k++) {
              int sym_pos = flex->State.sync2_sym_buf_start + k;
              if (sym_pos >= boundary) {
                read_data(flex, flex->State.sync2_sym_buf[k]);
                flex->State.data_count++;
              }
            }
          }
        }

        break;
      }
    case FLEX_STATE_DATA:
      {
        // The data portion of the frame is 1760 ms long at either
        // baudrate.  This is 2816 bits @ 1600 bps and 5632 bits @ 3200 bps.
        // The output_symbol() routine decodes and doles out the bits
        // to each of the four transmitted phases of FLEX interleaved codes.
        int idle = 0;
        idle = read_data(flex, sym_rectified);
        if (++flex->State.data_count == flex->Sync.baud*1760/1000 || idle) {
          decode_data(flex);
          flex->Demodulator.baud = 1600;
          flex->State.Current=FLEX_STATE_SYNC1;
          flex->State.data_count=0;
        }
        break;
      }
  }
}

static int buildSymbol(struct Flex_Next * flex, double sample) {
        if (flex == NULL) return 0;

        const int64_t phase_max = 100 * flex->Demodulator.sample_freq;                           // Maximum value for phase (calculated to divide by sample frequency without remainder)
        const int64_t phase_rate = phase_max*flex->Demodulator.baud / flex->Demodulator.sample_freq;      // Increment per baseband sample
        const double phasepercent = 100.0 *  flex->Demodulator.phase / phase_max;

        /*Update the sample counter*/
        flex->Demodulator.sample_count++;

        /*Remove DC offset (FIR filter)*/
        if (flex->State.Current == FLEX_STATE_SYNC1) {
                flex->Modulation.zero = (flex->Modulation.zero*(FREQ_SAMP*DC_OFFSET_FILTER) + sample) / ((FREQ_SAMP*DC_OFFSET_FILTER) + 1);
        }
        sample -= flex->Modulation.zero;

        if (flex->Demodulator.locked) {
                /*During the synchronisation period, establish the envelope of the signal*/
                if (flex->State.Current == FLEX_STATE_SYNC1) {
                        flex->Demodulator.envelope_sum += fabs(sample);
                        flex->Demodulator.envelope_count++;
                        flex->Modulation.envelope = flex->Demodulator.envelope_sum / flex->Demodulator.envelope_count;
                }
        }
        else {
                /*Reset and hold in initial state*/
                flex->Modulation.envelope = 0;
                flex->Demodulator.envelope_sum = 0;
                flex->Demodulator.envelope_count = 0;
                flex->Demodulator.baud = 1600;
                flex->Demodulator.timeout = 0;
                flex->Demodulator.nonconsec = 0;
                flex->State.Current = FLEX_STATE_SYNC1;
        }

        /* MID 80% SYMBOL PERIOD: accumulate for both majority vote and I&D */
        if (phasepercent > 10 && phasepercent <90) {
                /* Majority vote bins */
                if (sample > 0) {
                        if (sample > flex->Modulation.envelope*SLICE_THRESHOLD)
                                flex->Demodulator.symcount[3]++;
                        else
                                flex->Demodulator.symcount[2]++;
                }
                else {
                        if (sample < -flex->Modulation.envelope*SLICE_THRESHOLD)
                                flex->Demodulator.symcount[0]++;
                        else
                                flex->Demodulator.symcount[1]++;
                }
                /* Integrate-and-dump: use tighter window that excludes
                 * inter-symbol transitions.  Transition duration is
                 * ~sample_rate/(2*baud) samples per side, which is
                 * 50*baud/sample_rate percent of the symbol period.
                 * At 3200 baud/22050 Hz: ~7.3% per side -> 25%-75% window.
                 * At 1600 baud/22050 Hz: ~3.6% per side -> 14%-86% window.
                 * Use 25% margin to be safe. */
                if (phasepercent > 25 && phasepercent < 75) {
                        flex->Demodulator.sym_sum += sample;
                        flex->Demodulator.sym_n++;
                }
        }

        /* ZERO CROSSING */
        if ((flex->Demodulator.sample_last<0 && sample >= 0) || (flex->Demodulator.sample_last >= 0 && sample<0)) {
                /*The phase error has a direction towards the closest symbol boundary*/
                double phase_error = 0.0;
                if (phasepercent<50) {
                        phase_error = flex->Demodulator.phase;
                }
                else {
                        phase_error = flex->Demodulator.phase - phase_max;
                }

                /*Phase lock with the signal*/
                if (flex->Demodulator.locked) {
                        flex->Demodulator.phase -= phase_error * PHASE_LOCKED_RATE;
                }
                else {
                        flex->Demodulator.phase -= phase_error * PHASE_UNLOCKED_RATE;
                }

                /*If too many zero crossing occur within the mid 80% then indicate lock has been lost*/
                if (phasepercent > 10 && phasepercent < 90) {
                        flex->Demodulator.nonconsec++;
                        if (flex->Demodulator.nonconsec>20 && flex->Demodulator.locked) {
                                verbprintf(1, "FLEX_NEXT: Synchronisation Lost\n");
                                flex->Demodulator.locked = 0;
                        }
                }
                else {
                        flex->Demodulator.nonconsec = 0;
                }

                flex->Demodulator.timeout = 0;
        }
        flex->Demodulator.sample_last = sample;

  /* END OF SYMBOL PERIOD */
  flex->Demodulator.phase += phase_rate;

  if (flex->Demodulator.phase > phase_max) {
    flex->Demodulator.phase -= phase_max;
    return 1;
  } else {
    return 0;
  }

}

static void Flex_Demodulate(struct Flex_Next * flex, double sample) {
  if(flex == NULL) return;

  if (buildSymbol(flex, sample) == 1) {
                flex->Demodulator.nonconsec = 0;
    flex->Demodulator.symbol_count++;
    flex->Modulation.symbol_rate = 1.0 * flex->Demodulator.symbol_count*flex->Demodulator.sample_freq / flex->Demodulator.sample_count;

    /* PRIMARY: Majority vote symbol decision (original method) */
    int j;
    int decmax = 0;
    int symbol = 0;
    for (j = 0; j<4; j++) {
      if (flex->Demodulator.symcount[j] > decmax) {
        symbol = j;
        decmax = flex->Demodulator.symcount[j];
      }
    }
    flex->Demodulator.symcount[0] = 0;
    flex->Demodulator.symcount[1] = 0;
    flex->Demodulator.symcount[2] = 0;
    flex->Demodulator.symcount[3] = 0;

    /* ALTERNATE: Integrate-and-dump symbol decision */
    int alt_symbol = 1;
    if (flex->Demodulator.sym_n > 0) {
      double mean = flex->Demodulator.sym_sum / flex->Demodulator.sym_n;
      double thr = flex->Modulation.envelope * SLICE_THRESHOLD_IAD;
      if (mean > 0)
        alt_symbol = (mean > thr) ? 3 : 2;
      else
        alt_symbol = (mean < -thr) ? 0 : 1;
    }
    flex->Demodulator.sym_sum = 0;
    flex->Demodulator.sym_n = 0;

    /* Feed alternate symbols into AltA/B/C/D during data.
     * Both bit_a and bit_b may differ between vote and I&D. */
    if (flex->Demodulator.locked && flex->State.Current == FLEX_STATE_DATA
        && flex->Sync.levels == 4 && flex->Sync.baud == 3200) {
      /* Use I&D's own bit_a and bit_b for alternate phase buffers. */
      int alt_bit_a = (alt_symbol > 1);
      int alt_bit_b = (alt_symbol == 1) || (alt_symbol == 2);
      unsigned int idx = ((flex->Data.data_bit_counter>>5)&0xFFF8) | (flex->Data.data_bit_counter&0x0007);
      if (idx < PHASE_WORDS) {
        if (flex->Data.phase_toggle == 0) {
          /* Even symbol: bit_a -> AltA, bit_b -> AltB */
          flex->Data.AltA.buf[idx] = (flex->Data.AltA.buf[idx]>>1) | (alt_bit_a?(0x80000000):0);
          flex->Data.AltB.buf[idx] = (flex->Data.AltB.buf[idx]>>1) | (alt_bit_b?(0x80000000):0);
        } else {
          /* Odd symbol: bit_a -> AltC, bit_b -> AltD */
          flex->Data.AltC.buf[idx] = (flex->Data.AltC.buf[idx]>>1) | (alt_bit_a?(0x80000000):0);
          flex->Data.AltD.buf[idx] = (flex->Data.AltD.buf[idx]>>1) | (alt_bit_b?(0x80000000):0);
        }
      }
    }


    if (flex->Demodulator.locked) {
      /*Process the symbol*/
      flex_sym(flex, symbol);
    }
    else {
      /*Check for lock pattern*/
      flex->Demodulator.lock_buf = (flex->Demodulator.lock_buf << 2) | (symbol ^ 0x1);
      uint64_t lock_pattern = flex->Demodulator.lock_buf ^ 0x6666666666666666ull;
      uint64_t lock_mask = (1ull << (2 * LOCK_LEN)) - 1;
      if ((lock_pattern&lock_mask) == 0 || ((~lock_pattern)&lock_mask) == 0) {
        verbprintf(1, "FLEX_NEXT: Locked\n");
        flex->Demodulator.locked = 1;
        /*Clear the syncronisation buffer*/
        flex->Demodulator.lock_buf = 0;
        flex->Demodulator.symbol_count = 0;
        flex->Demodulator.sample_count = 0;
      }
    }

    /*Time out after X periods with no zero crossing*/
    flex->Demodulator.timeout++;
    if (flex->Demodulator.timeout>DEMOD_TIMEOUT) {
      verbprintf(1, "FLEX_NEXT: Timeout\n");
      flex->Demodulator.locked = 0;
    }
  }

  report_state(flex);
}

static void Flex_Delete(struct Flex_Next * flex) {
  if (flex==NULL) return;
  free(flex);
}


static struct Flex_Next * Flex_New(unsigned int SampleFrequency) {
  struct Flex_Next *flex=(struct Flex_Next *)malloc(sizeof(struct Flex_Next));
  if (flex!=NULL) {
    memset(flex, 0, sizeof(struct Flex_Next));

    flex->Demodulator.sample_freq=SampleFrequency;
    // The baud rate of first syncword and FIW is always 1600, so set that
    // rate to start.
    flex->Demodulator.baud = 1600;

    /* Initialize BCH tables (does nothing if already initialized) */
    bch_init();

    for(int g = 0; g < GROUP_BITS; g++)
    {
      flex->GroupHandler.GroupFrame[g] = -1;
          flex->GroupHandler.GroupCycle[g] = -1;
    }
  }

  return flex;
}


static void flex_next_demod(struct demod_state *s, buffer_t buffer, int length) {
  if (s==NULL) return;
  if (s->l1.flex_next==NULL) return;
  int i;
  for (i=0; i<length; i++) {
    Flex_Demodulate(s->l1.flex_next, buffer.fbuffer[i]);
  }
}


static void flex_next_init(struct demod_state *s) {
  if (s==NULL) return;
  s->l1.flex_next=Flex_New(FREQ_SAMP);
}


static void flex_next_deinit(struct demod_state *s) {
  if (s==NULL) return;
  if (s->l1.flex_next==NULL) return;

  Flex_Delete(s->l1.flex_next);
  s->l1.flex_next=NULL;
}


const struct demod_param demod_flex_next = {
  "FLEX_NEXT", true, FREQ_SAMP, FILTLEN, flex_next_init, flex_next_demod, flex_next_deinit
};
