/*
 *      demod_gsc.c -- GSC (Golay Sequential Code) paging decoder
 *
 *      Copyright (C) 2026 Vasyl Samoilov (vasyl.samoilov@gmail.com)
 *
 *      Credits: Andreas Eversberg (jolly@eversberg.eu) for the original
 *      GSC encoder in the osmocom-analog project.
 *
 *      GSC is a 600 baud 2-FSK paging protocol using Golay(23,12) and
 *      BCH(15,7) error correction.  Messages consist of preamble, start
 *      code, address word pairs, and data blocks (alpha/numeric/tone/voice).
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#include "multimon.h"
#include "bch.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

/* ---------------------------------------------------------------------- */

#define FREQ_SAMP 22050
#define BAUD 600
#define SUBSAMP 2
#define FILTLEN 1

#define SPHASEINC (0x10000u * BAUD * SUBSAMP / FREQ_SAMP)

/* ---------------------------------------------------------------------- */
/* Protocol constants                                                     */
/* ---------------------------------------------------------------------- */

#define GSC_PREAMBLE_REPS 18   /* preamble codewords per batch */
#define GSC_COMMA_LEN 28       /* comma sequence length in bits */
#define GSC_DUP_BITS 46        /* duplicate-transmitted Golay codeword */
#define GSC_BCH_BLOCK_BITS 120 /* interleaved BCH block (15 x 8) */
#define GSC_START_CODE 713     /* start code value */
#define GSC_MAX_ADB 32         /* max alpha data blocks (256 chars, protocol has no fixed limit) */
#define GSC_MAX_NDB 2          /* max numeric data blocks (24 digits) */
#define GSC_MAX_BITS 16384     /* max bits in rx buffer (batch with 2 long messages ~10k bits) */
#define GSC_EOT_THRESHOLD 48   /* consecutive same-value bits = end of TX */

/* Activation code for voice messages (Golay-encoded) */
#define GSC_ACTIVATION_CODE 2563

/* Preamble values */
static const unsigned short preamble_values[10] = {
    2030, 1628, 3198, 647, 191, 3315, 1949, 2540, 1560, 2335,
};

/* Word 1 table */
static const unsigned short word1s[50] = {
    721,  2731, 2952, 1387, 1578, 1708, 2650, 1747, 2580, 1376, 2692, 696,  1667, 3800, 3552, 3424, 1384,
    3595, 876,  3124, 2285, 2608, 899,  3684, 3129, 2124, 1287, 2616, 1647, 3216, 375,  1232, 2824, 1840,
    408,  3127, 3387, 882,  3468, 3267, 1575, 3463, 3152, 2572, 1252, 2592, 1552, 835,  1440, 160,
};

/* ---------------------------------------------------------------------- */
/* Character decode tables                                                */
/* ---------------------------------------------------------------------- */

/* Alpha: 6-bit code -> ASCII */
static const char alpha_table[64] = {
    ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', '0',  '1', '2',  '3', '4', '5',
    '6', '7', '8', '9', ':', ';', '<', '=',  '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F',  'G', 'H',  'I', 'J', 'K',
    'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',  'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\r', ']', '\0', '_',
};

/* Numeric: 4-bit code -> character (unshifted) */
static const char numeric_table[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '\0', 'U', ' ', '-', '*', '\0',
};

/* Numeric: 4-bit code -> character (after 0xF shift prefix) */
static const char numeric_shift_table[16] = {
    'A', 'B', 'C', 'D', 'E', ' ', 'F', 'G', 'H', 'J', '\0', 'L', 'N', 'P', 'R', '?',
};

/* ---------------------------------------------------------------------- */
/* GSC decoder state (stored in demod_state)                              */
/* ---------------------------------------------------------------------- */

/* RX state machine */
enum gsc_rx_state {
    GSC_IDLE,     /* scanning for preamble */
    GSC_PREAMBLE, /* confirming preamble lock */
    GSC_DATA,     /* buffering post-preamble bits */
    GSC_VOICE,    /* voice message in progress */
};

#define GSC_PREAMBLE_LOCK 3 /* consecutive matches to confirm lock */

struct gsc_state {
    /* L1 demod state (PLL bit clock recovery) */
    uint32_t dcd_shreg;
    uint32_t sphase;
    uint32_t subsamp;

    /* L2 state */
    enum gsc_rx_state state;
    int preamble_index;    /* detected preamble (0-9) */
    int polarity_inverted; /* 1 = inverted signal */
    int batch_candidate;   /* 1 = inverted preamble, defer polarity decision */

    /* bit buffer for batch decode */
    uint8_t rx_bit[GSC_MAX_BITS];
    int rx_bit_num;

    /* preamble shift register (46 bits for one dup Golay codeword) */
    uint8_t rx_shift[46];
    int rx_shift_count;

    /* preamble confirmation */
    int confirm_index;
    int confirm_count;
    uint8_t confirm_bits[46 * GSC_PREAMBLE_REPS];
    int confirm_bit_count;

    /* end-of-transmission detection */
    int no_transition;

    /* voice tracking */
    char voice_address[16]; /* 7-digit GSC address */
    int voice_function;

    /* error stats */
    int error_count;
    int uncorrectable_count;
};

/* ---------------------------------------------------------------------- */
/* Helper: resolve 46-bit shift register to 23-bit Golay codeword         */
/* Each bit is transmitted twice; when pair disagrees, prefer first bit.  */
/* ---------------------------------------------------------------------- */

/* Escape newlines/CRs for single-line log output. Static buffer. */
static const char *esc_nl(const char *s)
{
    static char buf[GSC_MAX_ADB * 8 * 2 + 1];
    int i = 0;
    while (*s && i < (int)sizeof(buf) - 3) {
        if (*s == '\n') { buf[i++] = '\\'; buf[i++] = 'n'; }
        else if (*s == '\r') { buf[i++] = '\\'; buf[i++] = 'r'; }
        else buf[i++] = *s;
        s++;
    }
    buf[i] = '\0';
    return buf;
}

static unsigned int resolve_shift_register(const uint8_t *shift)
{
    unsigned int codeword = 0;
    int i;

    for (i = 0; i < 23; i++) {
        uint8_t bit1 = shift[i * 2];
        uint8_t bit2 = shift[i * 2 + 1];
        uint8_t resolved = (bit1 == bit2) ? bit1 : bit1;
        codeword |= ((unsigned int)resolved << i);
    }
    return codeword;
}

/* ---------------------------------------------------------------------- */
/* Helper: read duplicate Golay codeword from bit buffer                  */
/* ---------------------------------------------------------------------- */

static unsigned int read_dup_golay(const uint8_t *bits, int *pos)
{
    unsigned int codeword = 0;
    int p = *pos;
    int i;

    for (i = 0; i < 23; i++) {
        uint8_t bit1 = bits[p];
        uint8_t bit2 = bits[p + 1];
        codeword |= ((unsigned int)((bit1 == bit2) ? bit1 : bit1) << i);
        p += 2;
    }
    *pos = p;
    return codeword;
}

/* ---------------------------------------------------------------------- */
/* Helper: de-interleave 8 BCH(15,7) codewords from bit buffer            */
/* Reads 120 bits (15 bit-positions x 8 codewords, interleaved).          */
/* ---------------------------------------------------------------------- */

static void deinterleave_bch(const uint8_t *bits, int *pos, unsigned short bch[8])
{
    int p = *pos;
    int j, k;

    for (k = 0; k < 8; k++)
        bch[k] = 0;

    for (j = 0; j < 15; j++) {
        for (k = 0; k < 8; k++) {
            bch[k] |= (unsigned short)(bits[p] & 1) << j;
            p++;
        }
    }
    *pos = p;
}

/* ---------------------------------------------------------------------- */
/* Helper: match decoded Golay value against preamble table               */
/* Returns preamble index (0-9) or -1 if no match.                        */
/* ---------------------------------------------------------------------- */

static int match_preamble(unsigned short value)
{
    int i;
    for (i = 0; i < 10; i++) {
        if (value == preamble_values[i])
            return i;
    }
    return -1;
}

/* ---------------------------------------------------------------------- */
/* Helper: reverse W1 -> group digits (G1, G0)                            */
/* ---------------------------------------------------------------------- */

static int reverse_word1(unsigned short w1, int *g1, int *g0)
{
    int i;
    for (i = 0; i < 50; i++) {
        if (word1s[i] == w1) {
            *g1 = i / 10;
            *g0 = i % 10;
            return 0;
        }
    }
    return -1;
}

/* ---------------------------------------------------------------------- */
/* Helper: reverse W2 -> address digits (A2, A1, A0)                      */
/*                                                                        */
/* GSC address format: I G1 G0 A2 A1 A0 F (7 digits)                      */
/*   I    = Index digit (0-9), selects preamble: (I + G0) % 10            */
/*   G1G0 = Group digits (00-99), selects Word 1 via word1s[G1G0 % 50]    */
/*   A2A1A0 = Address digits, encoded into Word 2                         */
/*   F    = Function suffix, determines message type:                     */
/*          1-4 = voice, 5-8 = alpha/numeric, 9/0 = tone                  */
/*                                                                        */
/* Code Assignment Plans:                                                 */
/*   Plan 1: 50-100 codes, 1 preamble, fixed G1G0A2                       */
/*   Plan 2: 500-1000 codes, 10 preambles, fixed G1A2                     */
/*   Plan 3: 500-1000 codes, 1 preamble, fixed G1A2                       */
/*   Plan 4: 5000-10000 codes, 10 preambles, fixed G1                     */
/*   Plan 5: 5000-10000 codes, 1 preamble (I fixed), fixed G0             */
/*   Plan 6: 50000-100000 codes, 50 preambles, all digits variable        */
/*                                                                        */
/* Invalid GSC codes:                                                     */
/*   Certain A2A1A0 values are invalid for given G1G0 ranges and must     */
/*   be skipped when assigning codes. These arise from the W2 address     */
/*   arithmetic producing values that collide with protocol-reserved      */
/*   codewords or cause ambiguity in the W2-to-address reverse mapping.   */
/*                                                                        */
/*   G1G0 00-49: A2A1A0 must not equal                                    */
/*     000, 025, 051, 103, 206, 340, 363, 412,                            */
/*     445, 530, 642, 726, 782, 810, 825, 877                             */
/*                                                                        */
/*   G1G0 50-99: A2A1A0 must not equal                                    */
/*     000, 292, 425, 584, 631, 841, 851                                  */
/*                                                                        */
/*   For non-battery-saver ("N" code) systems, G1G0 must never            */
/*   equal 40 or 90 regardless of A2A1A0.                                 */
/*                                                                        */
/* W1 table ambiguity: word1s[] has 50 entries. G1G0 0-49 maps directly,  */
/* G1G0 50-99 uses word1s[G1G0-50] (same entry, W2 offset by +50).        */
/* The decoder tries both ranges and uses reverse_word2() success as      */
/* the discriminator. When both ranges produce valid addresses (the       */
/* invalid code tables do not cover all cases), the result is ambiguous.  */
/* A real pager knows its own address; a monitoring decoder cannot        */
/* always disambiguate.                                                   */
/* ---------------------------------------------------------------------- */

static int reverse_word2(unsigned short w2, int g1g0, int *a2, int *a1, int *a0)
{
    int raw, b3b2, b1b0;
    int ap3, ap2, ap1, ap0, ap;

    if (g1g0 >= 50)
        raw = w2 - 50;
    else
        raw = w2;

    /* raw must be non-negative for valid arithmetic */
    if (raw < 0)
        return -1;

    b3b2 = raw / 100;
    b1b0 = raw % 100;
    ap3 = b3b2 / 10;
    ap2 = b3b2 % 10;
    ap1 = (b1b0 * 2) / 10;
    ap0 = (b1b0 * 2) % 10;
    ap = ap3 * 1000 + ap2 * 100 + ap1 * 10 + ap0;

    *a2 = ap / 200;
    *a1 = (ap / 20) % 10;
    *a0 = (ap / 2) % 10;

    /* All digits must be 0-9. Negative values can occur when the W2
     * arithmetic overflows for invalid range combinations. */
    if (*a2 < 0 || *a2 > 9 || *a1 < 0 || *a1 > 9 || *a0 < 0 || *a0 > 9)
        return -1;

    return 0;
}

/* ---------------------------------------------------------------------- */
/* Batch decoder: parse the bit buffer into address + message             */
/* Returns 0 on success, -1 on failure.                                   */
/* ---------------------------------------------------------------------- */

static int gsc_decode_batch(struct gsc_state *gsc, int force)
{
    const uint8_t *bits = gsc->rx_bit;
    int pos = 0;
    int total_bits = gsc->rx_bit_num;
    unsigned int codeword;
    int rc, i;

    verbprintf(7, "GSC: decode_batch called: %d bits, force=%d\n", total_bits, force);

    /* --- Stage 1: Preamble (already confirmed by state machine) --- */
    /* The preamble is 28-bit comma + 18 x 46-bit dup Golay = 856 bits.
     * Instead of assuming exact position, scan for the start code (713)
     * starting from the expected position. This handles minor alignment
     * variations from the PLL. */
    int preamble_end = GSC_COMMA_LEN + GSC_PREAMBLE_REPS * GSC_DUP_BITS;
    if (total_bits < preamble_end + 121) {
        verbprintf(5, "GSC: Not enough bits (%d, need %d)\n", total_bits, preamble_end + 121);
        return -1;
    }

    /* --- Stage 2: Find start code --- */
    /* Scan from expected position (856) with a window of +/- 46 bits
     * to handle alignment variations. The start code is:
     * 28-bit comma + dup Golay(713) + 1-bit inv + dup Golay(~713) = 121 bits */
    int sc_found = 0;
    int scan_start = preamble_end - 46;
    int scan_end = preamble_end + 46;
    if (scan_start < 0)
        scan_start = 0;
    if (scan_end + GSC_COMMA_LEN + GSC_DUP_BITS > total_bits)
        scan_end = total_bits - GSC_COMMA_LEN - GSC_DUP_BITS;

    for (pos = scan_start; pos <= scan_end; pos++) {
        int try_pos = pos + GSC_COMMA_LEN;
        if (try_pos + GSC_DUP_BITS > total_bits)
            break;

        unsigned int try_cw = read_dup_golay(bits, &try_pos);
        unsigned int try_val = try_cw;
        rc = bch_golay_correct(&try_val);
        if (rc >= 0 && (unsigned short)try_val == GSC_START_CODE) {
            /* Found start code at this position */
            pos = pos + GSC_COMMA_LEN; /* skip comma */
            pos = try_pos;             /* past the dup Golay we just read */
            sc_found = 1;
            if (rc > 0)
                gsc->error_count += rc;
            break;
        }
    }

    if (!sc_found) {
        verbprintf(5, "GSC: Start code not found in scan range %d-%d\n", scan_start, scan_end);
        return -1;
    }

    pos += 1; /* skip 1-bit inverted comma */

    /* Verify complement start code */
    {
        unsigned int comp = read_dup_golay(bits, &pos);
        comp ^= 0x7FFFFF;
        rc = bch_golay_correct(&comp);
        if (rc < 0 || (unsigned short)comp != GSC_START_CODE) {
            verbprintf(3, "GSC: Complement start code failed\n");
            gsc->error_count++;
        }
    }

    /* --- Stage 3: Address (28 comma + 46 dup W1 + 1 inv + 46 dup W2 = 121) --- */
    if (pos + 121 > total_bits) {
        verbprintf(3, "GSC: Not enough bits for address\n");
        return -1;
    }

    pos += GSC_COMMA_LEN; /* skip comma */

    /* Decode W1 with inversion detection */
    unsigned short w1_value = 0;
    int w1_inverted = 0;
    {
        unsigned int w1_cw = read_dup_golay(bits, &pos);
        unsigned int w1_try = w1_cw;

        rc = bch_golay_correct(&w1_try);
        if (rc >= 0) {
            /* Check if decoded value is in word1s table */
            int found = 0;
            for (i = 0; i < 50; i++) {
                if ((unsigned short)w1_try == word1s[i]) {
                    found = 1;
                    break;
                }
            }
            if (found) {
                w1_value = (unsigned short)w1_try;
                if (rc > 0)
                    gsc->error_count += rc;
            } else {
                /* Not in table - try inverted */
                w1_try = w1_cw ^ 0x7FFFFF;
                rc = bch_golay_correct(&w1_try);
                if (rc >= 0) {
                    found = 0;
                    for (i = 0; i < 50; i++) {
                        if ((unsigned short)w1_try == word1s[i]) {
                            found = 1;
                            break;
                        }
                    }
                    if (found) {
                        w1_value = (unsigned short)w1_try;
                        w1_inverted = 1;
                        if (rc > 0)
                            gsc->error_count += rc;
                    } else {
                        verbprintf(3, "GSC: W1 not in table (normal or inverted)\n");
                        return -1;
                    }
                } else {
                    verbprintf(3, "GSC: W1 Golay decode failed\n");
                    return -1;
                }
            }
        } else {
            /* Normal decode failed - try inverted */
            w1_try = w1_cw ^ 0x7FFFFF;
            rc = bch_golay_correct(&w1_try);
            if (rc < 0) {
                verbprintf(3, "GSC: W1 Golay decode failed (both polarities)\n");
                return -1;
            }
            w1_value = (unsigned short)w1_try;
            w1_inverted = 1;
            if (rc > 0)
                gsc->error_count += rc;
        }
    }

    pos += 1; /* skip 1-bit inverted comma */

    /* Reverse-map W1 to group digits first (needed for W2 range detection) */
    int g1, g0, a2, a1, a0;
    int g1g0;
    if (reverse_word1(w1_value, &g1, &g0) < 0) {
        verbprintf(3, "GSC: W1 reverse mapping failed (w1=%u)\n", w1_value);
        return -1;
    }
    g1g0 = g1 * 10 + g0;

    /* Decode W2 with inversion AND range detection.
     *
     * W1 reverse gives g1g0 in low range (0-49). The actual g1g0 could
     * be 50-99 (same W1 value, W2 offset by +50). We try all 4 combos
     * of (normal/inverted Golay) x (low/high g1g0 range) and use
     * reverse_word2() success as the discriminator.
     *
     * Ambiguity: the invalid GSC code tables are designed
     * to prevent a single W2 value from producing valid addresses in
     * both ranges. However, some W2 values DO produce valid addresses
     * in both ranges (the tables don't cover all cases). When this
     * happens, we output both candidate addresses comma-separated.
     * A real pager knows its own address; a monitoring decoder cannot
     * always disambiguate. */
    unsigned short w2_value = 0;
    int w2_inverted = 0;

    /* Store up to 2 candidate addresses (low range, high range) */
    int n_candidates = 0;
    int cand_g1[2], cand_g0[2], cand_a2[2], cand_a1[2], cand_a0[2];
    int cand_inv[2], cand_g1g0[2];

    {
        unsigned int w2_cw = read_dup_golay(bits, &pos);
        unsigned short w2_try[2] = {0, 0};
        int golay_ok[2] = {0, 0};
        int try_g1g0[2];
        int ta2, ta1, ta0;
        int inv, rng;

        try_g1g0[0] = g1g0;
        try_g1g0[1] = g1g0 + 50;

        /* Try normal Golay decode */
        {
            unsigned int try_cw = w2_cw;
            rc = bch_golay_correct(&try_cw);
            if (rc >= 0) {
                w2_try[0] = (unsigned short)try_cw;
                golay_ok[0] = 1;
            }
        }

        /* Try inverted Golay decode */
        {
            unsigned int try_cw = w2_cw ^ 0x7FFFFF;
            rc = bch_golay_correct(&try_cw);
            if (rc >= 0) {
                w2_try[1] = (unsigned short)try_cw;
                golay_ok[1] = 1;
            }
        }

        /* Try all 4 combinations, collect all valid candidates */
        for (inv = 0; inv < 2; inv++) {
            if (!golay_ok[inv])
                continue;
            for (rng = 0; rng < 2; rng++) {
                if (reverse_word2(w2_try[inv], try_g1g0[rng], &ta2, &ta1, &ta0) == 0) {
                    if (n_candidates < 2) {
                        cand_inv[n_candidates] = inv;
                        cand_g1g0[n_candidates] = try_g1g0[rng];
                        cand_g1[n_candidates] = try_g1g0[rng] / 10;
                        cand_g0[n_candidates] = try_g1g0[rng] % 10;
                        cand_a2[n_candidates] = ta2;
                        cand_a1[n_candidates] = ta1;
                        cand_a0[n_candidates] = ta0;
                        n_candidates++;
                    }
                }
            }
        }

        if (n_candidates == 0) {
            verbprintf(5, "GSC: W2 no valid address from any combination (w2_cw=0x%06x)\n", w2_cw);
            return -1;
        }

        /* Use first candidate as primary */
        w2_value = w2_try[cand_inv[0]];
        w2_inverted = cand_inv[0];
        a2 = cand_a2[0];
        a1 = cand_a1[0];
        a0 = cand_a0[0];
        g1g0 = cand_g1g0[0];
        g1 = cand_g1[0];
        g0 = cand_g0[0];
    }

    /* Compute function number from inversion flags: function = (W1_inv << 1) | W2_inv */
    int function = (w1_inverted << 1) | w2_inverted;

    /* Compute index digit: preamble = (idx + g0) % 10 */
    int idx = (gsc->preamble_index - g0 + 10) % 10;

    /* Build address string. When both g1g0 ranges produce valid addresses
     * (ambiguity from the W1 table mapping two g1g0 values to the same
     * entry), show the primary
     * address normally and log the alternate at debug level. */
    char addr_str[16];
    snprintf(addr_str, sizeof(addr_str), "%d%d%d%d%d%d", idx, g1, g0, a2, a1, a0);

    if (n_candidates == 2) {
        int idx2 = (gsc->preamble_index - cand_g0[1] + 10) % 10;
        verbprintf(7, "GSC: Ambiguous address: %d%d%d%d%d%d or %d%d%d%d%d%d (W2 maps to both g1g0=%d and %d)\n", idx,
                   g1, g0, a2, a1, a0, idx2, cand_g1[1], cand_g0[1], cand_a2[1], cand_a1[1], cand_a0[1], cand_g1g0[0],
                   cand_g1g0[1]);
    }

    verbprintf(5, "GSC: Address decode: W1=%u(%s) W2=%u(%s) func=%d g1g0=%d idx=%d -> %d%d%d%d%d%d\n", w1_value,
               w1_inverted ? "inv" : "norm", w2_value, w2_inverted ? "inv" : "norm", function, g1g0, idx, idx, g1, g0,
               a2, a1, a0);

    /* Check what follows the address: data blocks or tone/voice */
    int remaining = total_bits - pos;

    /* --- Stage 4: Type detection ---
     *
     * Three message types produce distinct post-address signatures:
     *   Voice:  28-bit comma + dup Golay pair (activation_code) = 121 bits
     *   Data:   1-bit inverted comma + 120 interleaved BCH bits = 121 bits/block
     *   Tone:   968-bit comma sequence (121 * 8)
     *
     * Detection order:
     *   1. Check for voice activation code (after 28-bit comma)
     *   2. Probe first BCH block (after 1-bit inverted comma)
     *   3. If neither, need more bits or it's tone (if >= 968 bits) */
    int detected_type = 0;        /* 0=tone, 1=voice, 2=alpha, 3=numeric */
    int tone_comma_len = 121 * 8; /* 968 bits */

    if (remaining < 1 + GSC_BCH_BLOCK_BITS) {
        if (!force)
            return -1;
        detected_type = 0; /* tone */
    } else {
        detected_type = 0; /* default tone */

        /* Step 1: Check for voice activation code */
        if (remaining >= GSC_COMMA_LEN + GSC_DUP_BITS + 1 + GSC_DUP_BITS) {
            int peek_pos = pos + GSC_COMMA_LEN;
            unsigned int peek_cw = read_dup_golay(bits, &peek_pos);
            unsigned int peek_try = peek_cw;
            if (bch_golay_correct(&peek_try) >= 0 && (unsigned short)peek_try == GSC_ACTIVATION_CODE)
                detected_type = 1; /* voice */
        }

        /* Step 2: If not voice, probe first BCH block */
        if (detected_type != 1) {
            int data_detected = 0;

            if (remaining >= 1 + GSC_BCH_BLOCK_BITS) {
                int probe_pos = pos + 1;
                unsigned short probe_bch[8];
                uint8_t probe_d[8];
                int pk, probe_ok = 1;

                deinterleave_bch(bits, &probe_pos, probe_bch);
                for (pk = 0; pk < 8; pk++) {
                    unsigned int cw = probe_bch[pk];
                    if (bch_gsc_correct(&cw) < 0) {
                        probe_ok = 0;
                        break;
                    }
                    probe_d[pk] = (uint8_t)cw;
                }

                if (probe_ok) {
                    uint8_t cksum = 0;
                    for (pk = 0; pk < 7; pk++)
                        cksum += bch_gsc_encode(probe_d[pk]);
                    cksum &= 0x7F;
                    if (cksum == probe_d[7])
                        data_detected = 1;
                }
            }

            if (data_detected) {
                detected_type = 2; /* data (alpha or numeric decided later) */
            } else if (remaining < tone_comma_len) {
                /* Not enough bits to confirm tone - need more data */
                if (!force)
                    return -1;
                detected_type = 0; /* forced: default tone */
            } else {
                detected_type = 0; /* tone (>= 968 bits, no valid data) */
            }
        }
    }

    /* Compute suffix per Function Plan A */
    char suffix;
    switch (detected_type) {
    case 1: /* voice */
        suffix = '1' + function;
        break;
    case 2:
    case 3: /* alpha/numeric */
        suffix = '5' + function;
        break;
    default: /* tone */
        suffix = (function == 0) ? '9' : '0';
        break;
    }

    /* --- Stage 5: Decode based on detected type --- */

    if (detected_type == 2) {
        /* Dual-decode: extract both alpha and numeric from the same data blocks,
         * then use fill-count and content scoring to pick the winner. */
        static char alpha_msg[GSC_MAX_ADB * 8 + 1];
        static char numeric_msg[GSC_MAX_NDB * 12 + 1];
        static uint8_t numeric_nibbles[GSC_MAX_NDB * 12 + 1];
        int alpha_len = 0;
        int numeric_len = 0;
        int numeric_nibble_count = 0;
        int alpha_fill = 0;
        int numeric_fill = 0;
        int shifted = 0;
        int block_count = 0;
        int last_contbit = 0;

        while (pos + 1 + GSC_BCH_BLOCK_BITS <= total_bits && block_count < GSC_MAX_ADB) {
            unsigned short bch_cw[8];
            uint8_t d[8];
            uint8_t contbit;
            int k;

            pos += 1; /* skip 1-bit inverted comma */
            deinterleave_bch(bits, &pos, bch_cw);

            /* Decode all 8 BCH codewords */
            for (k = 0; k < 8; k++) {
                unsigned int cw = bch_cw[k];
                rc = bch_gsc_correct(&cw);
                if (rc < 0) {
                    d[k] = 0;
                    gsc->uncorrectable_count++;
                } else {
                    d[k] = (uint8_t)cw;
                    if (rc > 0)
                        gsc->error_count += rc;
                }
            }

            verbprintf(5, "GSC: BCH block %d: d=%02x %02x %02x %02x %02x %02x %02x %02x cont=%d\n", block_count, d[0],
                       d[1], d[2], d[3], d[4], d[5], d[6], d[7], (d[6] >> 6) & 1);

            /* Verify data block checksum */
            {
                uint8_t cksum = 0;
                int k2;
                for (k2 = 0; k2 < 7; k2++)
                    cksum += bch_gsc_encode(d[k2]);
                cksum &= 0x7F;
                if (cksum != d[7]) {
                    verbprintf(3, "GSC: BCH block %d checksum fail (0x%02x != 0x%02x)\n", block_count, cksum, d[7]);
                    gsc->error_count++;
                }
            }

            contbit = (d[6] >> 6) & 1;

            /* Alpha unpack: 7 data words -> 8 six-bit characters */
            {
                uint8_t ch[8];
                ch[0] = d[0] & 0x3F;
                ch[1] = ((d[0] >> 6) | (d[1] << 1)) & 0x3F;
                ch[2] = ((d[1] >> 5) | (d[2] << 2)) & 0x3F;
                ch[3] = ((d[2] >> 4) | (d[3] << 3)) & 0x3F;
                ch[4] = ((d[3] >> 3) | (d[4] << 4)) & 0x3F;
                ch[5] = ((d[4] >> 2) | (d[5] << 5)) & 0x3F;
                ch[6] = (d[5] >> 1) & 0x3F;
                ch[7] = d[6] & 0x3F;

                for (k = 0; k < 8; k++) {
                    if (ch[k] == 0x3E) {
                        alpha_fill++; /* NULL fill character */
                        continue;
                    }
                    char c = alpha_table[ch[k] & 0x3F];
                    if (c == '\0')
                        continue;
                    if (c == '\r' && alpha_len < GSC_MAX_ADB * 8) {
                        alpha_msg[alpha_len++] = '\n';
                        continue;
                    }
                    if (alpha_len < GSC_MAX_ADB * 8)
                        alpha_msg[alpha_len++] = c;
                }
            }

            /* Numeric unpack: 7 data words -> 12 four-bit nibbles */
            {
                uint8_t nib[12];
                nib[0] = d[0] & 0x0F;
                nib[1] = ((d[0] >> 4) | (d[1] << 3)) & 0x0F;
                nib[2] = (d[1] >> 1) & 0x0F;
                nib[3] = ((d[1] >> 5) | (d[2] << 2)) & 0x0F;
                nib[4] = (d[2] >> 2) & 0x0F;
                nib[5] = ((d[2] >> 6) | (d[3] << 1)) & 0x0F;
                nib[6] = (d[3] >> 3) & 0x0F;
                nib[7] = d[4] & 0x0F;
                nib[8] = ((d[4] >> 4) | (d[5] << 3)) & 0x0F;
                nib[9] = (d[5] >> 1) & 0x0F;
                nib[10] = ((d[5] >> 5) | (d[6] << 2)) & 0x0F;
                nib[11] = (d[6] >> 2) & 0x0F;

                for (k = 0; k < 12; k++) {
                    if (numeric_nibble_count < 256)
                        numeric_nibbles[numeric_nibble_count++] = nib[k];
                    if (nib[k] == 0x0A) {
                        numeric_fill++;
                        continue;
                    }
                    if (nib[k] == 0x0F) {
                        shifted = 1;
                        continue;
                    }
                    char c;
                    if (shifted) {
                        c = numeric_shift_table[nib[k] & 0x0F];
                        shifted = 0;
                    } else {
                        c = numeric_table[nib[k] & 0x0F];
                    }
                    if (c == '\0')
                        continue;
                    if (numeric_len < GSC_MAX_NDB * 12)
                        numeric_msg[numeric_len++] = c;
                }
            }

            block_count++;
            last_contbit = contbit;
            if (!contbit)
                break;
        }

        /* If the last block had contbit=1, more data blocks are expected
         * but we ran out of bits. Return -1 to keep buffering unless forced. */
        if (last_contbit && block_count >= GSC_MAX_ADB)
            verbprintf(1, "GSC: Warning: message truncated at %d blocks (%d chars), transmitter sent more data\n",
                       block_count, alpha_len);
        else if (last_contbit && !force)
            return -1;

        alpha_msg[alpha_len] = '\0';
        numeric_msg[numeric_len] = '\0';

        /* Content scoring.
         * Alpha: letters/digits/space = +3, other printable = -2, control = -5.
         *        Fill chars (0x3E) add quadratic bonus.
         * Numeric: digits = +3, space/hyphen/asterisk = -2, stray U = -15.
         *          Fill nibbles (0x0A) add quadratic bonus (weaker than alpha). */
        int alpha_score = 0;
        for (i = 0; i < alpha_len; i++) {
            char c = alpha_msg[i];
            if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ')
                alpha_score += 3;
            else if (c >= 0x20 && c <= 0x7E)
                alpha_score -= 2;
            else
                alpha_score -= 5;
        }
        alpha_score += alpha_fill * alpha_fill * 2;

        int numeric_score = 0;
        {
            /* Numeric scoring with position awareness.
             *
             * Real numeric messages are typically short (phone numbers,
             * codes). The first 12 nibbles (one block) get a position
             * bonus. Beyond that, the bonus drops to zero - long numeric
             * output is likely alpha data misinterpreted.
             *
             * U (0x0B): valid only as urgent prefix (first non-fill nibble).
             *   Single leading U gets mild penalty (-1).
             *   Stray U elsewhere is a strong artifact signal (-15).
             * Asterisk (0x0E): reserved in the standard, not used in
             *   real numeric messages. Heavy penalty (-15).
             * Space/hyphen: common in phone numbers, mild penalty (-2).
             * Shift prefix (0x0F): uncommon in numeric, mild penalty (-2). */
            int u_count = 0, first_u = -1, ni;
            for (ni = 0; ni < numeric_nibble_count; ni++) {
                if (numeric_nibbles[ni] == 0x0A)
                    continue;
                if (numeric_nibbles[ni] == 0x0B) {
                    u_count++;
                    if (first_u < 0)
                        first_u = ni;
                }
            }
            int urgent_prefix = (u_count == 1 && first_u == 0);

            int content_pos = 0; /* position among non-fill nibbles */
            for (ni = 0; ni < numeric_nibble_count; ni++) {
                uint8_t n = numeric_nibbles[ni];
                if (n == 0x0A)
                    continue; /* fill */
                if (n <= 0x09) {
                    /* Digit: +5 in first block, +1 after */
                    numeric_score += (content_pos < 12) ? 5 : 1;
                } else if (n == 0x0B)
                    numeric_score += urgent_prefix ? -1 : -15;
                else if (n == 0x0C)
                    numeric_score -= 2; /* space */
                else if (n == 0x0D)
                    numeric_score -= 2; /* hyphen */
                else if (n == 0x0E)
                    numeric_score -= 15; /* asterisk - reserved */
                else if (n == 0x0F)
                    numeric_score -= 2; /* shift prefix */
                content_pos++;
            }
        }
        numeric_score += numeric_fill * numeric_fill;

        /* Discrimination: use content scoring as primary, with fill count
         * as a tiebreaker. Fill is only meaningful for short messages where
         * the correct interpretation has trailing padding. For full blocks
         * (no fill in either), content scoring is the only signal.
         * When one has significantly more fill than the other AND the
         * content scores are close, fill wins. */
        int is_numeric;
        int score_diff = alpha_score - numeric_score;
        if (score_diff < 0)
            score_diff = -score_diff;

        if (score_diff > 10) {
            /* Clear winner by content score */
            is_numeric = (numeric_score > alpha_score);
        } else if (numeric_fill > 0 && alpha_fill == 0) {
            is_numeric = 1;
        } else if (alpha_fill > 0 && numeric_fill == 0) {
            is_numeric = 0;
        } else if (numeric_fill > alpha_fill) {
            is_numeric = 1;
        } else if (alpha_fill > numeric_fill) {
            is_numeric = 0;
        } else {
            is_numeric = (numeric_score > alpha_score);
        }
        char suffix;
        if (is_numeric)
            suffix = '5' + function; /* numeric: suffix 5-8 */
        else
            suffix = '5' + function; /* alpha: suffix 5-8 (same range for data) */

        /* Output decoded message */
        if (is_numeric && numeric_len > 0) {
            verbprintf(0, "GSC: Address: %s%c  Function: %d  Numeric: \"%s\"\n", addr_str, suffix, function + 1,
                       numeric_msg);
            verbprintf(1,
                       "GSC: Address: %s%c  Function: %d  likely numeric: \"%s\" unlikely alpha: \"%s\" (scores: n=%d "
                       "a=%d fill: n=%d a=%d)\n",
                       addr_str, suffix, function + 1, numeric_msg, esc_nl(alpha_msg), numeric_score, alpha_score, numeric_fill,
                       alpha_fill);
        } else if (alpha_len > 0) {
            verbprintf(0, "GSC: Address: %s%c  Function: %d  Alpha:   \"%s\"\n", addr_str, suffix, function + 1,
                       esc_nl(alpha_msg));
            verbprintf(1,
                       "GSC: Address: %s%c  Function: %d  likely alpha: \"%s\" unlikely numeric: \"%s\" (scores: a=%d "
                       "n=%d fill: a=%d n=%d)\n",
                       addr_str, suffix, function + 1, esc_nl(alpha_msg), numeric_msg, alpha_score, numeric_score, alpha_fill,
                       numeric_fill);
        } else {
            /* No content decoded - treat as tone */
            suffix = (function == 0) ? '9' : '0';
            verbprintf(0, "GSC: Address: %s%c  Function: %d  Tone\n", addr_str, suffix, function + 1);
        }
    } else { /* not data */
        /* Tone or voice */
        if (detected_type == 1) {
            /* Voice: output tone first, then voice start */
            verbprintf(0, "GSC: Address: %s%c  Function: %d  Tone\n", addr_str, suffix, function + 1);

            /* Verify activation code */
            if (remaining >= GSC_COMMA_LEN + GSC_DUP_BITS + 1 + GSC_DUP_BITS) {
                pos += GSC_COMMA_LEN;
                codeword = read_dup_golay(bits, &pos);
                rc = bch_golay_correct(&codeword);
                /* Already verified in type detection, just advance pos */
                pos += 1;            /* skip 1-bit inverted comma */
                pos += GSC_DUP_BITS; /* skip complement */
            }

            {
                char voice_addr[40];
                char voice_suffix = '1' + function;
                snprintf(voice_addr, sizeof(voice_addr), "%s%c", addr_str, voice_suffix);
                verbprintf(0, "GSC: Address: %s  Function: %d  Voice: message start\n", voice_addr, function + 1);
                strncpy(gsc->voice_address, voice_addr, sizeof(gsc->voice_address) - 1);
                gsc->voice_function = function + 1;
            }
            return 1; /* signal voice mode */
        } else {
            /* Tone only */
            verbprintf(0, "GSC: Address: %s%c  Function: %d  Tone\n", addr_str, suffix, function + 1);
        }
    }

    /* --- Batch continuation: check for additional addresses --- */
    /* After decoding one address+message, peek ahead for another W1.
     * Batch mode transmissions pack multiple address/data pairs. */
    {
        int batch_count = 1;
        int batch_pos = pos;

        while (batch_count < 32) {
            if (batch_pos + GSC_COMMA_LEN + GSC_DUP_BITS > total_bits)
                break;

            batch_pos += GSC_COMMA_LEN;

            unsigned int peek_cw = read_dup_golay(bits, &batch_pos);
            unsigned int peek_try;
            int is_w1 = 0, is_start = 0, is_preamble = 0;
            int bm_w1_inverted = 0;
            unsigned short bm_w1_value = 0;

            /* Try normal */
            peek_try = peek_cw;
            if (bch_golay_correct(&peek_try) >= 0) {
                for (i = 0; i < 50; i++) {
                    if ((unsigned short)peek_try == word1s[i]) { is_w1 = 1; bm_w1_value = (unsigned short)peek_try; break; }
                }
                if (!is_w1 && (unsigned short)peek_try == GSC_START_CODE) is_start = 1;
                if (!is_w1 && !is_start && match_preamble((unsigned short)peek_try) >= 0) is_preamble = 1;
            }

            /* Try inverted for W1 */
            if (!is_w1 && !is_start && !is_preamble) {
                peek_try = peek_cw ^ 0x7FFFFF;
                if (bch_golay_correct(&peek_try) >= 0) {
                    for (i = 0; i < 50; i++) {
                        if ((unsigned short)peek_try == word1s[i]) { is_w1 = 1; bm_w1_value = (unsigned short)peek_try; bm_w1_inverted = 1; break; }
                    }
                }
            }

            if (is_preamble || (!is_w1 && !is_start))
                break;

            if (is_start) {
                /* Extended batch: skip complement and continue */
                if (batch_pos + 1 + GSC_DUP_BITS > total_bits) break;
                batch_pos += 1 + GSC_DUP_BITS;
                continue;
            }

            /* Valid W1 — decode the next address+message */
            verbprintf(1, "GSC: Batch: additional address %d found\n", batch_count + 1);

            int bm_g1, bm_g0;
            if (reverse_word1(bm_w1_value, &bm_g1, &bm_g0) < 0) break;
            int bm_g1g0 = bm_g1 * 10 + bm_g0;

            /* Decode W2 */
            if (batch_pos + 1 + GSC_DUP_BITS > total_bits) break;
            batch_pos += 1; /* skip inverted comma */

            unsigned int w2_cw = read_dup_golay(bits, &batch_pos);
            unsigned int w2_try[2] = {0, 0};
            int w2_ok[2] = {0, 0};
            int bm_w2_inverted = 0;
            int bm_a2, bm_a1, bm_a0;

            peek_try = w2_cw;
            if (bch_golay_correct(&peek_try) >= 0) { w2_try[0] = peek_try; w2_ok[0] = 1; }
            peek_try = w2_cw ^ 0x7FFFFF;
            if (bch_golay_correct(&peek_try) >= 0) { w2_try[1] = peek_try; w2_ok[1] = 1; }

            int best_inv = -1, best_range = -1;
            int try_g1g0[2] = { bm_g1g0, bm_g1g0 + 50 };
            for (int inv = 0; inv < 2; inv++) {
                if (!w2_ok[inv]) continue;
                for (int rng = 0; rng < 2; rng++) {
                    int ta2, ta1, ta0;
                    if (reverse_word2((unsigned short)w2_try[inv], try_g1g0[rng], &ta2, &ta1, &ta0) == 0) {
                        if (best_inv < 0) { best_inv = inv; best_range = rng; bm_a2 = ta2; bm_a1 = ta1; bm_a0 = ta0; }
                    }
                }
            }
            if (best_inv < 0) break;
            bm_w2_inverted = best_inv;
            if (best_range == 1) { bm_g1g0 = try_g1g0[1]; bm_g1 = bm_g1g0 / 10; bm_g0 = bm_g1g0 % 10; }

            int bm_function = (bm_w1_inverted ? 0x2 : 0) | (bm_w2_inverted ? 0x1 : 0);
            int bm_idx = (gsc->preamble_index - bm_g0 + 10) % 10;

            char bm_addr[8];
            bm_addr[0] = '0' + bm_idx;
            bm_addr[1] = '0' + bm_g1;
            bm_addr[2] = '0' + bm_g0;
            bm_addr[3] = '0' + bm_a2;
            bm_addr[4] = '0' + bm_a1;
            bm_addr[5] = '0' + bm_a0;
            bm_addr[6] = '\0';

            /* Decode data blocks for this address */
            int bm_remaining = total_bits - batch_pos;
            int bm_detected = -1; /* -1=unknown, 0=tone, 1=voice, 2=data */

            if (bm_remaining >= 1 + GSC_BCH_BLOCK_BITS) {
                /* Probe first BCH block */
                int probe_pos = batch_pos + 1;
                unsigned short probe_bch[8];
                uint8_t probe_d[8];
                int probe_ok = 1;

                deinterleave_bch(bits, &probe_pos, probe_bch);
                for (int k = 0; k < 8; k++) {
                    unsigned int cw = probe_bch[k];
                    if (bch_gsc_correct(&cw) < 0) { probe_ok = 0; break; }
                    probe_d[k] = cw & 0x7F;
                }
                if (probe_ok) {
                    uint8_t cksum = 0;
                    for (int k = 0; k < 7; k++) cksum += bch_gsc_encode(probe_d[k]);
                    cksum &= 0x7F;
                    if (cksum == probe_d[7]) bm_detected = 2;
                }
            }

            if (bm_detected == 2) {
                /* Decode alpha data blocks */
                static char bm_alpha[GSC_MAX_ADB * 8 + 1];
                int bm_alen = 0;
                int bm_contbit = 1;
                int bm_blocks = 0;

                while (batch_pos + 1 + GSC_BCH_BLOCK_BITS <= total_bits && bm_blocks < GSC_MAX_ADB && bm_contbit) {
                    batch_pos += 1;
                    unsigned short bch_cw[8];
                    uint8_t d[8];
                    deinterleave_bch(bits, &batch_pos, bch_cw);
                    int ok = 1;
                    for (int k = 0; k < 8; k++) {
                        unsigned int cw = bch_cw[k];
                        if (bch_gsc_correct(&cw) < 0) { d[k] = 0; ok = 0; }
                        else d[k] = cw & 0x7F;
                    }
                    if (ok) {
                        uint8_t ch[8];
                        ch[0] = d[0] & 0x3f;
                        ch[1] = ((d[0] >> 6) | (d[1] << 1)) & 0x3f;
                        ch[2] = ((d[1] >> 5) | (d[2] << 2)) & 0x3f;
                        ch[3] = ((d[2] >> 4) | (d[3] << 3)) & 0x3f;
                        ch[4] = ((d[3] >> 3) | (d[4] << 4)) & 0x3f;
                        ch[5] = ((d[4] >> 2) | (d[5] << 5)) & 0x3f;
                        ch[6] = (d[5] >> 1) & 0x3f;
                        ch[7] = d[6] & 0x3f;
                        bm_contbit = (d[6] >> 6) & 1;
                        for (int j = 0; j < 8 && bm_alen < GSC_MAX_ADB * 8; j++) {
                            char c = alpha_table[ch[j] & 0x3f];
                            if (c == '\r') c = '\n';
                            if (c) bm_alpha[bm_alen++] = c;
                        }
                    } else {
                        bm_contbit = 0;
                    }
                    bm_blocks++;
                }
                bm_alpha[bm_alen] = '\0';

                char bm_suffix = '5' + bm_function;
                verbprintf(0, "GSC: Address: %s%c  Function: %d  Alpha:   \"%s\"\n",
                           bm_addr, bm_suffix, bm_function + 1, esc_nl(bm_alpha));
            } else {
                /* Tone or unknown */
                char bm_suffix = (bm_function == 0) ? '9' : '0';
                verbprintf(0, "GSC: Address: %s%c  Function: %d  Tone\n", bm_addr, bm_suffix, bm_function + 1);
            }

            batch_count++;
        }
    }

    return 0;
}

/* ---------------------------------------------------------------------- */
/* Bit-level state machine: receives one demodulated bit at a time        */
/* ---------------------------------------------------------------------- */

static void gsc_rxbit(struct demod_state *s, uint8_t bit)
{
    struct gsc_state *gsc = (struct gsc_state *)s->l1.gsc;
    if (!gsc)
        return;

    /* ---- IDLE: scan for preamble codeword ---- */
    if (gsc->state == GSC_IDLE) {
        /* Shift bit into 46-bit register */
        if (gsc->rx_shift_count < 46) {
            gsc->rx_shift[gsc->rx_shift_count++] = bit;
        } else {
            memmove(gsc->rx_shift, gsc->rx_shift + 1, 45);
            gsc->rx_shift[45] = bit;
        }

        if (gsc->rx_shift_count < 46)
            return;

        /* Try to decode as dup Golay codeword */
        {
            unsigned int codeword = resolve_shift_register(gsc->rx_shift);
            unsigned int try_cw;
            int idx;

            /* Normal polarity */
            try_cw = codeword;
            if (bch_golay_correct(&try_cw) >= 0) {
                idx = match_preamble((unsigned short)try_cw);
                if (idx >= 0) {
                    gsc->polarity_inverted = 0;
                    gsc->batch_candidate = 0;
                    goto preamble_hit;
                }
            }

            /* Inverted polarity — could be batch mode (only preamble
             * inverted) or whole-signal inversion. Defer the decision
             * until the start code is examined. */
            try_cw = codeword ^ 0x7FFFFF;
            if (bch_golay_correct(&try_cw) >= 0) {
                idx = match_preamble((unsigned short)try_cw);
                if (idx >= 0) {
                    gsc->polarity_inverted = 0;
                    gsc->batch_candidate = 1;
                    goto preamble_hit;
                }
            }
            return;

        preamble_hit:
            gsc->confirm_index = idx;
            gsc->confirm_count = 1;
            memcpy(gsc->confirm_bits, gsc->rx_shift, 46);
            gsc->confirm_bit_count = 0;
            gsc->rx_shift_count = 0;
            gsc->state = GSC_PREAMBLE;
        }
        return;
    }

    /* ---- PREAMBLE: confirm consecutive matches ---- */
    if (gsc->state == GSC_PREAMBLE) {
        gsc->rx_shift[gsc->confirm_bit_count++] = bit;

        if (gsc->confirm_bit_count < 46)
            return;

        /* Decode and verify */
        {
            unsigned int codeword = resolve_shift_register(gsc->rx_shift);
            unsigned int try_cw;
            int idx;

            gsc->confirm_bit_count = 0;

            if (gsc->polarity_inverted || gsc->batch_candidate)
                codeword ^= 0x7FFFFF;

            try_cw = codeword;
            if (bch_golay_correct(&try_cw) < 0) {
                gsc->state = GSC_IDLE;
                gsc->rx_shift_count = 0;
                return;
            }

            idx = match_preamble((unsigned short)try_cw);
            if (idx != gsc->confirm_index) {
                gsc->state = GSC_IDLE;
                gsc->rx_shift_count = 0;
                return;
            }

            memcpy(gsc->confirm_bits + gsc->confirm_count * 46, gsc->rx_shift, 46);
            gsc->confirm_count++;

            if (gsc->confirm_count < GSC_PREAMBLE_LOCK) {
                verbprintf(5, "GSC: Preamble confirm %d/%d\n", gsc->confirm_count, GSC_PREAMBLE_LOCK);
                return;
            }

            /* Lock achieved - build rx_bit buffer */
            verbprintf(1, "GSC: Locked (preamble index %d, %s, %d bits buffered)\n", gsc->confirm_index,
                       gsc->batch_candidate ? "batch candidate" :
                       gsc->polarity_inverted ? "inverted polarity" : "normal polarity",
                       gsc->rx_bit_num);

            gsc->preamble_index = gsc->confirm_index;
            gsc->rx_bit_num = 0;
            gsc->error_count = 0;
            gsc->uncorrectable_count = 0;

            /* 28-bit comma placeholder */
            memset(gsc->rx_bit, 0, GSC_COMMA_LEN);
            gsc->rx_bit_num = GSC_COMMA_LEN;

            /* Copy confirmed preamble bits.
             * For batch_candidate: store raw (un-inverted) bits —
             * the start code check will disambiguate later.
             * For polarity_inverted: invert now. */
            {
                int b;
                int nbits = gsc->confirm_count * 46;
                if (gsc->batch_candidate) {
                    /* Raw bits — preamble is inverted but we don't
                     * know about the rest yet */
                    for (b = 0; b < nbits; b++)
                        gsc->rx_bit[gsc->rx_bit_num + b] = !gsc->confirm_bits[b];
                } else if (gsc->polarity_inverted) {
                    for (b = 0; b < nbits; b++)
                        gsc->rx_bit[gsc->rx_bit_num + b] = !gsc->confirm_bits[b];
                } else {
                    memcpy(gsc->rx_bit + gsc->rx_bit_num, gsc->confirm_bits, nbits);
                }
                gsc->rx_bit_num += nbits;
            }

            gsc->no_transition = 0;
            gsc->state = GSC_DATA;
        }
        return;
    }

    /* ---- VOICE: scan for new preamble ---- */
    if (gsc->state == GSC_VOICE) {
        /* During voice, the transmitter sends analog audio, not FSK data.
         * The PLL produces garbage bits. Voice ends when:
         * - A new preamble is detected (next transmission starts)
         * - The activation code (2563) is detected (voice stop signal)
         * Both are checked via sliding window Golay decode below. */

        /* Sliding window preamble scan */
        if (gsc->rx_shift_count < 46) {
            gsc->rx_shift[gsc->rx_shift_count++] = bit;
        } else {
            memmove(gsc->rx_shift, gsc->rx_shift + 1, 45);
            gsc->rx_shift[45] = bit;
        }

        if (gsc->rx_shift_count >= 46) {
            unsigned int codeword = resolve_shift_register(gsc->rx_shift);
            unsigned int try_cw;

            /* Check for preamble (new transmission) */
            try_cw = codeword;
            if (bch_golay_correct(&try_cw) >= 0) {
                if (match_preamble((unsigned short)try_cw) >= 0) {
                    verbprintf(0, "GSC: Address: %s  Function: %d  Voice: message end\n", gsc->voice_address,
                               gsc->voice_function);
                    gsc->confirm_index = match_preamble((unsigned short)try_cw);
                    gsc->confirm_count = 1;
                    gsc->polarity_inverted = 0;
                    memcpy(gsc->confirm_bits, gsc->rx_shift, 46);
                    gsc->confirm_bit_count = 0;
                    gsc->rx_shift_count = 0;
                    gsc->rx_bit_num = 0;
                    gsc->state = GSC_PREAMBLE;
                    return;
                }
                /* Check for activation code (voice stop signal) */
                if ((unsigned short)try_cw == GSC_ACTIVATION_CODE) {
                    verbprintf(0, "GSC: Address: %s  Function: %d  Voice: message end\n", gsc->voice_address,
                               gsc->voice_function);
                    gsc->state = GSC_IDLE;
                    gsc->rx_shift_count = 0;
                    gsc->rx_bit_num = 0;
                    return;
                }
            }

            /* Also check inverted polarity for preamble */
            try_cw = codeword ^ 0x7FFFFF;
            if (bch_golay_correct(&try_cw) >= 0) {
                if (match_preamble((unsigned short)try_cw) >= 0) {
                    verbprintf(0, "GSC: Address: %s  Function: %d  Voice: message end\n", gsc->voice_address,
                               gsc->voice_function);
                    gsc->confirm_index = match_preamble((unsigned short)try_cw);
                    gsc->confirm_count = 1;
                    gsc->polarity_inverted = 0;
                    gsc->batch_candidate = 1;
                    memcpy(gsc->confirm_bits, gsc->rx_shift, 46);
                    gsc->confirm_bit_count = 0;
                    gsc->rx_shift_count = 0;
                    gsc->rx_bit_num = 0;
                    gsc->state = GSC_PREAMBLE;
                    return;
                }
                /* Check inverted activation code */
                if ((unsigned short)try_cw == GSC_ACTIVATION_CODE) {
                    verbprintf(0, "GSC: Address: %s  Function: %d  Voice: message end\n", gsc->voice_address,
                               gsc->voice_function);
                    gsc->state = GSC_IDLE;
                    gsc->rx_shift_count = 0;
                    gsc->rx_bit_num = 0;
                    return;
                }
            }
        }
        return;
    }

    /* ---- DATA: buffer bits until end of transmission ---- */
    if (gsc->rx_bit_num >= GSC_MAX_BITS) {
        gsc->state = GSC_IDLE;
        gsc->rx_shift_count = 0;
        gsc->rx_bit_num = 0;
        return;
    }

    /* For batch_candidate, buffer raw bits until disambiguation.
     * For confirmed polarity_inverted, invert as usual. */
    if (gsc->batch_candidate)
        gsc->rx_bit[gsc->rx_bit_num++] = bit;
    else
        gsc->rx_bit[gsc->rx_bit_num++] = gsc->polarity_inverted ? !bit : bit;

    /* ---- Batch candidate disambiguation ----
     * After preamble lock with batch_candidate set, we need to determine
     * if this is batch mode (only preamble inverted, data normal) or
     * whole-signal inversion (everything inverted).
     *
     * The start code (713) is at bit offset 856+28=884.
     * Try decoding it both ways once we have enough bits. */
    if (gsc->batch_candidate && gsc->rx_bit_num >= 856 + 28 + 46) {
        int sc_pos = 856 + GSC_COMMA_LEN;
        unsigned int sc_cw = read_dup_golay(gsc->rx_bit, &sc_pos);
        unsigned int try_normal = sc_cw;
        unsigned int try_inv = sc_cw ^ 0x7FFFFF;

        if (bch_golay_correct(&try_normal) >= 0 && (unsigned short)try_normal == GSC_START_CODE) {
            gsc->batch_candidate = 0;
            gsc->polarity_inverted = 0;
            verbprintf(1, "GSC: Batch mode confirmed (start code decoded without inversion)\n");
        } else if (bch_golay_correct(&try_inv) >= 0 && (unsigned short)try_inv == GSC_START_CODE) {
            gsc->batch_candidate = 0;
            gsc->polarity_inverted = 1;
            verbprintf(1, "GSC: Negative polarity confirmed (start code needed inversion)\n");
            {
                int b;
                for (b = 856; b < gsc->rx_bit_num; b++)
                    gsc->rx_bit[b] = !gsc->rx_bit[b];
            }
        } else {
            verbprintf(1, "GSC: Batch disambiguation failed, lost lock\n");
            gsc->state = GSC_IDLE;
            gsc->rx_shift_count = 0;
            gsc->rx_bit_num = 0;
            return;
        }
    }

    /* End-of-transmission: consecutive same-value bits */
    if (gsc->rx_bit_num >= 2 && gsc->rx_bit[gsc->rx_bit_num - 1] == gsc->rx_bit[gsc->rx_bit_num - 2])
        gsc->no_transition++;
    else
        gsc->no_transition = 0;

    /* Minimum bits for a valid batch: preamble + start + address */
    int min_bits = GSC_COMMA_LEN + GSC_PREAMBLE_REPS * GSC_DUP_BITS + 121 + 121;

    if (gsc->rx_bit_num < min_bits)
        return;

    /* Decode triggers */
    int do_decode = 0;
    int is_force = 0;

    if (gsc->no_transition >= GSC_EOT_THRESHOLD) {
        do_decode = 1;
        is_force = 1;
    } else if (gsc->rx_bit_num >= GSC_MAX_BITS) {
        do_decode = 1;
        is_force = 1;
    } else if ((gsc->rx_bit_num % 46) == 0) {
        do_decode = 1;
    }

    if (do_decode) {
        int nbits = gsc->rx_bit_num;
        if (is_force && gsc->no_transition >= GSC_EOT_THRESHOLD) {
            nbits -= gsc->no_transition;
            if (nbits < min_bits)
                nbits = min_bits;
        }

        /* Save bit count, attempt decode */
        int saved_num = gsc->rx_bit_num;
        gsc->rx_bit_num = nbits;

        int rc = gsc_decode_batch(gsc, is_force);

        gsc->rx_bit_num = saved_num;

        if (rc == 0) {
            /* Success - return to idle */
            gsc->state = GSC_IDLE;
            gsc->rx_shift_count = 0;
            gsc->rx_bit_num = 0;
        } else if (rc == 1) {
            /* Voice message - enter voice state */
            gsc->state = GSC_VOICE;
            gsc->rx_bit_num = 0;
            gsc->rx_shift_count = 0;
            gsc->no_transition = 0;
        } else if (is_force) {
            /* Forced decode failed - give up */
            verbprintf(3, "GSC: Decode failed, returning to idle\n");
            gsc->state = GSC_IDLE;
            gsc->rx_shift_count = 0;
            gsc->rx_bit_num = 0;
        }
        /* else: keep buffering */
    }
}

/* ---------------------------------------------------------------------- */
/* Demodulator: 600 baud 2-FSK with PLL bit clock recovery                */
/* Follows the same pattern as demod_poc5.c / demod_poc12.c               */
/* ---------------------------------------------------------------------- */

static void gsc_init(struct demod_state *s)
{
    struct gsc_state *gsc;

    bch_gsc_init();

    gsc = (struct gsc_state *)calloc(1, sizeof(struct gsc_state));
    if (!gsc)
        return;

    gsc->state = GSC_IDLE;
    s->l1.gsc = gsc;
}

static void gsc_demod(struct demod_state *s, buffer_t buffer, int length)
{
    struct gsc_state *gsc = (struct gsc_state *)s->l1.gsc;
    if (!gsc)
        return;

    if (gsc->subsamp) {
        if (length <= (int)gsc->subsamp) {
            gsc->subsamp -= length;
            return;
        }
        buffer.fbuffer += gsc->subsamp;
        length -= gsc->subsamp;
        gsc->subsamp = 0;
    }
    for (; length > 0; length -= SUBSAMP, buffer.fbuffer += SUBSAMP) {
        gsc->dcd_shreg <<= 1;
        gsc->dcd_shreg |= ((*buffer.fbuffer) > 0);
        /*
         * check if transition
         */
        if ((gsc->dcd_shreg ^ (gsc->dcd_shreg >> 1)) & 1) {
            if (gsc->sphase < (0x8000u - (SPHASEINC / 2)))
                gsc->sphase += SPHASEINC / 8;
            else
                gsc->sphase -= SPHASEINC / 8;
        }
        gsc->sphase += SPHASEINC;
        if (gsc->sphase >= 0x10000u) {
            gsc->sphase &= 0xffffu;
            gsc_rxbit(s, gsc->dcd_shreg & 1);
        }
    }
    gsc->subsamp = -length;
}

static void gsc_deinit(struct demod_state *s)
{
    if (s->l1.gsc) {
        free(s->l1.gsc);
        s->l1.gsc = NULL;
    }
}

/* ---------------------------------------------------------------------- */

const struct demod_param demod_gsc = {"GSC", true, FREQ_SAMP, FILTLEN, gsc_init, gsc_demod, gsc_deinit};
