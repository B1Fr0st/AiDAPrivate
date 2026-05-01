#include <stdint.h>
#include <stddef.h>
#include <string.h>

static void mem_copy_local(void* d, const void* s, size_t n) {
    uint8_t* dd = (uint8_t*)d;
    const uint8_t* ss = (const uint8_t*)s;
    size_t i;
    for (i = 0; i < n; ++i) dd[i] = ss[i];
}

static void mem_set_local(void* d, uint8_t v, size_t n) {
    uint8_t* dd = (uint8_t*)d;
    size_t i;
    for (i = 0; i < n; ++i) dd[i] = v;
}

#define WBAES_T_BOXES_OFFSET   ((uint32_t)0u)
#define WBAES_T_BOXES_SIZE     ((uint32_t)(10u * 16u * 256u))
#define WBAES_MB_TABLES_OFFSET (WBAES_T_BOXES_OFFSET + WBAES_T_BOXES_SIZE)
#define WBAES_MB_TABLES_SIZE   ((uint32_t)(9u * 16u * 256u * 4u))
#define WBAES_EXT_IN_OFFSET    (WBAES_MB_TABLES_OFFSET + WBAES_MB_TABLES_SIZE)
#define WBAES_EXT_OUT_OFFSET   (WBAES_EXT_IN_OFFSET + 16u)
#define WBAES_TABLE_ID_OFFSET  (WBAES_EXT_OUT_OFFSET + 16u)
#define WBAES_TABLE_TOTAL_SIZE (WBAES_TABLE_ID_OFFSET + 16u)

static int wbaes_sr_source_index_local(int target_col, int row) {
    return (((target_col + row) & 3) * 4) + row;
}

static uint8_t wbaes_t_box_lookup_local(const uint8_t* tbl_blob, int round, int slot, uint8_t b) {
    uint32_t off = WBAES_T_BOXES_OFFSET
                 + (uint32_t)round * 16u * 256u
                 + (uint32_t)slot * 256u
                 + (uint32_t)b;
    return tbl_blob[off];
}

static uint32_t wbaes_mb_table_lookup_local(const uint8_t* tbl_blob, int round, int slot, uint8_t b) {
    uint32_t off = WBAES_MB_TABLES_OFFSET
                 + (uint32_t)round * 16u * 256u * 4u
                 + (uint32_t)slot * 256u * 4u
                 + (uint32_t)b * 4u;
    uint32_t v = (uint32_t)tbl_blob[off]
               | ((uint32_t)tbl_blob[off + 1u] << 8)
               | ((uint32_t)tbl_blob[off + 2u] << 16)
               | ((uint32_t)tbl_blob[off + 3u] << 24);
    return v;
}

static void wbaes_encrypt_block_local(const uint8_t* tbl_blob, const uint8_t* in, uint8_t* out) {
    const uint8_t* ext_in_p = tbl_blob + WBAES_EXT_IN_OFFSET;
    const uint8_t* ext_out_p = tbl_blob + WBAES_EXT_OUT_OFFSET;
    uint8_t state[16];
    int i;
    int c;
    int r;
    for (i = 0; i < 16; ++i) {
        state[i] = (uint8_t)(in[i] ^ ext_in_p[i]);
    }
    for (r = 0; r < 9; ++r) {
        uint8_t next_state[16];
        for (c = 0; c < 4; ++c) {
            uint32_t col_word = 0u;
            for (i = 0; i < 4; ++i) {
                int src_idx = wbaes_sr_source_index_local(c, i);
                uint8_t b = state[src_idx];
                col_word ^= wbaes_mb_table_lookup_local(tbl_blob, r, c * 4 + i, b);
            }
            next_state[c * 4 + 0] = (uint8_t)((col_word >> 24) & 0xFFu);
            next_state[c * 4 + 1] = (uint8_t)((col_word >> 16) & 0xFFu);
            next_state[c * 4 + 2] = (uint8_t)((col_word >> 8) & 0xFFu);
            next_state[c * 4 + 3] = (uint8_t)(col_word & 0xFFu);
        }
        mem_copy_local(state, next_state, 16);
        mem_set_local(next_state, 0, 16);
    }
    {
        uint8_t final_state[16];
        for (c = 0; c < 4; ++c) {
            for (i = 0; i < 4; ++i) {
                int src_idx = wbaes_sr_source_index_local(c, i);
                uint8_t b = state[src_idx];
                final_state[c * 4 + i] = wbaes_t_box_lookup_local(tbl_blob, 9, c * 4 + i, b);
            }
        }
        mem_copy_local(state, final_state, 16);
        mem_set_local(final_state, 0, 16);
    }
    for (i = 0; i < 16; ++i) {
        out[i] = (uint8_t)(state[i] ^ ext_out_p[i]);
    }
    mem_set_local(state, 0, 16);
}

int aes128_wbaes_decrypt_ctr_payload(const uint8_t* tbl_blob, uint32_t tbl_size,
                                      const uint8_t iv[16], const uint8_t* in,
                                      uint8_t* out, uint32_t len) {
    if (tbl_blob == 0 || iv == 0) return 0;
    if (tbl_size < WBAES_TABLE_TOTAL_SIZE) return 0;
    if (len > 0u && (in == 0 || out == 0)) return 0;
    uint8_t counter[16];
    uint8_t ks[16];
    uint32_t off = 0u;
    mem_copy_local(counter, iv, 16);
    while (off < len) {
        wbaes_encrypt_block_local(tbl_blob, counter, ks);
        int j;
        for (j = 15; j >= 0; --j) {
            counter[j] = (uint8_t)(counter[j] + 1u);
            if (counter[j] != 0) break;
        }
        uint32_t bl = (len - off < 16u) ? (len - off) : 16u;
        uint32_t k;
        for (k = 0u; k < bl; ++k) {
            out[off + k] = (uint8_t)(in[off + k] ^ ks[k]);
        }
        off += bl;
    }
    mem_set_local(counter, 0, 16);
    mem_set_local(ks, 0, 16);
    return 1;
}
