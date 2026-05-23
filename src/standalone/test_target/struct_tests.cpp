#include "struct_tests.h"
#include "test_log.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace test_target {
namespace structs {

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[STR] ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

enum class weapon_type_t : uint32_t {
    sword   = 0,
    bow     = 1,
    staff   = 2,
    dagger  = 3,
    axe     = 4,
};

enum flags_t : uint32_t {
    flag_none      = 0,
    flag_active    = 1 << 0,
    flag_hostile   = 1 << 1,
    flag_invisible = 1 << 2,
    flag_immortal  = 1 << 3,
    flag_flying    = 1 << 4,
    flag_poisoned  = 1 << 5,
    flag_frozen    = 1 << 6,
    flag_burning   = 1 << 7,
};

struct vec3_t {
    float x, y, z;
};

struct color_t {
    uint8_t r, g, b, a;
};

struct bounding_box_t {
    vec3_t min_pt;
    vec3_t max_pt;
};

union variant_t {
    int32_t   as_int;
    float     as_float;
    uint64_t  as_u64;
    char      as_str[8];
    void*     as_ptr;
};

struct inventory_item_t {
    uint32_t      id;
    char          name[32];
    weapon_type_t type;
    float         damage;
    float         weight;
    uint32_t      quantity;
    variant_t     extra;
};

struct stats_t {
    int32_t strength;
    int32_t dexterity;
    int32_t intelligence;
    int32_t vitality;
    int32_t luck;
    float   critical_chance;
    float   dodge_chance;
    float   armor_rating;
};

struct linked_list_node_t {
    uint64_t            key;
    char                data[48];
    linked_list_node_t* next;
    linked_list_node_t* prev;
};

struct tree_node_t {
    int32_t      value;
    uint32_t     color;
    tree_node_t* left;
    tree_node_t* right;
    tree_node_t* parent;
    char         label[16];
};

struct entity_t {
    uint64_t          id;
    char              name[64];
    vec3_t            position;
    vec3_t            velocity;
    bounding_box_t    bounds;
    color_t           color;
    stats_t           stats;
    flags_t           flags;
    inventory_item_t  inventory[8];
    uint32_t          inventory_count;
    entity_t*         target;
    entity_t*         owner;
    uint64_t          creation_tick;
    uint64_t          last_update_tick;
    float             health;
    float             max_health;
    float             mana;
    float             max_mana;
};

struct network_packet_t {
    uint32_t  magic;
    uint16_t  version;
    uint16_t  opcode;
    uint32_t  payload_length;
    uint32_t  sequence;
    uint64_t  timestamp;
    uint32_t  source_id;
    uint32_t  dest_id;
    uint8_t   flags;
    uint8_t   priority;
    uint16_t  checksum;
    uint8_t   payload[256];
};

struct config_entry_t {
    char      section[32];
    char      key[64];
    variant_t value;
    uint32_t  type;
    uint32_t  flags;
};

class base_handler_t {
public:
    uint32_t handler_id;
    char     handler_name[32];

    virtual ~base_handler_t() = default;
    virtual int process(const uint8_t* data, uint32_t len) = 0;
    virtual const char* get_type_name() = 0;
    virtual uint32_t get_priority() { return 0; }
};

class packet_handler_t : public base_handler_t {
public:
    uint32_t packets_processed;
    uint64_t bytes_processed;

    int process(const uint8_t* data, uint32_t len) override {
        packets_processed++;
        bytes_processed += len;
        return 0;
    }

    const char* get_type_name() override {
        return "packet_handler";
    }

    uint32_t get_priority() override {
        return 10;
    }
};

class crypto_handler_t : public base_handler_t {
public:
    uint32_t blocks_encrypted;
    uint32_t blocks_decrypted;
    uint8_t  key_material[32];

    int process(const uint8_t* data, uint32_t len) override {
        blocks_encrypted += (len + 15) / 16;
        return 0;
    }

    const char* get_type_name() override {
        return "crypto_handler";
    }

    uint32_t get_priority() override {
        return 50;
    }
};

class logger_handler_t : public base_handler_t {
public:
    uint32_t messages_logged;
    uint32_t errors_logged;
    char     log_prefix[16];

    int process(const uint8_t* data, uint32_t len) override {
        messages_logged++;
        if (len > 0 && data[0] == 'E')
            errors_logged++;
        return 0;
    }

    const char* get_type_name() override {
        return "logger_handler";
    }
};

class compression_handler_t : public base_handler_t {
public:
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint32_t level;

    int process(const uint8_t* data, uint32_t len) override {
        bytes_in += len;
        bytes_out += len * 7 / 10;
        return 0;
    }

    const char* get_type_name() override {
        return "compression_handler";
    }

    uint32_t get_priority() override {
        return 20;
    }
};

struct handler_table_t {
    base_handler_t* handlers[16];
    uint32_t        count;
};

static volatile entity_t          s_entities[4]{};
static volatile network_packet_t  s_packet{};
static volatile config_entry_t    s_configs[8]{};
static handler_table_t            s_handler_table{};

static linked_list_node_t* build_linked_list(int count) {
    linked_list_node_t* head = nullptr;
    linked_list_node_t* prev = nullptr;

    for (int i = 0; i < count; ++i) {
        linked_list_node_t* node = (linked_list_node_t*)malloc(sizeof(linked_list_node_t));
        memset(node, 0, sizeof(*node));
        node->key = (uint64_t)(i * 17 + 42);
        sprintf_s(node->data, sizeof(node->data), "node_%d_data", i);
        node->next = nullptr;
        node->prev = prev;

        if (prev) prev->next = node;
        if (!head) head = node;
        prev = node;
    }

    return head;
}

static tree_node_t* build_bst(int* values, int lo, int hi, tree_node_t* parent) {
    if (lo > hi) return nullptr;

    int mid = lo + (hi - lo) / 2;
    tree_node_t* node = (tree_node_t*)malloc(sizeof(tree_node_t));
    memset(node, 0, sizeof(*node));
    node->value = values[mid];
    node->color = (mid % 2 == 0) ? 0 : 1;
    node->parent = parent;
    sprintf_s(node->label, sizeof(node->label), "n%d", values[mid]);

    node->left = build_bst(values, lo, mid - 1, node);
    node->right = build_bst(values, mid + 1, hi, node);

    return node;
}

static int tree_height(tree_node_t* node) {
    if (!node) return 0;
    int lh = tree_height(node->left);
    int rh = tree_height(node->right);
    return 1 + ((lh > rh) ? lh : rh);
}

static int tree_count(tree_node_t* node) {
    if (!node) return 0;
    return 1 + tree_count(node->left) + tree_count(node->right);
}

static void free_tree(tree_node_t* node) {
    if (!node) return;
    free_tree(node->left);
    free_tree(node->right);
    free(node);
}

static void free_list(linked_list_node_t* head) {
    while (head) {
        linked_list_node_t* next = head->next;
        free(head);
        head = next;
    }
}

static void populate_entity(volatile entity_t* e, uint64_t id, const char* name, float x, float y, float z) {
    e->id = id;
    strncpy_s((char*)e->name, sizeof(e->name), name, _TRUNCATE);
    e->position.x = x;            e->position.y = y;            e->position.z = z;
    e->velocity.x = x * 0.1f;     e->velocity.y = y * 0.1f;     e->velocity.z = z * 0.1f;
    e->bounds.min_pt.x = x - 1.0f; e->bounds.min_pt.y = y - 1.0f; e->bounds.min_pt.z = z - 1.0f;
    e->bounds.max_pt.x = x + 1.0f; e->bounds.max_pt.y = y + 1.0f; e->bounds.max_pt.z = z + 1.0f;
    e->color.r = (uint8_t)(id * 37);  e->color.g = (uint8_t)(id * 73);
    e->color.b = (uint8_t)(id * 113); e->color.a = 255;
    e->stats.strength = (int32_t)(id * 3 + 10);
    e->stats.dexterity = (int32_t)(id * 2 + 15);
    e->stats.intelligence = (int32_t)(id * 4 + 8);
    e->stats.vitality = (int32_t)(id * 5 + 12);
    e->stats.luck = (int32_t)(id + 5);
    e->stats.critical_chance = 0.05f * id;
    e->stats.dodge_chance = 0.03f * id;
    e->stats.armor_rating = 10.0f + id * 5.0f;
    e->flags = (flags_t)(flag_active | (id % 2 == 0 ? flag_hostile : 0));
    e->health = 100.0f + id * 10.0f;
    e->max_health = e->health;
    e->mana = 50.0f + id * 5.0f;
    e->max_mana = e->mana;
    e->creation_tick = GetTickCount64();
    e->last_update_tick = e->creation_tick;
    e->inventory_count = 0;
    e->target = nullptr;
    e->owner = nullptr;
}

static void populate_inventory(volatile entity_t* e) {
    const char* item_names[] = { "Iron Sword", "Oak Bow", "Fire Staff", "Shadow Dagger" };
    weapon_type_t types[] = { weapon_type_t::sword, weapon_type_t::bow, weapon_type_t::staff, weapon_type_t::dagger };
    float damages[] = { 25.0f, 18.0f, 35.0f, 15.0f };

    int count = (e->id % 4) + 1;
    if (count > 4) count = 4;

    for (int i = 0; i < count; ++i) {
        volatile inventory_item_t* item = &e->inventory[i];
        item->id = (uint32_t)(e->id * 100 + i);
        strncpy_s((char*)item->name, sizeof(item->name), item_names[i], _TRUNCATE);
        item->type = types[i];
        item->damage = damages[i];
        item->weight = 2.0f + i * 0.5f;
        item->quantity = 1;
        item->extra.as_int = (int32_t)(e->id * 10 + i);
    }
    e->inventory_count = count;
}

void run_all(const config_t& cfg, std::atomic<bool>& running) {
    log("=== Structure tests starting ===");

    log("sizeof(entity_t)         = %zu", sizeof(entity_t));
    log("sizeof(network_packet_t) = %zu", sizeof(network_packet_t));
    log("sizeof(config_entry_t)   = %zu", sizeof(config_entry_t));
    log("sizeof(inventory_item_t) = %zu", sizeof(inventory_item_t));
    log("sizeof(stats_t)          = %zu", sizeof(stats_t));
    log("sizeof(linked_list_node_t)= %zu", sizeof(linked_list_node_t));
    log("sizeof(tree_node_t)      = %zu", sizeof(tree_node_t));
    log("sizeof(variant_t)        = %zu", sizeof(variant_t));

    populate_entity(&s_entities[0], 1, "Warrior_Alpha", 10.0f, 20.0f, 0.0f);
    populate_entity(&s_entities[1], 2, "Archer_Beta", 30.0f, 40.0f, 5.0f);
    populate_entity(&s_entities[2], 3, "Mage_Gamma", -10.0f, 15.0f, 0.0f);
    populate_entity(&s_entities[3], 4, "Rogue_Delta", 0.0f, 0.0f, -5.0f);

    for (int i = 0; i < 4; ++i) {
        populate_inventory(&s_entities[i]);
        int next = (i + 1) % 4;
        s_entities[i].target = (entity_t*)&s_entities[next];
        log("Entity '%s' at %p (id=%llu, hp=%.1f, items=%u, target='%s')",
            (const char*)s_entities[i].name,
            (const void*)&s_entities[i],
            s_entities[i].id,
            s_entities[i].health,
            s_entities[i].inventory_count,
            (const char*)s_entities[next].name);
    }

    s_entities[0].owner = (entity_t*)&s_entities[0];
    s_entities[1].owner = (entity_t*)&s_entities[0];

    s_packet.magic = 0x41494441;
    s_packet.version = 1;
    s_packet.opcode = 0x0042;
    s_packet.payload_length = 64;
    s_packet.sequence = 1;
    s_packet.timestamp = GetTickCount64();
    s_packet.source_id = 1001;
    s_packet.dest_id = 2002;
    s_packet.flags = 0x03;
    s_packet.priority = 5;
    for (int i = 0; i < 64; ++i)
        s_packet.payload[i] = (uint8_t)(i ^ 0x55);
    s_packet.checksum = 0xBEEF;
    log("Network packet at %p (magic=0x%08X, opcode=0x%04X, seq=%u)",
        (const void*)&s_packet, s_packet.magic, s_packet.opcode, s_packet.sequence);

    for (int i = 0; i < 8; ++i) {
        volatile config_entry_t* c = &s_configs[i];
        sprintf_s((char*)c->section, sizeof(c->section), "section_%d", i / 2);
        sprintf_s((char*)c->key, sizeof(c->key), "key_%d_%s", i, (i % 2 == 0) ? "int" : "str");
        if (i % 2 == 0) {
            c->value.as_int = i * 100 + 42;
            c->type = 0;
        } else {
            strncpy_s((char*)c->value.as_str, sizeof(c->value.as_str), "val", _TRUNCATE);
            c->type = 1;
        }
        c->flags = (i < 4) ? flag_active : flag_none;
    }
    log("Config entries at %p (%d entries)", (const void*)s_configs, 8);

    linked_list_node_t* list_head = build_linked_list(16);
    int list_count = 0;
    for (linked_list_node_t* n = list_head; n; n = n->next)
        list_count++;
    log("Linked list at %p (%d nodes, doubly-linked)", (void*)list_head, list_count);

    int bst_values[] = { 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65 };
    tree_node_t* bst_root = build_bst(bst_values, 0, 12, nullptr);
    log("BST at %p (nodes=%d, height=%d, root=%d)",
        (void*)bst_root, tree_count(bst_root), tree_height(bst_root), bst_root ? bst_root->value : -1);

    static packet_handler_t      s_pkt_handler{};
    static crypto_handler_t      s_cry_handler{};
    static logger_handler_t      s_log_handler{};
    static compression_handler_t s_cmp_handler{};

    s_pkt_handler.handler_id = 1;
    strncpy_s(s_pkt_handler.handler_name, sizeof(s_pkt_handler.handler_name), "pkt", _TRUNCATE);
    s_pkt_handler.packets_processed = 0;
    s_pkt_handler.bytes_processed = 0;

    s_cry_handler.handler_id = 2;
    strncpy_s(s_cry_handler.handler_name, sizeof(s_cry_handler.handler_name), "crypto", _TRUNCATE);
    s_cry_handler.blocks_encrypted = 0;
    s_cry_handler.blocks_decrypted = 0;
    memset(s_cry_handler.key_material, 0xAB, 32);

    s_log_handler.handler_id = 3;
    strncpy_s(s_log_handler.handler_name, sizeof(s_log_handler.handler_name), "logger", _TRUNCATE);
    s_log_handler.messages_logged = 0;
    s_log_handler.errors_logged = 0;
    strncpy_s(s_log_handler.log_prefix, sizeof(s_log_handler.log_prefix), "[LOG]", _TRUNCATE);

    s_cmp_handler.handler_id = 4;
    strncpy_s(s_cmp_handler.handler_name, sizeof(s_cmp_handler.handler_name), "compress", _TRUNCATE);
    s_cmp_handler.bytes_in = 0;
    s_cmp_handler.bytes_out = 0;
    s_cmp_handler.level = 6;

    s_handler_table.handlers[0] = &s_pkt_handler;
    s_handler_table.handlers[1] = &s_cry_handler;
    s_handler_table.handlers[2] = &s_log_handler;
    s_handler_table.handlers[3] = &s_cmp_handler;
    s_handler_table.count = 4;

    uint8_t test_data[64];
    memset(test_data, 0x42, sizeof(test_data));

    for (uint32_t i = 0; i < s_handler_table.count; ++i) {
        base_handler_t* h = s_handler_table.handlers[i];
        h->process(test_data, sizeof(test_data));
        log("Handler '%s' (id=%u, type='%s', priority=%u) processed 64 bytes",
            h->handler_name, h->handler_id, h->get_type_name(), h->get_priority());
    }

    log("Vtable addresses:");
    for (uint32_t i = 0; i < s_handler_table.count; ++i) {
        base_handler_t* h = s_handler_table.handlers[i];
        void** vtbl = *(void***)h;
        log("  handler[%u] vtable at %p, object at %p", i, (void*)vtbl, (void*)h);
    }

    free_list(list_head);
    free_tree(bst_root);

    log("=== Structure tests complete ===");
}

}
}
