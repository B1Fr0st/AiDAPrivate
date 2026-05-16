#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include "diag_log.hpp"
#include "win32_dialog.hpp"


struct AsmInstr
{
    uint64_t addr      = 0;
    uint8_t  raw[16]   = {};
    int      len       = 1;
    char     mnem[24]  = {};
    char     ops[64]   = {};
    bool     is_branch = false;
    bool     is_call   = false;
    bool     is_ret    = false;
};


struct PESection
{
    uint64_t             va = 0;
    std::vector<uint8_t> bytes;
};


struct DisasmFile
{
    std::string            path;
    std::string            filename;
    uint64_t               image_base = 0;
    uint64_t               text_va    = 0;
    std::vector<PESection> sections;
    std::vector<AsmInstr>  instrs;
    bool                   loaded = false;
    std::string            err;
};


struct DisasmState
{
    DisasmFile file;
    int  ctx_row   = -1;
    bool show_ctx  = false;
};


namespace x64detail
{
    static const char* const r8[]  = { "al","cl","dl","bl","spl","bpl","sil","dil",
                                        "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b" };
    static const char* const r16[] = { "ax","cx","dx","bx","sp","bp","si","di",
                                        "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w" };
    static const char* const r32[] = { "eax","ecx","edx","ebx","esp","ebp","esi","edi",
                                        "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d" };
    static const char* const r64[] = { "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                        "r8","r9","r10","r11","r12","r13","r14","r15" };
    static const char* const mm[]  = { "mm0","mm1","mm2","mm3","mm4","mm5","mm6","mm7" };
    static const char* const xmm[] = { "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
                                        "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15" };

    static inline int32_t  ri32(const uint8_t* p){ int32_t v; memcpy(&v,p,4); return v; }
    static inline uint32_t ru32(const uint8_t* p){ uint32_t v; memcpy(&v,p,4); return v; }
    static inline uint64_t ru64(const uint8_t* p){ uint64_t v; memcpy(&v,p,8); return v; }
    static inline int16_t  ri16(const uint8_t* p){ int16_t v; memcpy(&v,p,2); return v; }


    static int decode_modrm(const uint8_t* p, int avail, bool rex_r, bool rex_x, bool rex_b, bool rex_w,
                              bool p66, bool p67,
                              int  reg_field_out,
                              int* reg_out,
                              char* op_rm, int op_rm_sz,
                              char* op_reg, int op_reg_sz,
                              int sz_override = -1)
    {
        if (avail < 1) return 0;
        uint8_t modrm = p[0];
        int mod = (modrm >> 6) & 3;
        int reg = (modrm >> 3) & 7;
        int rm  =  modrm       & 7;
        if (rex_r) reg |= 8;
        if (rex_b) rm  |= 8;
        if (reg_out) *reg_out = reg;

        int sz = sz_override >= 0 ? sz_override
               : (rex_w ? 64 : (p66 ? 16 : 32));


        if (op_reg) {
            const char* rname = sz==64 ? r64[reg] : sz==16 ? r16[reg] : r32[reg];
            snprintf(op_reg, op_reg_sz, "%s", rname);
        }

        int consumed = 1;

        if (mod == 3) {

            const char* rname = sz==8  ? r8[rm]
                               : sz==64? r64[rm]
                               : sz==16? r16[rm]
                               : r32[rm];
            if (op_rm) snprintf(op_rm, op_rm_sz, "%s", rname);
            return consumed;
        }


        const char* sz_pfx = sz==64 ? "qword ptr" : sz==32 ? "dword ptr"
                           : sz==16 ? "word ptr"  : "byte ptr";

        char addr[64] = {};
        const uint8_t* q = p + 1; int qleft = avail - 1;

        bool has_sib = (rm & 7) == 4;
        int orig_rm = modrm & 7;
        has_sib = (orig_rm == 4);

        if (has_sib) {
            if (qleft < 1) return consumed;
            uint8_t sib = *q++; qleft--; consumed++;
            int scale  = 1 << ((sib >> 6) & 3);
            int sidx   = (sib >> 3) & 7;
            int sbase  =  sib       & 7;
            if (rex_x) sidx  |= 8;
            if (rex_b) sbase |= 8;

            char base_str[16]  = {};
            char index_str[32] = {};


            bool no_base = (sbase & 7) == 5 && mod == 0;
            if (!no_base) snprintf(base_str, sizeof(base_str), "%s", r64[sbase]);

            if ((sidx & 7) != 4)
                snprintf(index_str, sizeof(index_str), "%s*%d", r64[sidx], scale);

            int32_t disp = 0;
            if (mod == 1) { if (qleft<1) return consumed; disp=(int8_t)*q++; qleft--; consumed++; }
            if (mod == 2 || no_base) { if(qleft<4) return consumed; disp=ri32(q); q+=4; qleft-=4; consumed+=4; }

            char tmp[48] = {};
            if (base_str[0] && index_str[0])      snprintf(tmp,sizeof(tmp),"%s+%s",base_str,index_str);
            else if (base_str[0])                 snprintf(tmp,sizeof(tmp),"%s",base_str);
            else if (index_str[0])                snprintf(tmp,sizeof(tmp),"%s",index_str);
            if (disp > 0)  { char d[16]; snprintf(d,sizeof(d),"+0x%X",disp);  strcat(tmp,d); }
            if (disp < 0)  { char d[16]; snprintf(d,sizeof(d),"-0x%X",-disp); strcat(tmp,d); }
            if (tmp[0])    snprintf(addr,sizeof(addr),"[%s]",tmp);
            else           snprintf(addr,sizeof(addr),"[0x%X]",(uint32_t)disp);
        }
        else if ((orig_rm == 5) && mod == 0) {

            if (qleft < 4) return consumed;
            int32_t d = ri32(q); q+=4; qleft-=4; consumed+=4;
            snprintf(addr, sizeof(addr), "[rip+0x%X]", (unsigned)d);
        }
        else {
            int32_t disp = 0;
            if (mod == 1) { if(qleft<1) return consumed; disp=(int8_t)*q++; qleft--; consumed++; }
            if (mod == 2) { if(qleft<4) return consumed; disp=ri32(q);  q+=4; qleft-=4; consumed+=4; }

            if (disp > 0) snprintf(addr,sizeof(addr),"[%s+0x%X]", r64[rm], disp);
            else if (disp < 0) snprintf(addr,sizeof(addr),"[%s-0x%X]", r64[rm], -disp);
            else snprintf(addr,sizeof(addr),"[%s]", r64[rm]);
        }

        if (op_rm) snprintf(op_rm, op_rm_sz, "%s %s", sz_pfx, addr);
        return consumed;
    }


    static const char* grp1_name(int reg) {
        static const char* t[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
        return t[reg & 7];
    }

    static const char* grp2_name(int reg) {
        static const char* t[] = {"rol","ror","rcl","rcr","shl","shr","???","sar"};
        return t[reg & 7];
    }

    static const char* jcc8_name(int op) {
        static const char* t[] = {"jo","jno","jb","jnb","je","jne","jbe","jnbe",
                                   "js","jns","jp","jnp","jl","jnl","jle","jnle"};
        return t[op & 0xF];
    }

    static const char* jcc32_name(int op2) {
        static const char* t[] = {"jo","jno","jb","jnb","je","jne","jbe","jnbe",
                                   "js","jns","jp","jnp","jl","jnl","jle","jnle"};
        return t[op2 & 0xF];
    }
}


static int x64_decode_one(const uint8_t* code, int avail, uint64_t va,
                           char* mnem, char* ops,
                           bool& is_branch, bool& is_call, bool& is_ret)
{
    using namespace x64detail;
    if (!code || avail <= 0) return 0;
    mnem[0] = ops[0] = 0;
    is_branch = is_call = is_ret = false;

    const uint8_t* start = code;
    const uint8_t* p     = code;
    int left = avail;


    uint8_t rex  = 0;
    bool p66 = false, p67 = false, pF2 = false, pF3 = false;
    bool pLOCK = false, pREP = false;

    for (;;) {
        if (left <= 0) return (int)(p - start);
        uint8_t b = *p;
        if      (b >= 0x40 && b <= 0x4F)                          { rex  = b; p++; left--; }
        else if (b == 0x66)                                        { p66  = true; p++; left--; }
        else if (b == 0x67)                                        { p67  = true; p++; left--; }
        else if (b == 0xF2)                                        { pF2  = true; p++; left--; }
        else if (b == 0xF3)                                        { pF3  = true; p++; left--; }
        else if (b == 0xF0)                                        { pLOCK=true;  p++; left--; }
        else if (b==0x2E||b==0x36||b==0x3E||b==0x26||b==0x64||b==0x65) { p++; left--; }
        else break;
    }

    bool rW = (rex >> 3) & 1;
    bool rR = (rex >> 2) & 1;
    bool rX = (rex >> 1) & 1;
    bool rB = (rex >> 0) & 1;

    if (left <= 0) { snprintf(mnem,24,"db"); snprintf(ops,64,"0x%02X",*start); return 1; }

    uint8_t op = *p++; left--;


    switch (op) {

    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
        snprintf(mnem,24,"push");
        snprintf(ops,64,"%s", r64[(op&7)|(rB?8:0)]);
        return (int)(p-start);

    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        snprintf(mnem,24,"pop");
        snprintf(ops,64,"%s", r64[(op&7)|(rB?8:0)]);
        return (int)(p-start);

    case 0x6A:
        if (left<1) break;
        snprintf(mnem,24,"push");
        snprintf(ops,64,"0x%02X",(uint8_t)*p); p++; left--;
        return (int)(p-start);

    case 0x68:
        if (left<4) break;
        { uint32_t v=ru32(p); p+=4; left-=4;
          snprintf(mnem,24,"push"); snprintf(ops,64,"0x%X",v); }
        return (int)(p-start);

    case 0x83: {
        if (left<1) break;
        char rm[64]={}, reg_dummy[32]={};
        int reg_f=0;
        int c = decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&reg_f,rm,sizeof(rm),reg_dummy,sizeof(reg_dummy));
        if (!c||left<c+1) break;
        p+=c; left-=c;
        int8_t imm=(int8_t)*p++; left--;
        snprintf(mnem,24,"%s",grp1_name(reg_f));
        if (imm<0) snprintf(ops,64,"%s, -0x%X",rm,(int)-imm);
        else       snprintf(ops,64,"%s, 0x%X",rm,(int)imm);
        return (int)(p-start); }

    case 0x81: {
        if (left<1) break;
        char rm[64]={}, dummy[32]={};
        int reg_f=0;
        int c = decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&reg_f,rm,sizeof(rm),dummy,sizeof(dummy));
        if (!c||left<c+4) break;
        p+=c; left-=c;
        int32_t imm=ri32(p); p+=4; left-=4;
        snprintf(mnem,24,"%s",grp1_name(reg_f));
        if (imm<0) snprintf(ops,64,"%s, -0x%X",rm,-imm);
        else       snprintf(ops,64,"%s, 0x%X",rm,(unsigned)imm);
        return (int)(p-start); }

    case 0x80: {
        if (left<1) break;
        char rm[64]={}, dummy[32]={};
        int reg_f=0;
        int c = decode_modrm(p,left,rR,rX,rB,false,p66,p67,0,&reg_f,rm,sizeof(rm),dummy,sizeof(dummy),-1);
        if (!c||left<c+1) break;
        p+=c; left-=c;
        uint8_t imm=*p++; left--;
        snprintf(mnem,24,"%s",grp1_name(reg_f));
        snprintf(ops,64,"%s, 0x%X",rm,imm);
        return (int)(p-start); }

    case 0x01: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"add"); snprintf(ops,64,"%s, %s",rm,rg);
                 return (int)(p-start); }
    case 0x03: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"add"); snprintf(ops,64,"%s, %s",rg,rm);
                 return (int)(p-start); }

    case 0x29: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"sub"); snprintf(ops,64,"%s, %s",rm,rg);
                 return (int)(p-start); }
    case 0x2B: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"sub"); snprintf(ops,64,"%s, %s",rg,rm);
                 return (int)(p-start); }

    case 0x21: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"and"); snprintf(ops,64,"%s, %s",rm,rg);
                 return (int)(p-start); }
    case 0x23: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"and"); snprintf(ops,64,"%s, %s",rg,rm);
                 return (int)(p-start); }

    case 0x09: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"or"); snprintf(ops,64,"%s, %s",rm,rg);
                 return (int)(p-start); }
    case 0x0B: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"or"); snprintf(ops,64,"%s, %s",rg,rm);
                 return (int)(p-start); }

    case 0x31: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"xor"); snprintf(ops,64,"%s, %s",rm,rg);
                 return (int)(p-start); }
    case 0x33: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"xor"); snprintf(ops,64,"%s, %s",rg,rm);
                 return (int)(p-start); }

    case 0x39: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"cmp"); snprintf(ops,64,"%s, %s",rm,rg);
                 return (int)(p-start); }
    case 0x3B: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"cmp"); snprintf(ops,64,"%s, %s",rg,rm);
                 return (int)(p-start); }
    case 0x3C: if(left<1)break; { snprintf(mnem,24,"cmp"); snprintf(ops,64,"al, 0x%02X",(uint8_t)*p++); left--; return (int)(p-start); }
    case 0x3D: if(left<4)break; { snprintf(mnem,24,"cmp"); snprintf(ops,64,"%s, 0x%X",r64[0|(rB?8:0)],ru32(p)); p+=4; left-=4; return (int)(p-start); }

    case 0x84: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,false,p66,p67,0,&rg_f,rm,64,rg,32,8);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"test"); snprintf(ops,64,"%s, %s",rm,rg);
                 return (int)(p-start); }
    case 0x85: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"test"); snprintf(ops,64,"%s, %s",rm,rg);
                 return (int)(p-start); }
    case 0xA9: if(left<4)break; { snprintf(mnem,24,"test"); snprintf(ops,64,"eax, 0x%X",ru32(p)); p+=4; left-=4; return (int)(p-start); }

    case 0x88: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,false,p66,p67,0,&rg_f,rm,64,rg,32,8);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"mov"); snprintf(ops,64,"%s, %s",rm,rg);
                 return (int)(p-start); }
    case 0x89: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"mov"); snprintf(ops,64,"%s, %s",rm,rg);
                 return (int)(p-start); }

    case 0x8A: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,false,p66,p67,0,&rg_f,rm,64,rg,32,8);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"mov"); snprintf(ops,64,"%s, %s",rg,rm);
                 return (int)(p-start); }
    case 0x8B: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"mov"); snprintf(ops,64,"%s, %s",rg,rm);
                 return (int)(p-start); }

    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        if (left<1) break;
        snprintf(mnem,24,"mov");
        snprintf(ops,64,"%s, 0x%02X", r8[(op&7)|(rB?8:0)], (uint8_t)*p++); left--;
        return (int)(p-start);
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        if (rW) {
            if (left<8) break;
            uint64_t v = ru64(p); p+=8; left-=8;
            snprintf(mnem,24,"mov"); snprintf(ops,64,"%s, 0x%llX", r64[(op&7)|(rB?8:0)], (unsigned long long)v);
        } else {
            if (left<4) break;
            uint32_t v = ru32(p); p+=4; left-=4;
            snprintf(mnem,24,"mov"); snprintf(ops,64,"%s, 0x%X", r32[(op&7)|(rB?8:0)], v);
        }
        return (int)(p-start);

    case 0xC6: { if(left<1)break;
                 char rm[64]={},dummy[32]={};
                 int c=decode_modrm(p,left,rR,rX,rB,false,p66,p67,0,nullptr,rm,64,dummy,32,8);
                 if(!c||left<c+1) break; p+=c; left-=c;
                 uint8_t imm=*p++; left--;
                 snprintf(mnem,24,"mov"); snprintf(ops,64,"%s, 0x%02X",rm,imm);
                 return (int)(p-start); }
    case 0xC7: { if(left<1)break;
                 char rm[64]={},dummy[32]={};
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,nullptr,rm,64,dummy,32);
                 if(!c||left<c+4) break; p+=c; left-=c;
                 int32_t imm=ri32(p); p+=4; left-=4;
                 snprintf(mnem,24,"mov");
                 if (imm<0) snprintf(ops,64,"%s, -0x%X",rm,-imm);
                 else       snprintf(ops,64,"%s, 0x%X",rm,(uint32_t)imm);
                 return (int)(p-start); }

    case 0x8D: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;

                 const char* mr = rm;
                 if (strncmp(rm,"qword ptr ",10)==0) mr=rm+10;
                 else if(strncmp(rm,"dword ptr ",10)==0) mr=rm+10;
                 snprintf(mnem,24,"lea"); snprintf(ops,64,"%s, %s",rg,mr);
                 return (int)(p-start); }

    case 0x86: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,false,p66,p67,0,&rg_f,rm,64,rg,32,8);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"xchg"); snprintf(ops,64,"%s, %s",rm,rg);
                 return (int)(p-start); }
    case 0x87: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"xchg"); snprintf(ops,64,"%s, %s",rm,rg);
                 return (int)(p-start); }

    case 0x90:
        snprintf(mnem,24,"nop"); ops[0]=0;
        return (int)(p-start);

    case 0xC3:
        snprintf(mnem,24,"ret"); ops[0]=0; is_ret=true;
        return (int)(p-start);
    case 0xC2:
        if (left<2) break;
        snprintf(mnem,24,"retn"); snprintf(ops,64,"0x%04X",ri16(p)&0xFFFF); p+=2; left-=2; is_ret=true;
        return (int)(p-start);

    case 0xCC:
        snprintf(mnem,24,"int3"); ops[0]=0;
        return (int)(p-start);
    case 0xCD:
        if (left<1) break;
        snprintf(mnem,24,"int"); snprintf(ops,64,"0x%02X",(uint8_t)*p++); left--;
        return (int)(p-start);

    case 0xE8:
        if (left<4) break;
        { int32_t rel=ri32(p); p+=4; left-=4;
          uint64_t tgt = va + (uint64_t)(p-start) + (int64_t)rel;
          snprintf(mnem,24,"call"); snprintf(ops,64,"0x%llX",(unsigned long long)tgt);
          is_call=true; }
        return (int)(p-start);

    case 0xE9:
        if (left<4) break;
        { int32_t rel=ri32(p); p+=4; left-=4;
          uint64_t tgt = va + (uint64_t)(p-start) + (int64_t)rel;
          snprintf(mnem,24,"jmp"); snprintf(ops,64,"0x%llX",(unsigned long long)tgt);
          is_branch=true; }
        return (int)(p-start);

    case 0xEB:
        if (left<1) break;
        { int8_t rel=(int8_t)*p++; left--;
          uint64_t tgt = va + (uint64_t)(p-start) + (int64_t)rel;
          snprintf(mnem,24,"jmp"); snprintf(ops,64,"0x%llX",(unsigned long long)tgt);
          is_branch=true; }
        return (int)(p-start);

    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        if (left<1) break;
        { int8_t rel=(int8_t)*p++; left--;
          uint64_t tgt = va + (uint64_t)(p-start) + (int64_t)rel;
          snprintf(mnem,24,"%s",jcc8_name(op)); snprintf(ops,64,"0x%llX",(unsigned long long)tgt);
          is_branch=true; }
        return (int)(p-start);

    case 0xC0: { char rm[64]={},dummy[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,false,p66,p67,0,&rg_f,rm,64,dummy,32,8);
                 if(!c||left<c+1) break; p+=c; left-=c;
                 uint8_t imm=*p++; left--;
                 snprintf(mnem,24,"%s",grp2_name(rg_f)); snprintf(ops,64,"%s, 0x%X",rm,imm);
                 return (int)(p-start); }
    case 0xC1: { char rm[64]={},dummy[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,dummy,32);
                 if(!c||left<c+1) break; p+=c; left-=c;
                 uint8_t imm=*p++; left--;
                 snprintf(mnem,24,"%s",grp2_name(rg_f)); snprintf(ops,64,"%s, 0x%X",rm,imm);
                 return (int)(p-start); }
    case 0xD1: { char rm[64]={},dummy[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,dummy,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"%s",grp2_name(rg_f)); snprintf(ops,64,"%s, 1",rm);
                 return (int)(p-start); }
    case 0xD3: { char rm[64]={},dummy[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,dummy,32);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,"%s",grp2_name(rg_f)); snprintf(ops,64,"%s, cl",rm);
                 return (int)(p-start); }

    case 0x69: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c||left<c+4) break; p+=c; left-=c;
                 int32_t imm=ri32(p); p+=4; left-=4;
                 snprintf(mnem,24,"imul");
                 if(imm<0) snprintf(ops,64,"%s, %s, -0x%X",rg,rm,-imm);
                 else      snprintf(ops,64,"%s, %s, 0x%X",rg,rm,(uint32_t)imm);
                 return (int)(p-start); }
    case 0x6B: { char rm[64]={},rg[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                 if(!c||left<c+1) break; p+=c; left-=c;
                 int8_t imm=(int8_t)*p++; left--;
                 snprintf(mnem,24,"imul");
                 if(imm<0) snprintf(ops,64,"%s, %s, -0x%X",rg,rm,(int)-imm);
                 else      snprintf(ops,64,"%s, %s, 0x%X",rg,rm,(int)imm);
                 return (int)(p-start); }

    case 0xF6: { char rm[64]={},dummy[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,false,p66,p67,0,&rg_f,rm,64,dummy,32,8);
                 if(!c) break; p+=c; left-=c;
                 static const char* t[]={"test","???","not","neg","mul","imul","div","idiv"};
                 if(rg_f==0){if(left<1)break;uint8_t imm=*p++;left--;snprintf(mnem,24,"test");snprintf(ops,64,"%s, 0x%02X",rm,imm);}
                 else{snprintf(mnem,24,"%s",t[rg_f&7]);snprintf(ops,64,"%s",rm);}
                 return (int)(p-start); }
    case 0xF7: { char rm[64]={},dummy[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,dummy,32);
                 if(!c) break; p+=c; left-=c;
                 static const char* t[]={"test","???","not","neg","mul","imul","div","idiv"};
                 if(rg_f==0){if(left<4)break;int32_t imm=ri32(p);p+=4;left-=4;
                   if(imm<0)snprintf(ops,64,"%s, -0x%X",rm,-imm);
                   else     snprintf(ops,64,"%s, 0x%X",rm,(uint32_t)imm);
                   snprintf(mnem,24,"test");}
                 else{snprintf(mnem,24,"%s",t[rg_f&7]);snprintf(ops,64,"%s",rm);}
                 return (int)(p-start); }

    case 0xFE: { char rm[64]={},dummy[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,false,p66,p67,0,&rg_f,rm,64,dummy,32,8);
                 if(!c) break; p+=c; left-=c;
                 snprintf(mnem,24,rg_f==0?"inc":"dec"); snprintf(ops,64,"%s",rm);
                 return (int)(p-start); }
    case 0xFF: { char rm[64]={},dummy[32]={}; int rg_f=0;
                 int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,dummy,32);
                 if(!c) break; p+=c; left-=c;
                 switch(rg_f&7){
                   case 0: snprintf(mnem,24,"inc"); snprintf(ops,64,"%s",rm); break;
                   case 1: snprintf(mnem,24,"dec"); snprintf(ops,64,"%s",rm); break;
                   case 2: snprintf(mnem,24,"call"); snprintf(ops,64,"%s",rm); is_call=true; break;
                   case 4: snprintf(mnem,24,"jmp"); snprintf(ops,64,"%s",rm); is_branch=true; break;
                   case 6: snprintf(mnem,24,"push"); snprintf(ops,64,"%s",rm); break;
                   default: snprintf(mnem,24,"grp5/%d",rg_f&7); snprintf(ops,64,"%s",rm); break;
                 }
                 return (int)(p-start); }

    case 0x0F: {
        if (left<1) break;
        uint8_t op2 = *p++; left--;
        switch(op2) {

        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F:
            if(left<4) break;
            { int32_t rel=ri32(p); p+=4; left-=4;
              uint64_t tgt=va+(uint64_t)(p-start)+(int64_t)rel;
              snprintf(mnem,24,"%s",jcc32_name(op2)); snprintf(ops,64,"0x%llX",(unsigned long long)tgt);
              is_branch=true; }
            return (int)(p-start);

        case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
        case 0x96: case 0x97: case 0x98: case 0x99: case 0x9A: case 0x9B:
        case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
            static const char* st[]={"seto","setno","setb","setnb","sete","setne","setbe","setnbe",
                                      "sets","setns","setp","setnp","setl","setnl","setle","setnle"};
            char rm[64]={},dummy[32]={}; int rg_f=0;
            int c=decode_modrm(p,left,rR,rX,rB,false,p66,p67,0,&rg_f,rm,64,dummy,32,8);
            if(!c) break; p+=c; left-=c;
            snprintf(mnem,24,"%s",st[op2&0xF]); snprintf(ops,64,"%s",rm);
            return (int)(p-start); }

        case 0xB6: { char rm[64]={},rg[32]={}; int rg_f=0;
                     int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32,-1);
                     if(!c) break; p+=c; left-=c;

                     char rm8[64]={}; decode_modrm(p-(c),c+left,rR,rX,rB,false,p66,p67,0,nullptr,rm8,64,nullptr,0,8);

                     snprintf(mnem,24,"movzx"); snprintf(ops,64,"%s, %s",rg,rm8);
                     return (int)(p-start); }
        case 0xB7: { char rm[64]={},rg[32]={}; int rg_f=0;
                     int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32,-1);
                     if(!c) break; p+=c; left-=c;
                     snprintf(mnem,24,"movzx"); snprintf(ops,64,"%s, %s",rg,rm);
                     return (int)(p-start); }

        case 0xBE: case 0xBF: {
            char rm[64]={},rg[32]={}; int rg_f=0;
            int sz = op2==0xBE ? 8 : 16;
            int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32,sz);
            if(!c) break; p+=c; left-=c;
            snprintf(mnem,24,"movsx"); snprintf(ops,64,"%s, %s",rg,rm);
            return (int)(p-start); }

        case 0xAF: { char rm[64]={},rg[32]={}; int rg_f=0;
                     int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
                     if(!c) break; p+=c; left-=c;
                     snprintf(mnem,24,"imul"); snprintf(ops,64,"%s, %s",rg,rm);
                     return (int)(p-start); }

        case 0xA3: case 0xAB: case 0xB3: case 0xBB: {
            static const char* bt[]={"bt","bts","btr","btc"};
            int idx = (op2==0xA3)?0:(op2==0xAB)?1:(op2==0xB3)?2:3;
            char rm[64]={},rg[32]={}; int rg_f=0;
            int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
            if(!c) break; p+=c; left-=c;
            snprintf(mnem,24,"%s",bt[idx]); snprintf(ops,64,"%s, %s",rm,rg);
            return (int)(p-start); }
        case 0xBC: case 0xBD: {
            char rm[64]={},rg[32]={}; int rg_f=0;
            int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
            if(!c) break; p+=c; left-=c;
            snprintf(mnem,24,op2==0xBC?"bsf":"bsr"); snprintf(ops,64,"%s, %s",rg,rm);
            return (int)(p-start); }

        case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
            static const char* ct[]={"cmovo","cmovno","cmovb","cmovnb","cmove","cmovne","cmovbe","cmovnbe",
                                      "cmovs","cmovns","cmovp","cmovnp","cmovl","cmovnl","cmovle","cmovnle"};
            char rm[64]={},rg[32]={}; int rg_f=0;
            int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,&rg_f,rm,64,rg,32);
            if(!c) break; p+=c; left-=c;
            snprintf(mnem,24,"%s",ct[op2&0xF]); snprintf(ops,64,"%s, %s",rg,rm);
            return (int)(p-start); }

        case 0x1F: { char rm[64]={},dummy[32]={};
                     int c=decode_modrm(p,left,rR,rX,rB,rW,p66,p67,0,nullptr,rm,64,dummy,32);
                     if(!c) break; p+=c; left-=c;
                     snprintf(mnem,24,"nop"); snprintf(ops,64,"%s",rm);
                     return (int)(p-start); }

        case 0x05: snprintf(mnem,24,"syscall"); ops[0]=0; return (int)(p-start);

        case 0xA2: snprintf(mnem,24,"cpuid"); ops[0]=0; return (int)(p-start);

        default:

            p--; left++;
            goto db_fallback;
        }
        break; }

    case 0x06: case 0x07: case 0x0E: case 0x16: case 0x17: case 0x1E: case 0x1F:
        snprintf(mnem,24,op&1?"pop":"push"); ops[0]=0;
        return (int)(p-start);

    case 0x9A: case 0xEA:
        goto db_fallback;

    case 0xC9:
        snprintf(mnem,24,"leave"); ops[0]=0;
        return (int)(p-start);

    case 0xC8:
        if (left<3) break;
        snprintf(mnem,24,"enter"); snprintf(ops,64,"0x%04X, 0x%02X",ri16(p)&0xFFFF,(uint8_t)p[2]);
        p+=3; left-=3;
        return (int)(p-start);

    case 0xF4: snprintf(mnem,24,"hlt");  ops[0]=0; return (int)(p-start);
    case 0xF8: snprintf(mnem,24,"clc");  ops[0]=0; return (int)(p-start);
    case 0xF9: snprintf(mnem,24,"stc");  ops[0]=0; return (int)(p-start);
    case 0xFA: snprintf(mnem,24,"cli");  ops[0]=0; return (int)(p-start);
    case 0xFB: snprintf(mnem,24,"sti");  ops[0]=0; return (int)(p-start);
    case 0xFC: snprintf(mnem,24,"cld");  ops[0]=0; return (int)(p-start);
    case 0xFD: snprintf(mnem,24,"std");  ops[0]=0; return (int)(p-start);

    case 0x99: snprintf(mnem,24,rW?"cqo":"cdq"); ops[0]=0; return (int)(p-start);
    case 0x98: snprintf(mnem,24,rW?"cdqe":"cwde"); ops[0]=0; return (int)(p-start);

    default:
        goto db_fallback;
    }

db_fallback:
    snprintf(mnem, 24, "db");
    snprintf(ops,  64, "0x%02X", (uint8_t)(*start));
    return 1;
}


namespace disasm
{
    inline std::string open_file_dialog(HWND owner)
    {
        char buf[MAX_PATH] = {};
        static const char k_filter[] =
            "PE Files (*.exe;*.dll;*.sys;*.bin)\0*.exe;*.dll;*.sys;*.bin\0"
            "All files (*.*)\0*.*\0\0";
        if (win32_dialog::show_open_file_dialog(owner,
                "Open PE File",
                k_filter,
                buf, sizeof(buf),
                "disasm.h::open_file_dialog"))
            return std::string(buf);
        return {};
    }

    inline bool load_pe(const std::string& path, DisasmFile& out)
    {
        out = {};
        out.path = path;

        size_t sl = path.find_last_of("/\\");
        out.filename = (sl != std::string::npos) ? path.substr(sl+1) : path;

        HANDLE hf = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, 0, nullptr);
        if (hf == INVALID_HANDLE_VALUE) { out.err = "Cannot open file"; return false; }

        DWORD fsz = GetFileSize(hf, nullptr);
        if (fsz == INVALID_FILE_SIZE || fsz < sizeof(IMAGE_DOS_HEADER)) {
            CloseHandle(hf); out.err = "File too small"; return false;
        }

        std::vector<uint8_t> raw(fsz);
        DWORD read = 0;
        if (!ReadFile(hf, raw.data(), fsz, &read, nullptr) || read != fsz) {
            CloseHandle(hf); out.err = "Read error"; return false;
        }
        CloseHandle(hf);

        auto* dos = (IMAGE_DOS_HEADER*)raw.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { out.err = "Not a PE file"; return false; }
        if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fsz) { out.err = "Corrupt PE"; return false; }

        auto* nt = (IMAGE_NT_HEADERS64*)(raw.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) { out.err = "Not a PE file"; return false; }
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) { out.err = "Not x64 PE"; return false; }

        out.image_base = nt->OptionalHeader.ImageBase;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        WORD nsec = nt->FileHeader.NumberOfSections;

        for (WORD i = 0; i < nsec; i++) {
            bool is_exec = (sec[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
                           (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);
            if (!is_exec) continue;
            DWORD off = sec[i].PointerToRawData;
            DWORD sz  = sec[i].SizeOfRawData;
            if (sec[i].Misc.VirtualSize && sec[i].Misc.VirtualSize < sz) sz = sec[i].Misc.VirtualSize;
            if (sz == 0 || (uint64_t)off + sz > fsz) continue;
            PESection ps;
            ps.va = out.image_base + sec[i].VirtualAddress;
            ps.bytes.assign(raw.data() + off, raw.data() + off + sz);
            out.sections.push_back(std::move(ps));
        }
        if (out.sections.empty()) { out.err = "No executable section found"; return false; }
        out.text_va = out.sections[0].va;
        out.loaded = true;
        return true;
    }

    inline void decode_section(DisasmFile& file)
    {
        file.instrs.clear();
        file.instrs.reserve(file.sections[0].bytes.size() / 3);
        for (auto& section : file.sections) {
            const uint8_t* data = section.bytes.data();
            int             sz   = (int)section.bytes.size();
            int             off  = 0;
            uint64_t        va   = section.va;
            while (off < sz) {
                AsmInstr ins;
                ins.addr = va + off;
                char mn[24]={}, op[64]={};
                bool br=false, ca=false, rt=false;
                int avail = std::min(sz - off, 15);
                int len = x64_decode_one(data + off, avail, va + off, mn, op, br, ca, rt);
                if (len <= 0) len = 1;
                ins.len = len;
                memcpy(ins.raw, data + off, std::min(len, 15));
                memcpy(ins.mnem, mn, sizeof(ins.mnem));
                memcpy(ins.ops, op, sizeof(ins.ops));
                ins.is_branch = br;
                ins.is_call   = ca;
                ins.is_ret    = rt;
                file.instrs.push_back(ins);
                off += len;
            }
        }
    }
}
