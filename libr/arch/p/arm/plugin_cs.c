/* radare2 - LGPL - Copyright 2013-2026 - pancake */

#include <r_arch.h>
#include <sdb/ht_uu.h>

#define CAPSTONE_AARCH64_COMPAT_HEADER
#define CAPSTONE_ARM_COMPAT_HEADER
#include <capstone/capstone.h>
#include <capstone/arm.h>
#include <r_util/r_assert.h>
#include "../capstone.inc.c"
#include "arm_hacks.inc.c"
#include "asm_arm_hacks.inc.c"
#include "arm_regprofile.inc.c"

typedef char RStringShort[32];

typedef struct plugin_data_t {
	bool bigendian;
	int bits;
	char *cpu;
	csh cs_handle;
	HtUU *ht_itblock;
	HtUU *ht_it;
	int last_syntax;
} PluginData;

static inline csh *cs_handle_for_session(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, NULL);
	PluginData *pd = (PluginData*) as->data;
	return &(pd->cs_handle);
}

static inline HtUU *ht_itblock_for_session (RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, NULL);
	PluginData *pd = (PluginData*) as->data;
	return pd->ht_itblock;
}

static inline HtUU *ht_it_for_session (RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, NULL);
	PluginData *pd = (PluginData*) as->data;
	return pd->ht_it;
}

/* arm64 */
#define IMM64(x) (ut64)(insn->detail->arm64.operands[x].imm)
#define INSOP64(x) insn->detail->arm64.operands[x]

/* arm32 */
#define REG(x) r_str_getf (cs_reg_name (*handle, insn->detail->arm.operands[x].reg))
#define REG64(x) r_str_getf (cs_reg_name (*handle, insn->detail->arm64.operands[x].reg))
#define REGID64(x) insn->detail->arm64.operands[x].reg
#define REGID(x) insn->detail->arm.operands[x].reg
#define IMM(x) (ut32)(insn->detail->arm.operands[x].imm)
#define INSOP(x) insn->detail->arm.operands[x]
#define MEMBASE(x) r_str_getf (cs_reg_name (*handle, insn->detail->arm.operands[x].mem.base))
#define MEMBASE64(x) r_str_getf (cs_reg_name (*handle, insn->detail->arm64.operands[x].mem.base))
#define REGBASE(x) insn->detail->arm.operands[x].mem.base
#define REGBASE64(x) insn->detail->arm64.operands[x].mem.base
// s/index/base|reg/
#define MEMINDEX(x) r_str_getf (cs_reg_name (*handle, insn->detail->arm.operands[x].mem.index))
#define HASMEMINDEX(x) (insn->detail->arm.operands[x].mem.index != ARM_REG_INVALID)
#define MEMINDEX64(x) r_str_getf (cs_reg_name (*handle, insn->detail->arm64.operands[x].mem.index))
#define HASMEMINDEX64(x) ((arm64_reg)insn->detail->arm64.operands[x].mem.index != ARM64_REG_INVALID)
#define ISMEMINDEXSUB(x) insn->detail->arm.operands[x].subtracted
#define MEMDISP(x) insn->detail->arm.operands[x].mem.disp
#define MEMDISP64(x) (ut64)insn->detail->arm64.operands[x].mem.disp
#define ISIMM(x) (insn->detail->arm.operands[x].type == ARM_OP_IMM)
#define ISIMM64(x) ((arm64_op_type)insn->detail->arm64.operands[x].type & (ARM64_OP_IMM | ARM64_OP_CIMM | ARM64_OP_FP))
#define ISREG(x) (insn->detail->arm.operands[x].type == ARM_OP_REG)
#define ISREG64(x) ((arm64_op_type)insn->detail->arm64.operands[x].type == ARM64_OP_REG)
#define ISMEM(x) (insn->detail->arm.operands[x].type == ARM_OP_MEM)
#define ISMEM64(x) ((arm64_op_type)insn->detail->arm64.operands[x].type == ARM64_OP_MEM)
#define EXT64(x) decode_sign_ext (insn->detail->arm64.operands[x].ext)

#define LSHIFT(x) insn->detail->arm.operands[x].mem.lshift
#define LSHIFT2(x) insn->detail->arm.operands[x].shift.value // Dangerous, returns value even if isn't LSL
#define LSHIFT2_64(x) insn->detail->arm64.operands[x].shift.value
#define OPCOUNT() insn->detail->arm.op_count
#define OPCOUNT64() insn->detail->arm64.op_count
#define ISSHIFTED(x) (insn->detail->arm.operands[x].shift.type != ARM_SFT_INVALID && insn->detail->arm.operands[x].shift.value != 0)
#define ISSHIFTED64(x) ((arm64_shifter)insn->detail->arm64.operands[x].shift.type != ARM64_SFT_INVALID && insn->detail->arm64.operands[x].shift.value != 0)
#define SHIFTTYPE(x) insn->detail->arm.operands[x].shift.type
#define SHIFTVALUE(x) insn->detail->arm.operands[x].shift.value

#if CS_API_MAJOR < 6
#define SHIFTTYPEREG(x) (\
		SHIFTTYPE(x) == ARM_SFT_ASR_REG || SHIFTTYPE(x) == ARM_SFT_LSL_REG || \
		SHIFTTYPE(x) == ARM_SFT_LSR_REG || SHIFTTYPE(x) == ARM_SFT_ROR_REG || \
		SHIFTTYPE(x) == ARM_SFT_RRX_REG)
#define ISWRITEBACK32() (insn->detail->arm.writeback == true)
#define ISWRITEBACK64() (insn->detail->arm64.writeback == true)
#define PSTATE() op->pstate
#define SYS() (ut64)op->sys
#define PREFETCH() op->prefetch
#define BARRIER() op->barrier
#else
// *********************
// CS6 compatibility:
#define SHIFTTYPEREG(x) (\
		SHIFTTYPE(x) == ARM_SFT_ASR_REG || SHIFTTYPE(x) == ARM_SFT_LSL_REG || \
		SHIFTTYPE(x) == ARM_SFT_LSR_REG || SHIFTTYPE(x) == ARM_SFT_ROR_REG)
#define ISWRITEBACK32() (insn->detail->writeback == true)
#define ISWRITEBACK64() ISWRITEBACK32 ()
#define PSTATE() op->sysop.alias.pstateimm0_15
#define SYS() (ut64)op->sysop.reg.tlbi
#define PREFETCH() op->sysop.alias.prfm
#define BARRIER() op->sysop.alias.db
// *********************
#endif

#define ISPREINDEX32() (((OPCOUNT () == 2) && (ISMEM (1)) && (ISWRITEBACK32 ())) || ((OPCOUNT () == 3) && (ISMEM (2)) && (ISWRITEBACK32 ())))
#define ISPOSTINDEX32() (((OPCOUNT () == 3) && (ISIMM (2) || ISREG (2)) && (ISWRITEBACK32 ())) || ((OPCOUNT () == 4) && (ISIMM (3) || ISREG (3)) && (ISWRITEBACK32 ())))
#define ISPREINDEX64() (((OPCOUNT64 () == 2) && (ISMEM64 (1)) && (ISWRITEBACK64 ())) || ((OPCOUNT64 () == 3) && (ISMEM64 (2)) && (ISWRITEBACK64 ())))
#define ISPOSTINDEX64() (((OPCOUNT64 () == 3) && (ISIMM64 (2)) && (ISWRITEBACK64 ())) || ((OPCOUNT64 () == 4) && (ISIMM64 (3)) && (ISWRITEBACK64 ())))

// *********************
// CS6 compatibility:
#if CS_API_MAJOR == 6

#define ARM_INS_NOP ARM_INS_ALIAS_NOP

#define ARM64_INS_MNEG ARM64_INS_ALIAS_MNEG
#define ARM64_INS_NOP ARM64_INS_ALIAS_NOP
#define ARM64_INS_CMP ARM64_INS_ALIAS_CMP
#define ARM64_INS_CMN ARM64_INS_ALIAS_CMN
#define ARM64_INS_TST ARM64_INS_ALIAS_TST
#define ARM64_INS_CSET ARM64_INS_ALIAS_CSET
#define ARM64_INS_CINC ARM64_INS_ALIAS_CINC
#define ARM64_INS_CSETM ARM64_INS_ALIAS_CSETM
#define ARM64_INS_CINV ARM64_INS_ALIAS_CINV
#define ARM64_INS_CNEG ARM64_INS_ALIAS_CNEG
#define ARM64_INS_MVN ARM64_INS_ALIAS_MVN
#define ARM64_INS_BFI ARM64_INS_ALIAS_BFI
#define ARM64_INS_BFXIL ARM64_INS_ALIAS_BFXIL
#define ARM64_INS_SBFIZ ARM64_INS_ALIAS_SBFIZ
#define ARM64_INS_UBFIZ ARM64_INS_ALIAS_UBFIZ
#define ARM64_INS_SBFX ARM64_INS_ALIAS_SBFX
#define ARM64_INS_UBFX ARM64_INS_ALIAS_UBFX
#define ARM64_INS_NEGS ARM64_INS_ALIAS_NEGS
#define ARM64_INS_NGC ARM64_INS_ALIAS_NGC
#define ARM64_INS_NGCS ARM64_INS_ALIAS_NGCS
#define ARM64_INS_PACIA1716 ARM64_INS_ALIAS_PACIA1716
#define ARM64_INS_PACIASP ARM64_INS_ALIAS_PACIASP
#define ARM64_INS_PACIAZ ARM64_INS_ALIAS_PACIAZ
#define ARM64_INS_PACIB1716 ARM64_INS_ALIAS_PACIB1716
#define ARM64_INS_PACIBSP ARM64_INS_ALIAS_PACIBSP
#define ARM64_INS_PACIBZ ARM64_INS_ALIAS_PACIBZ
#define ARM64_INS_AUTIA1716 ARM64_INS_ALIAS_AUTIA1716
#define ARM64_INS_AUTIASP ARM64_INS_ALIAS_AUTIASP
#define ARM64_INS_AUTIAZ ARM64_INS_ALIAS_AUTIAZ
#define ARM64_INS_AUTIB1716 ARM64_INS_ALIAS_AUTIB1716
#define ARM64_INS_AUTIBSP ARM64_INS_ALIAS_AUTIBSP
#define ARM64_INS_AUTIBZ ARM64_INS_ALIAS_AUTIBZ
#define ARM64_INS_XPACLRI ARM64_INS_ALIAS_XPACLRI
#define ARM64_INS_IC ARM64_INS_ALIAS_IC
#define ARM64_INS_DC ARM64_INS_ALIAS_DC
#define ARM64_INS_NEGS ARM64_INS_ALIAS_NEGS

// ARM64_OP_*:

#define ARM64_OP_PSTATE ARM64_OP_PSTATEIMM0_15
#define ARM64_PSTATE_SPSEL ARM64_PSTATEIMM0_15_SPSEL
#define ARM64_PSTATE_DAIFSET ARM64_PSTATEIMM0_15_DAIFSET
#define ARM64_PSTATE_DAIFCLR ARM64_PSTATEIMM0_15_DAIFCLR

#define ARM64_OP_SYS ARM64_OP_TLBI
#define ARM64_OP_PREFETCH ARM64_OP_PRFM
#define ARM64_OP_BARRIER ARM64_OP_DB

// GRP
#define ARM64_GRP_CRC ARM64_FEATURE_HASCRC
#define ARM64_GRP_NEON ARM64_FEATURE_HASNEON
#define ARM64_GRP_FPARMV8 ARM64_FEATURE_HASFPARMV8

#define ARM_GRP_CRC ARM_FEATURE_HASCRC
#define ARM_GRP_NEON ARM_FEATURE_HASNEON
#define ARM_GRP_FPARMV8 ARM_FEATURE_HASFPARMV8
#endif
// *********************

#define BITMASK_BY_WIDTH_COUNT 64
static const ut64 bitmask_by_width[BITMASK_BY_WIDTH_COUNT] = {
	0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff,
	0xfff, 0x1fff, 0x3fff, 0x7fff, 0xffff, 0x1ffff, 0x3ffff, 0x7ffff,
	0xfffff, 0x1fffff, 0x3fffff, 0x7fffff, 0xffffff, 0x1ffffffLL, 0x3ffffffLL,
	0x7ffffffLL, 0xfffffffLL, 0x1fffffffLL, 0x3fffffffLL, 0x7fffffffLL, 0xffffffffLL,
	0x1ffffffffLL, 0x3ffffffffLL, 0x7ffffffffLL, 0xfffffffffLL, 0x1fffffffffLL,
	0x3fffffffffLL, 0x7fffffffffLL, 0xffffffffffLL, 0x1ffffffffffLL, 0x3ffffffffffLL,
	0x7ffffffffffLL, 0xfffffffffffLL, 0x1fffffffffffLL, 0x3fffffffffffLL, 0x7fffffffffffLL,
	0xffffffffffffLL, 0x1ffffffffffffLL, 0x3ffffffffffffLL, 0x7ffffffffffffLL,
	0xfffffffffffffLL, 0x1fffffffffffffLL, 0x3fffffffffffffLL, 0x7fffffffffffffLL,
	0xffffffffffffffLL, 0x1ffffffffffffffLL, 0x3ffffffffffffffLL, 0x7ffffffffffffffLL,
	0xfffffffffffffffLL, 0x1fffffffffffffffLL, 0x3fffffffffffffffLL, 0x7fffffffffffffffLL, 0xffffffffffffffffLL
};

static const char *shift_type_name(arm_shifter type) {
	switch (type) {
	case ARM_SFT_ASR:
		return "asr";
	case ARM_SFT_LSL:
		return "lsl";
	case ARM_SFT_LSR:
		return "lsr";
	case ARM_SFT_ROR:
		return "ror";
	case ARM_SFT_RRX:
		return "rrx";
	case ARM_SFT_ASR_REG:
		return "asr_reg";
	case ARM_SFT_LSL_REG:
		return "lsl_reg";
	case ARM_SFT_LSR_REG:
		return "lsr_reg";
	case ARM_SFT_ROR_REG:
		return "ror_reg";
#if CS_API_MAJOR < 6
	case ARM_SFT_RRX_REG:
		return "rrx_reg";
#endif
	default:
		return "";
	}
}

static const char *vector_data_type_name(arm_vectordata_type type) {
	switch (type) {
	case ARM_VECTORDATA_I8:
		return "i8";
	case ARM_VECTORDATA_I16:
		return "i16";
	case ARM_VECTORDATA_I32:
		return "i32";
	case ARM_VECTORDATA_I64:
		return "i64";
	case ARM_VECTORDATA_S8:
		return "s8";
	case ARM_VECTORDATA_S16:
		return "s16";
	case ARM_VECTORDATA_S32:
		return "s32";
	case ARM_VECTORDATA_S64:
		return "s64";
	case ARM_VECTORDATA_U8:
		return "u8";
	case ARM_VECTORDATA_U16:
		return "u16";
	case ARM_VECTORDATA_U32:
		return "u32";
	case ARM_VECTORDATA_U64:
		return "u64";
	case ARM_VECTORDATA_P8:
		return "p8";
	case ARM_VECTORDATA_F32:
		return "f32";
	case ARM_VECTORDATA_F64:
		return "f64";
	case ARM_VECTORDATA_F16F64:
		return "f16.f64";
	case ARM_VECTORDATA_F64F16:
		return "f64.f16";
	case ARM_VECTORDATA_F32F16:
		return "f32.f16";
	case ARM_VECTORDATA_F16F32:
		return "f16.f32";
	case ARM_VECTORDATA_F64F32:
		return "f64.f32";
	case ARM_VECTORDATA_F32F64:
		return "f32.f64";
	case ARM_VECTORDATA_S32F32:
		return "s32.f32";
	case ARM_VECTORDATA_U32F32:
		return "u32.f32";
	case ARM_VECTORDATA_F32S32:
		return "f32.s32";
	case ARM_VECTORDATA_F32U32:
		return "f32.u32";
	case ARM_VECTORDATA_F64S16:
		return "f64.s16";
	case ARM_VECTORDATA_F32S16:
		return "f32.s16";
	case ARM_VECTORDATA_F64S32:
		return "f64.s32";
	case ARM_VECTORDATA_S16F64:
		return "s16.f64";
	case ARM_VECTORDATA_S16F32:
		return "s16.f64";
	case ARM_VECTORDATA_S32F64:
		return "s32.f64";
	case ARM_VECTORDATA_U16F64:
		return "u16.f64";
	case ARM_VECTORDATA_U16F32:
		return "u16.f32";
	case ARM_VECTORDATA_U32F64:
		return "u32.f64";
	case ARM_VECTORDATA_F64U16:
		return "f64.u16";
	case ARM_VECTORDATA_F32U16:
		return "f32.u16";
	case ARM_VECTORDATA_F64U32:
		return "f64.u32";
	default:
		return "";
	}
}

static const char *cc_name(arm_cc cc) {
	switch (cc) {
	case ARM_CC_EQ: // Equal                      Equal
		return "eq";
	case ARM_CC_NE: // Not equal                  Not equal, or unordered
		return "ne";
	case ARM_CC_HS: // Carry set                  >, ==, or unordered
		return "hs";
	case ARM_CC_LO: // Carry clear                Less than
		return "lo";
	case ARM_CC_MI: // Minus, negative            Less than
		return "mi";
	case ARM_CC_PL: // Plus, positive or zero     >, ==, or unordered
		return "pl";
	case ARM_CC_VS: // Overflow                   Unordered
		return "vs";
	case ARM_CC_VC: // No overflow                Not unordered
		return "vc";
	case ARM_CC_HI: // Unsigned higher            Greater than, or unordered
		return "hi";
	case ARM_CC_LS: // Unsigned lower or same     Less than or equal
		return "ls";
	case ARM_CC_GE: // Greater than or equal      Greater than or equal
		return "ge";
	case ARM_CC_LT: // Less than                  Less than, or unordered
		return "lt";
	case ARM_CC_GT: // Greater than               Greater than
		return "gt";
	case ARM_CC_LE: // Less than or equal         <, ==, or unordered
		return "le";
	default:
		return "";
	}
}

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	cs_arm *x = &insn->detail->arm;
	for (i = 0; i < x->op_count; i++) {
		cs_arm_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case ARM_OP_REG:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", cs_reg_name (handle, op->reg));
			break;
		case ARM_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_ki (pj, "value", op->imm);
			break;
		case ARM_OP_MEM:
			pj_ks (pj, "type", "mem");
			if (op->mem.base != ARM_REG_INVALID) {
				pj_ks (pj, "base", cs_reg_name (handle, op->mem.base));
			}
			if (op->mem.index != ARM_REG_INVALID) {
				pj_ks (pj, "index", cs_reg_name (handle, op->mem.index));
			}
			pj_ki (pj, "scale", op->mem.scale);
			pj_ki (pj, "disp", op->mem.disp);
			break;
		case ARM_OP_FP:
			pj_ks (pj, "type", "fp");
			pj_kd (pj, "value", op->fp);
			break;
		case ARM_OP_CIMM:
			pj_ks (pj, "type", "cimm");
			pj_ki (pj, "value", op->imm);
			break;
		case ARM_OP_PIMM:
			pj_ks (pj, "type", "pimm");
			pj_ki (pj, "value", op->imm);
			break;
		case ARM_OP_SETEND:
			pj_ks (pj, "type", "setend");
			switch (op->setend) {
			case ARM_SETEND_BE:
				pj_ks (pj, "value", "be");
				break;
			case ARM_SETEND_LE:
				pj_ks (pj, "value", "le");
				break;
			default:
				pj_ks (pj, "value", "invalid");
				break;
			}
			break;
		case ARM_OP_SYSREG:
			pj_ks (pj, "type", "sysreg");
			pj_ks (pj, "value", r_str_get_fail (cs_reg_name (handle, op->reg), ""));
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		if (op->shift.type != ARM_SFT_INVALID) {
			pj_ko (pj, "shift");
			switch (op->shift.type) {
			case ARM_SFT_ASR:
			case ARM_SFT_LSL:
			case ARM_SFT_LSR:
			case ARM_SFT_ROR:
			case ARM_SFT_RRX:
				pj_ks (pj, "type", shift_type_name (op->shift.type));
				pj_kn (pj, "value", (ut64)op->shift.value);
				break;
			case ARM_SFT_ASR_REG:
			case ARM_SFT_LSL_REG:
			case ARM_SFT_LSR_REG:
			case ARM_SFT_ROR_REG:
#if CS_API_MAJOR < 6
			case ARM_SFT_RRX_REG:
				pj_ks (pj, "type", shift_type_name (op->shift.type));
				pj_ks (pj, "value", cs_reg_name (handle, op->shift.value));
				break;
#endif
			default:
				break;
			}
			pj_end (pj); /* o shift */
		}
		if (op->vector_index != -1) {
			pj_ki (pj, "vector_index", op->vector_index);
		}
		if (op->subtracted) {
			pj_kb (pj, "subtracted", true);
		}
		pj_end (pj); /* o operand */
	}
	pj_end (pj); /* a operands */
	if (x->usermode) {
		pj_kb (pj, "usermode", true);
	}
	if (x->update_flags) {
		pj_kb (pj, "update_flags", true);
	}
	if (ISWRITEBACK32 ()) {
		pj_kb (pj, "writeback", true);
	}
	if (x->vector_size) {
		pj_ki (pj, "vector_size", x->vector_size);
	}
	if (x->vector_data != ARM_VECTORDATA_INVALID) {
		pj_ks (pj, "vector_data", vector_data_type_name (x->vector_data));
	}
	if (x->cps_mode != ARM_CPSMODE_INVALID) {
		pj_ki (pj, "cps_mode", x->cps_mode);
	}
	if (x->cps_flag != ARM_CPSFLAG_INVALID) {
		pj_ki (pj, "cps_flag", x->cps_flag);
	}
	if ((arm_cc)x->cc != ARM_CC_INVALID && (arm_cc)x->cc != ARM_CC_AL) {
		pj_ks (pj, "cc", cc_name (x->cc));
	}
	// XXX: No ARM_MB_INVALID for cs6
	if (x->mem_barrier /* != ARM_MB_INVALID */) {
		pj_ki (pj, "mem_barrier", x->mem_barrier - 1);
	}
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}

static int arm64_reg_width(int reg) {
	switch (reg) {
	case ARM64_REG_W0:
	case ARM64_REG_W1:
	case ARM64_REG_W2:
	case ARM64_REG_W3:
	case ARM64_REG_W4:
	case ARM64_REG_W5:
	case ARM64_REG_W6:
	case ARM64_REG_W7:
	case ARM64_REG_W8:
	case ARM64_REG_W9:
	case ARM64_REG_W10:
	case ARM64_REG_W11:
	case ARM64_REG_W12:
	case ARM64_REG_W13:
	case ARM64_REG_W14:
	case ARM64_REG_W15:
	case ARM64_REG_W16:
	case ARM64_REG_W17:
	case ARM64_REG_W18:
	case ARM64_REG_W19:
	case ARM64_REG_W20:
	case ARM64_REG_W21:
	case ARM64_REG_W22:
	case ARM64_REG_W23:
	case ARM64_REG_W24:
	case ARM64_REG_W25:
	case ARM64_REG_W26:
	case ARM64_REG_W27:
	case ARM64_REG_W28:
	case ARM64_REG_W29:
	case ARM64_REG_W30:
	case ARM64_REG_S0:
	case ARM64_REG_S1:
	case ARM64_REG_S2:
	case ARM64_REG_S3:
	case ARM64_REG_S4:
	case ARM64_REG_S5:
	case ARM64_REG_S6:
	case ARM64_REG_S7:
	case ARM64_REG_S8:
	case ARM64_REG_S9:
	case ARM64_REG_S10:
	case ARM64_REG_S11:
	case ARM64_REG_S12:
	case ARM64_REG_S13:
	case ARM64_REG_S14:
	case ARM64_REG_S15:
	case ARM64_REG_S16:
	case ARM64_REG_S17:
	case ARM64_REG_S18:
	case ARM64_REG_S19:
	case ARM64_REG_S20:
	case ARM64_REG_S21:
	case ARM64_REG_S22:
	case ARM64_REG_S23:
	case ARM64_REG_S24:
	case ARM64_REG_S25:
	case ARM64_REG_S26:
	case ARM64_REG_S27:
	case ARM64_REG_S28:
	case ARM64_REG_S29:
	case ARM64_REG_S30:
	case ARM64_REG_S31:
		return 32;
	default:
		break;
	}
	return 64;
}

static const char *cc_name64(arm64_cc cc) {
	switch (cc) {
	case ARM64_CC_EQ: // Equal
		return "eq";
	case ARM64_CC_NE: // Not equal:                 Not equal, or unordered
		return "ne";
	case ARM64_CC_HS: // Unsigned higher or same:   >, ==, or unordered
		return "hs";
	case ARM64_CC_LO: // Unsigned lower or same:    Less than
		return "lo";
	case ARM64_CC_MI: // Minus, negative:           Less than
		return "mi";
	case ARM64_CC_PL: // Plus, positive or zero:    >, ==, or unordered
		return "pl";
	case ARM64_CC_VS: // Overflow:                  Unordered
		return "vs";
	case ARM64_CC_VC: // No overflow:               Ordered
		return "vc";
	case ARM64_CC_HI: // Unsigned higher:           Greater than, or unordered
		return "hi";
	case ARM64_CC_LS: // Unsigned lower or same:    Less than or equal
		return "ls";
	case ARM64_CC_GE: // Greater than or equal:     Greater than or equal
		return "ge";
	case ARM64_CC_LT: // Less than:                 Less than, or unordered
		return "lt";
	case ARM64_CC_GT: // Signed greater than:       Greater than
		return "gt";
	case ARM64_CC_LE: // Signed less than or equal: <, ==, or unordered
		return "le";
	default:
		return "";
	}
}

static const char *extender_name(arm64_extender extender) {
	switch (extender) {
	case ARM64_EXT_UXTB:
		return "uxtb";
	case ARM64_EXT_UXTH:
		return "uxth";
	case ARM64_EXT_UXTW:
		return "uxtw";
	case ARM64_EXT_UXTX:
		return "uxtx";
	case ARM64_EXT_SXTB:
		return "sxtb";
	case ARM64_EXT_SXTH:
		return "sxth";
	case ARM64_EXT_SXTW:
		return "sxtw";
	case ARM64_EXT_SXTX:
		return "sxtx";
	default:
		return "";
	}
}

static const char *vas_name(arm64_vas vas) {
	switch (vas) {
	case ARM64_VAS_8B:
		return "8b";
	case ARM64_VAS_16B:
		return "16b";
	case ARM64_VAS_4H:
		return "4h";
	case ARM64_VAS_8H:
		return "8h";
	case ARM64_VAS_2S:
		return "2s";
	case ARM64_VAS_4S:
		return "4s";
	case ARM64_VAS_2D:
		return "2d";
	case ARM64_VAS_1D:
		return "1d";
	case ARM64_VAS_1Q:
		return "1q";
#if CS_API_MAJOR > 4
	case ARM64_VAS_4B:
		return "8b";
	case ARM64_VAS_2H:
		return "2h";
	case ARM64_VAS_1S:
		return "1s";
#if CS_API_MAJOR < 6
	case ARM64_VAS_1B:
		return "8b";
	case ARM64_VAS_1H:
		return "1h";
#endif
#endif
	default:
		return "";
	}
}

static int vas_size(arm64_vas vas) {
	switch (vas) {
	case ARM64_VAS_8B:
	case ARM64_VAS_16B:
		return 8;
	case ARM64_VAS_4H:
	case ARM64_VAS_8H:
		return 16;
	case ARM64_VAS_2S:
	case ARM64_VAS_4S:
		return 32;
	case ARM64_VAS_2D:
	case ARM64_VAS_1D:
		return 64;
	case ARM64_VAS_1Q:
		return 128;
#if CS_API_MAJOR > 4
	case ARM64_VAS_4B:
		return 8;
	case ARM64_VAS_2H:
		return 16;
	case ARM64_VAS_1S:
		return 32;
#if CS_API_MAJOR < 6
	case ARM64_VAS_1B:
		return 8;
	case ARM64_VAS_1H:
		return 16;
#endif
#endif
	default:
		return 64;
	}
}

static int vas_count(arm64_vas vas) {
	switch (vas) {
	case ARM64_VAS_16B:
		return 16;
	case ARM64_VAS_8B:
	case ARM64_VAS_8H:
		return 8;
	case ARM64_VAS_4S:
	case ARM64_VAS_4H:
		return 4;
	case ARM64_VAS_2D:
	case ARM64_VAS_2S:
		return 2;
	case ARM64_VAS_1D:
	case ARM64_VAS_1Q:
		return 1;
#if CS_API_MAJOR > 4
	case ARM64_VAS_4B:
		return 4;
	case ARM64_VAS_2H:
		return 2;
#if CS_API_MAJOR < 6
	case ARM64_VAS_1B:
	case ARM64_VAS_1H:
#endif
	case ARM64_VAS_1S:
		return 1;
#endif
	default:
		return 64;
	}
}

#if CS_API_MAJOR == 4
static const char *vess_name(arm64_vess vess) {
	switch (vess) {
	case ARM64_VESS_B:
		return "b";
	case ARM64_VESS_H:
		return "h";
	case ARM64_VESS_S:
		return "s";
	case ARM64_VESS_D:
		return "d";
	default:
		return "";
	}
}
#endif

#if CS_API_MAJOR == 4
static int vess_size(arm64_vess vess) {
	switch (vess) {
	case ARM64_VESS_B:
		return 8;
	case ARM64_VESS_H:
		return 16;
	case ARM64_VESS_S:
		return 32;
	case ARM64_VESS_D:
		return 64;
	default:
		return 64;
	}
}
#endif

static void opex64(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	cs_arm64 *x = &insn->detail->arm64;
	for (i = 0; i < x->op_count; i++) {
		cs_arm64_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case ARM64_OP_REG:
			{
			pj_ks (pj, "type", "reg");
			const char *rn = cs_reg_name (handle, op->reg);
			if (rn) {
				pj_ks (pj, "value", rn);
			}
			}
			break;
		case ARM64_OP_REG_MRS:
			pj_ks (pj, "type", "reg_mrs");
			// TODO value
			break;
		case ARM64_OP_REG_MSR:
			pj_ks (pj, "type", "reg_msr");
			// TODO value
			break;
		case ARM64_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_kN (pj, "value", op->imm);
			break;
		case ARM64_OP_MEM:
			pj_ks (pj, "type", "mem");
			if ((arm64_reg) op->mem.base != ARM64_REG_INVALID) {
				pj_ks (pj, "base", cs_reg_name (handle, op->mem.base));
			}
			if ((arm64_reg) op->mem.index != ARM64_REG_INVALID) {
				pj_ks (pj, "index", cs_reg_name (handle, op->mem.index));
			}
			pj_ki (pj, "disp", op->mem.disp);
			break;
		case ARM64_OP_FP:
			pj_ks (pj, "type", "fp");
			pj_kd (pj, "value", op->fp);
			break;
		case ARM64_OP_CIMM:
			pj_ks (pj, "type", "cimm");
			pj_kN (pj, "value", op->imm);
			break;
		case ARM64_OP_PSTATE:
			pj_ks (pj, "type", "pstate");
			switch (PSTATE ()) {
			case ARM64_PSTATE_SPSEL:
				pj_ks (pj, "value", "spsel");
				break;
			case ARM64_PSTATE_DAIFSET:
				pj_ks (pj, "value", "daifset");
				break;
			case ARM64_PSTATE_DAIFCLR:
				pj_ks (pj, "value", "daifclr");
				break;
			default:
				pj_ki (pj, "value", PSTATE ());
			}
			break;
		case ARM64_OP_SYS:
			pj_ks (pj, "type", "sys");
			pj_kn (pj, "value", SYS ());
			break;
		case ARM64_OP_PREFETCH:
			pj_ks (pj, "type", "prefetch");
			pj_ki (pj, "value", PREFETCH () - 1);
			break;
		case ARM64_OP_BARRIER:
			pj_ks (pj, "type", "prefetch");
			pj_ki (pj, "value", BARRIER () - 1);
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		if ((arm64_shifter)op->shift.type != ARM64_SFT_INVALID) {
			pj_ko (pj, "shift");
			switch (op->shift.type) {
			case ARM64_SFT_LSL:
				pj_ks (pj, "type", "lsl");
				break;
			case ARM64_SFT_MSL:
				pj_ks (pj, "type", "msl");
				break;
			case ARM64_SFT_LSR:
				pj_ks (pj, "type", "lsr");
				break;
			case ARM64_SFT_ASR:
				pj_ks (pj, "type", "asr");
				break;
			case ARM64_SFT_ROR:
				pj_ks (pj, "type", "ror");
				break;
			default:
				break;
			}
			pj_kn (pj, "value", (ut64)op->shift.value);
			pj_end (pj);
		}
		if ((arm64_extender) op->ext != ARM64_EXT_INVALID) {
			pj_ks (pj, "ext", extender_name (op->ext));
		}
		if (op->vector_index != -1) {
			pj_ki (pj, "vector_index", op->vector_index);
		}
		if ((arm64_vas)op->vas != ARM64_VAS_INVALID) {
			pj_ks (pj, "vas", vas_name (op->vas));
		}
#if CS_API_MAJOR == 4
		if (op->vess != ARM64_VESS_INVALID) {
			pj_ks (pj, "vess", vess_name (op->vess));
		}
#endif
		pj_end (pj);
	}
	pj_end (pj);
	if (x->update_flags) {
		pj_kb (pj, "update_flags", true);
	}
	if (ISWRITEBACK32 ()) {
		pj_kb (pj, "writeback", true);
	}
	if ((arm64_cc)x->cc != ARM64_CC_INVALID && (arm64_cc)x->cc != ARM64_CC_AL && (arm64_cc)x->cc != ARM64_CC_NV) {
		pj_ks (pj, "cc", cc_name64 (x->cc));
	}
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}

// uxtx extends nothing; the narrower unsigned extenders are masks
static int decode_zero_ext(arm64_extender extender) {
	switch (extender) {
	case ARM64_EXT_UXTB:
		return 8;
	case ARM64_EXT_UXTH:
		return 16;
	case ARM64_EXT_UXTW:
		return 32;
	default:
		break;
	}
	return 0;
}

static int decode_sign_ext(arm64_extender extender) {
	switch (extender) {
	case ARM64_EXT_SXTB:
		return 8;
	case ARM64_EXT_SXTH:
		return 16;
	case ARM64_EXT_SXTW:
		return 32;
	case ARM64_EXT_SXTX:
		return 64;
	default:
		break;
	}

	return 0;
}

static const char *E_OP_SR = ">>";
static const char *E_OP_SL = "<<";
static const char *E_OP_RR = "ROR";
static const char *E_OP_ASR = "ASR";
static const char *E_OP_AR = "ASR";
static const char *E_OP_VOID = "";

static const char *decode_shift(arm_shifter shift) {
	switch (shift) {
	case ARM_SFT_ASR:
	case ARM_SFT_ASR_REG:
		return E_OP_ASR;
	case ARM_SFT_LSR:
	case ARM_SFT_LSR_REG:
		return E_OP_SR;
	case ARM_SFT_LSL:
	case ARM_SFT_LSL_REG:
		return E_OP_SL;
	case ARM_SFT_ROR:
	case ARM_SFT_RRX:
	case ARM_SFT_ROR_REG:
#if CS_API_MAJOR < 6
	case ARM_SFT_RRX_REG:
		return E_OP_RR;
#endif
	default:
		break;
	}
	return E_OP_VOID;
}

static const char *decode_shift_64(arm64_shifter shift) {
	switch (shift) {
	case ARM64_SFT_ASR:
		return E_OP_AR;
	case ARM64_SFT_LSR:
		return E_OP_SR;
	case ARM64_SFT_LSL:
	case ARM64_SFT_MSL:
		return E_OP_SL;
	case ARM64_SFT_ROR:
		return E_OP_RR;
	default:
		break;
	}
	return E_OP_VOID;
}

#define DECODE_SHIFT(x) decode_shift(insn->detail->arm.operands[x].shift.type)
#define DECODE_SHIFT64(x) decode_shift_64(insn->detail->arm64.operands[x].shift.type)

static unsigned int regsize32(cs_insn *insn, int n) {
	R_RETURN_VAL_IF_FAIL (n >= 0 && n < insn->detail->arm.op_count, 0);
	unsigned int reg = insn->detail->arm.operands[n].reg;
	if (reg >= ARM_REG_D0 && reg <= ARM_REG_D31) {
		return 8;
	}
	if (reg >= ARM_REG_Q0 && reg <= ARM_REG_Q15) {
		return 16;
	}
	return 4; // s0-s31, r0-r15
}

static int regsize64(cs_insn *insn, int n) {
	unsigned int reg = insn->detail->arm64.operands[n].reg;
	if ((reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) ||
		(reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) ||
		reg == ARM64_REG_WZR) {
		return 4;
	}
	if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
		return 1;
	}
	if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
		return 2;
	}
	if ((reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) ||
#if CS_API_MAJOR < 6
		(reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) ) {
#else
		(false) ) {
#endif
		return 16;
	}
	return 8;
}

#define REGSIZE64(x) regsize64 (insn, x)
#define REGSIZE32(x) regsize32 (insn, x)
#define REGBITS64(x) (8 * regsize64 (insn, x))
#define REGBITS32(x) (8 * regsize32 (insn, x))

static inline bool is_vector_op(const cs_arm64_op *op) {
#if CS_API_MAJOR == 4
	return op->vess || op->vas;
#else
	return op->vas;
#endif
}

static int vector_size(cs_arm64_op *op) {
#if CS_API_MAJOR == 4
	if (op->vess) {
		return vess_size (op->vess);
	}
#endif
	if (op->vas) {
		return vas_size (op->vas);
	}
	return 64;
}

// return postfix
const char* arm_prefix_cond(RAnalOp *op, int cond_type) {
	const char *close_cond[2];
	close_cond[0] = "\0";
	close_cond[1] = ",}\0";
	int close_type = 0;
	switch (cond_type) {
	case ARM_CC_EQ:
		close_type = 1;
		r_strbuf_append (&op->esil, "zf,?{,");
		break;
	case ARM_CC_NE:
		close_type = 1;
		r_strbuf_append (&op->esil, "zf,!,?{,");
		break;
	case ARM_CC_HS:
		close_type = 1;
		r_strbuf_append (&op->esil, "cf,?{,");
		break;
	case ARM_CC_LO:
		close_type = 1;
		r_strbuf_append (&op->esil, "cf,!,?{,");
		break;
	case ARM_CC_MI:
		close_type = 1;
		r_strbuf_append (&op->esil, "nf,?{,");
		break;
	case ARM_CC_PL:
		close_type = 1;
		r_strbuf_append (&op->esil, "nf,!,?{,");
		break;
	case ARM_CC_VS:
		close_type = 1;
		r_strbuf_append (&op->esil, "vf,?{,");
		break;
	case ARM_CC_VC:
		close_type = 1;
		r_strbuf_append (&op->esil, "vf,!,?{,");
		break;
	case ARM_CC_HI:
		close_type = 1;
		r_strbuf_append (&op->esil, "cf,zf,!,&,?{,");
		break;
	case ARM_CC_LS:
		close_type = 1;
		r_strbuf_append (&op->esil, "cf,!,zf,|,?{,");
		break;
	case ARM_CC_GE:
		close_type = 1;
		r_strbuf_append (&op->esil, "nf,vf,^,!,?{,");
		break;
	case ARM_CC_LT:
		close_type = 1;
		r_strbuf_append (&op->esil, "nf,vf,^,?{,");
		break;
	case ARM_CC_GT:
		// zf == 0 && nf == vf
		close_type = 1;
		r_strbuf_append (&op->esil, "zf,!,nf,vf,^,!,&,?{,");
		break;
	case ARM_CC_LE:
		// zf == 1 || nf != vf
		close_type = 1;
		r_strbuf_append (&op->esil, "zf,nf,vf,^,|,?{,");
		break;
	case ARM_CC_AL:
		// always executed
		break;
	default:
		break;
	}
	return close_cond[close_type];
}

/* arm64 */

static const char *arg(RArchSession *as, csh *handle, cs_insn *insn, char *buf, size_t buf_sz, int n) {
	buf[0] = 0;
	switch (insn->detail->arm.operands[n].type) {
	case ARM_OP_REG:
		if (ISSHIFTED (n)) {
			if (SHIFTTYPEREG (n)) {
				// the shift count is Rs[7:0]
				snprintf (buf, buf_sz, "0xff,%s,&,%s,%s",
						cs_reg_name(*handle, LSHIFT2(n)),
						REG (n), DECODE_SHIFT (n));
			} else {
				snprintf (buf, buf_sz, "%u,%s,%s", LSHIFT2 (n), REG (n), DECODE_SHIFT (n));
			}
		} else {
			snprintf (buf, buf_sz, "%s",
			r_str_getf (cs_reg_name (*handle,
				insn->detail->arm.operands[n].reg)));
		}
		break;
	case ARM_OP_IMM:
		if (as->config->bits == 64) {
			// 64bit only
			snprintf (buf, buf_sz, "%"PFMT64d, (ut64)
					insn->detail->arm.operands[n].imm);
		} else {
			// 32bit only
			snprintf (buf, buf_sz, "%"PFMT64d, (ut64)(ut32)
					insn->detail->arm.operands[n].imm);
		}
		break;
	case ARM_OP_MEM:
		break;
	case ARM_OP_FP:
		snprintf (buf, buf_sz, "%lf", insn->detail->arm.operands[n].fp);
		break;
	default:
		break;
	}
	return buf;
}

#define ARG(x) arg(as, handle, insn, str[x], sizeof (str[x]), x)

#define VEC64(n) insn->detail->arm64.operands[n].vess
#define VEC64_APPEND(sb, n, i) vector64_append(sb, handle, insn, n, i)
#define VEC64_MASK(sh, sz) (bitmask_by_width[63]^(bitmask_by_width[sz>0?sz-1:0]<<sh))

static void vector64_append(RStrBuf *sb, csh *handle, cs_insn *insn, int n, int i) {
	cs_arm64_op op = INSOP64 (n);
	if (op.vector_index != -1) {
		i = op.vector_index;
	}
	if (is_vector_op (&op) && i != -1) {
		int size = vector_size (&op);
		int shift = i * size;
		char *regc = "l";
		if (shift >= 64) {
			shift -= 64;
			regc = "h";
		}

		size_t s = sizeof (bitmask_by_width) / sizeof (*bitmask_by_width);
		int width = size > 0? (size - 1) % s: 0;
		if (shift > 0) {
			r_strbuf_appendf (sb, "0x%"PFMT64x",%d,%s%s,>>,&",
				bitmask_by_width[width], shift, REG64 (n), regc);
		} else {
			r_strbuf_appendf (sb, "0x%"PFMT64x",%s%s,&",
				bitmask_by_width[width], REG64 (n), regc);
		}
	} else {
		r_strbuf_appendf (sb, "%s", REG64 (n));
	}
}

#define VEC64_DST_APPEND(sb, n, i) vector64_dst_append(sb, handle, insn, n, i)

static void vector64_dst_append(RStrBuf *sb, csh *handle, cs_insn *insn, int n, int i) {
	cs_arm64_op op = INSOP64 (n);

	if (op.vector_index != -1) {
		i = op.vector_index;
	}
	if (is_vector_op (&op) && i != -1) {
		int size = vector_size (&op);
		int shift = i * size;
		char *regc = "l";
		size_t s = sizeof (bitmask_by_width) / sizeof (*bitmask_by_width);
		size_t index = size > 0? (size - 1) % s: 0;
		if (index >= BITMASK_BY_WIDTH_COUNT) {
			index = 0;
		}
		ut64 mask = bitmask_by_width[index];
		if (shift >= 64) {
			shift -= 64;
			regc = "h";
		}
		if (shift > 0 && shift < 64) {
			r_strbuf_appendf (sb, "%d,SWAP,0x%"PFMT64x",&,<<,%s%s,0x%"PFMT64x",&,|,%s%s",
				shift, mask, REG64 (n), regc, VEC64_MASK (shift, size), REG64 (n), regc);
		} else {
			r_strbuf_appendf (sb, "0x%"PFMT64x",&,%s%s,0x%"PFMT64x",&,|,%s%s",
				mask, REG64 (n), regc, VEC64_MASK (shift, size), REG64 (n), regc);
		}
	} else {
		r_strbuf_append (sb, REG64 (n));
	}
}

#define SHIFTED_IMM64(n, sz) shifted_imm64 (&INSOP64 (n), sz)

static ut64 shifted_imm64(const cs_arm64_op *op, int sz) {
	const ut64 imm = op->imm;
	const int sft = op->shift.value;
	switch (op->shift.type) {
	case ARM64_SFT_MSL:
		return (imm << sft) | ((1 << sft) - 1);
	case ARM64_SFT_LSL:
		return imm << sft;
	case ARM64_SFT_LSR:
		return imm >> sft;
	case ARM64_SFT_ROR:
		return (imm >> sft)|(imm << (sz - sft));
	case ARM64_SFT_ASR:
		switch (sz) {
		case 8: return (st8)imm >> sft;
		case 16: return (st16)imm >> sft;
		case 32: return (st32)imm >> sft;
		default: return (st64)imm >> sft;
		}
	default:
		return imm;
	}
}

#define ARG64_APPEND(sb, n) arg64_append (sb, handle, insn, n, -1, 0)
#define ARG64_SIGN_APPEND(sb, n, s) arg64_append (sb, handle, insn, n, -1, s)
#define VECARG64_APPEND(sb, n, i, s) arg64_append (sb, handle, insn, n, i, s)
#define COMMA(sb) r_strbuf_append (sb, ",")

static void arg64_append(RStrBuf *sb, csh *handle, cs_insn *insn, int n, int i, int sign) {
	cs_arm64_op op = INSOP64 (n);

	int size = 64;
	if (ISREG64 (n)) {
		size = REGSIZE64 (n) * 8;
	}

	if (ISIMM64 (n)) {
		if (!ISSHIFTED64 (n)) {
			ut64 imm = SHIFTED_IMM64 (n, size);
			r_strbuf_appendf (sb, "0x%"PFMT64x, imm);
			return;
		}
	}
	const char *rn = (ISMEM64 (n) && HASMEMINDEX64 (n))
		? MEMINDEX64 (n): REG64 (n);
	int shift = LSHIFT2_64 (n);
	int signext = EXT64 (n);
	const int zeroext = decode_zero_ext (op.ext);
	if (sign && !signext) {
		signext = size;
	}
	// a64 extends the register first and shifts the extended value
	if (shift) {
		r_strbuf_appendf (sb, "%d,", shift);
	}
	if (signext) {
		r_strbuf_appendf (sb, "%d,", signext);
	} else if (zeroext) {
		r_strbuf_appendf (sb, "0x%"PFMT64x",", r_num_bitmask (zeroext));
	}

	if (is_vector_op (&op)) {
		VEC64_APPEND (sb, n, i);
	} else {
		if (n > 0 && ISIMM64 (n) && !ISMEM64 (n)) {
			r_strbuf_appendf (sb, "%d", (int)IMM64 (n));
		} else {
			r_strbuf_append (sb, rn);
		}
	}

	if (signext) {
		r_strbuf_append (sb, ",~");
	} else if (zeroext) {
		r_strbuf_append (sb, ",&");
	}
	if (shift) {
		r_strbuf_appendf (sb, ",%s", DECODE_SHIFT64 (n));
	}
}

#define OPCALL(opchar) arm64math(as, op, addr, buf, len, handle, insn, opchar, 0, 0, 0)
#define OPCALL_NEG(opchar) arm64math(as, op, addr, buf, len, handle, insn, opchar, 1, 0, 0)
#define OPCALL_SIGN(opchar, sign) arm64math(as, op, addr, buf, len, handle, insn, opchar, 0, sign, 0)
#define OPCALL_FLAGS(opchar, fl) arm64math(as, op, addr, buf, len, handle, insn, opchar, 0, 0, fl)
#define OPCALL_NEG_FLAGS(opchar, fl) arm64math(as, op, addr, buf, len, handle, insn, opchar, 1, 0, fl)

static void arm64math(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, const char *opchar, int negate, int sign, char flags) {
	cs_arm64_op dst = INSOP64 (0);
	int i, c = (OPCOUNT64 () > 2) ? 1 : 0;

	if (dst.vas) {
		int end = vas_count (dst.vas);
		for (i = 0; i < end; i++) {
			VECARG64_APPEND (&op->esil, c + 1, i, sign);
			if (negate) {
				r_strbuf_append (&op->esil, ",-1,^");
			}
			COMMA (&op->esil);
			VECARG64_APPEND (&op->esil, c, i, sign);
			r_strbuf_appendf (&op->esil, ",%s,", opchar);
			VEC64_DST_APPEND (&op->esil, 0, i);
			r_strbuf_append (&op->esil, ",=");
			if (i < end - 1) {
				COMMA (&op->esil);
			}
		}
	} else {
		if (flags) {
			const int bits = REGBITS64 (0);
			if (flags == 'l') {
				r_strbuf_append (&op->esil, "0,");
			}
			VECARG64_APPEND (&op->esil, c + 1, -1, sign);
			if (negate) {
				r_strbuf_append (&op->esil, ",-1,^");
			}
			if (flags == 'a') {
				// a - (-b) drives $c/$o through esil old/cur as an addition
				r_strbuf_append (&op->esil, ",-1,*");
			}
			COMMA (&op->esil);
			VECARG64_APPEND (&op->esil, c, -1, sign);
			switch (flags) {
			case 'a':
				r_strbuf_appendf (&op->esil, ",==,$z,zf,:=,%d,$s,nf,:=,%d,$c,cf,:=,%d,$o,vf,:=,", bits - 1, bits - 1, bits - 1);
				break;
			case 's':
				// $o after == is unsound for subtraction, V needs ((a^b)&(a^(a-b)))>>msb
				r_strbuf_appendf (&op->esil, ",==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,", bits - 1, bits, bits - 1);
				VECARG64_APPEND (&op->esil, c + 1, -1, sign);
				COMMA (&op->esil);
				VECARG64_APPEND (&op->esil, c, -1, sign);
				r_strbuf_append (&op->esil, ",^,");
				VECARG64_APPEND (&op->esil, c + 1, -1, sign);
				COMMA (&op->esil);
				VECARG64_APPEND (&op->esil, c, -1, sign);
				r_strbuf_append (&op->esil, ",-,");
				VECARG64_APPEND (&op->esil, c, -1, sign);
				r_strbuf_append (&op->esil, ",^,&,>>,vf,:=,");
				break;
			case 'l':
				// A64 flag-setting logical ops set NZ from the result and clear CV
				r_strbuf_appendf (&op->esil, ",%s,==,$z,zf,:=,%d,$s,nf,:=,0,cf,:=,0,vf,:=,", opchar, bits - 1);
				break;
			}
		}
		VECARG64_APPEND (&op->esil, c + 1, -1, sign);
		if (negate) {
			r_strbuf_append (&op->esil, ",-1,^");
		}
		COMMA (&op->esil);
		VECARG64_APPEND (&op->esil, c, -1, sign);
		r_strbuf_appendf (&op->esil, ",%s,", opchar);
		VEC64_DST_APPEND (&op->esil, 0, -1);
		r_strbuf_append (&op->esil, ",=");
	}
}

#define FPOPCALL(opchar) arm64fpmath(as, op, addr, buf, len, handle, insn, opchar, 0)
#define FPOPCALL_NEGATE(opchar) arm64fpmath(as, op, addr, buf, len, handle, insn, opchar, 1)

// floating point math instruction helper
static void arm64fpmath(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, const char *opchar, int negate) {
	int i, size = REGSIZE64 (1)*8;

	cs_arm64_op dst = INSOP64 (0);
	int start = -1;
	int end = 0;
	int convert = size == 64 ? 0 : 1;
	if (dst.vas) {
		start = 0;
		end = vas_count(dst.vas);
	}

	for (i = start; i < end; i++) {
		if (convert) {
			r_strbuf_appendf (&op->esil, "%d,DUP,", size);
		}
		VEC64_APPEND (&op->esil, 2, i);
		if (convert) {
			r_strbuf_append (&op->esil, ",F2D");
		}
		if (negate) {
			r_strbuf_append (&op->esil, ",-F");
		}
		if (convert) {
			r_strbuf_appendf (&op->esil, ",%d", size);
		}
		COMMA (&op->esil);
		VEC64_APPEND (&op->esil, 1, i);
		if (convert) {
			r_strbuf_appendf (&op->esil, ",F2D,F%s,D2F,", opchar);
		} else {
			r_strbuf_appendf (&op->esil, ",F%s,", opchar);
		}
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		if (i < end - 1) {
			COMMA (&op->esil);
		}
	}
}

// w0..w30 -> 0..30, wsp -> 31, anything else -> -1
static int arm64_wreg_bit(const char *tok, size_t len) {
	if (len == 3 && !memcmp (tok, "wsp", 3)) {
		return 31;
	}
	if (len < 2 || len > 3 || tok[0] != 'w' || !isdigit ((ut8)tok[1])) {
		return -1;
	}
	if (len == 3 && !isdigit ((ut8)tok[2])) {
		return -1;
	}
	int n = atoi (tok + 1);
	return n <= 30? n: -1;
}

// W writes zero-extend into X; the profile maps wN onto xN's low half only
static void arm64_esil_zext_wregs(RAnalOp *op) {
	const char *tok = r_strbuf_get (&op->esil);
	if (R_STR_ISEMPTY (tok)) {
		return;
	}
	ut32 regs = 0;
	const char *prev = NULL;
	size_t prevlen = 0;
	while (tok) {
		const char *end = strchr (tok, ',');
		size_t len = end? (size_t)(end - tok): strlen (tok);
		// '=' assigns; "==" "<=" ">=" compare and "=[N]" stores
		bool assign = len > 0 && tok[len - 1] == '='
			&& !(len == 2 && strchr ("=<>", tok[0]))
			&& !memchr (tok, '[', len);
		int bit = assign && prev? arm64_wreg_bit (prev, prevlen): -1;
		if (bit >= 0) {
			regs |= 1u << bit;
		}
		prev = tok;
		prevlen = len;
		tok = end? end + 1: NULL;
	}
	int n;
	for (n = 0; n < 31; n++) {
		if (regs & (1u << n)) {
			r_strbuf_appendf (&op->esil, ",w%d,x%d,=", n, n);
		}
	}
	if (regs & (1u << 31)) {
		r_strbuf_append (&op->esil, ",wsp,sp,=");
	}
}

// Narrow FP/SIMD writes clear the rest of the register; lane inserts preserve it.
static void arm64_esil_zext_vupper(RAnalOp *op, csh *handle, cs_insn *insn) {
	if (R_STR_ISEMPTY (r_strbuf_get (&op->esil))) {
		return;
	}
	int i;
	// The lane index of an indexed structure access applies to every
	// register in its list, so one indexed write operand means all the
	// vector writes of the instruction are lane inserts. These keep the
	// rest of their register and must not be zero-extended.
	for (i = 0; i < OPCOUNT64 (); i++) {
		cs_arm64_op o = INSOP64 (i);
		if (o.type == ARM64_OP_REG && (o.access & CS_AC_WRITE) && o.vector_index != -1) {
			return;
		}
	}
	for (i = 0; i < OPCOUNT64 (); i++) {
		cs_arm64_op dst = INSOP64 (i);
		const char *name;
		int bits, n;
		if (dst.type != ARM64_OP_REG || !(dst.access & CS_AC_WRITE) || dst.vector_index != -1) {
			continue;
		}
		name = cs_reg_name (*handle, dst.reg);
		if (!name || !strchr ("bhsdvq", name[0]) || !isdigit ((ut8)name[1])) {
			continue;
		}
		bits = dst.vas? vas_count (dst.vas) * vector_size (&dst): REGBITS64 (i);
		if (bits < 8 || bits >= 128) {
			continue;
		}
		n = atoi (name + 1);
		if (bits < 64) {
			r_strbuf_appendf (&op->esil, ",0x%"PFMT64x",v%dl,&=", bitmask_by_width[bits - 1], n);
		}
		r_strbuf_appendf (&op->esil, ",0,v%dh,=", n);
	}
}

#if CS_API_MAJOR > 4
static void arm64_subp_esil(RAnalOp *op, csh *handle, cs_insn *insn, bool flags, bool compare) {
	const int first = compare? 0: 1;
	char left[64], right[64];
	snprintf (left, sizeof (left), "56,%s,~", REG64 (first));
	snprintf (right, sizeof (right), "56,%s,~", REG64 (first + 1));
	if (flags) {
		r_strbuf_setf (&op->esil,
			"%s,%s,==,$z,zf,:=,63,$s,nf,:=,64,$b,!,cf,:=,"
			"63,%s,%s,^,%s,%s,-,%s,^,&,>>,vf,:=",
			right, left, right, left, right, left, left);
	}
	if (!compare && (arm64_reg)REGID64 (0) != ARM64_REG_XZR) {
		COMMA (&op->esil);
		r_strbuf_appendf (&op->esil, "%s,%s,-,%s,=", right, left, REG64 (0));
	}
}
#endif

// the system registers the profile states, by encoding (op0:op1:CRn:CRm:op2)
static const char *arm64_profile_sysreg(cs_insn *insn, int n) {
	cs_arm64_op *op = &insn->detail->arm64.operands[n];
#if CS_API_MAJOR < 6
	// capstone 5 builds differ: the bundled one tags these sys, others use the mrs/msr types
	ut32 enc;
	if (op->type == ARM64_OP_SYS) {
		enc = op->sys;
	} else if (op->type == ARM64_OP_REG_MRS || op->type == ARM64_OP_REG_MSR) {
		enc = op->reg;
	} else {
		return NULL;
	}
#else
	if (op->type != AARCH64_OP_SYSREG) {
		return NULL;
	}
	const ut32 enc = op->sysop.reg.sysreg;
#endif
	switch (enc) {
	case 0xde82: return "tpidr_el0";
	case 0xde83: return "tpidrro_el0";
	case 0xda10: return "nzcv";
	}
	return NULL;
}

// always-true conditions emit no opener, so only the taken arm is written
static void arm64_esil_cond_select(RAnalOp *op, const char *postfix, const char *taken, const char *other, const char *dst) {
	if (*postfix) {
		r_strbuf_appendf (&op->esil, "%s,}{,%s,},%s,=", taken, other, dst);
	} else {
		r_strbuf_appendf (&op->esil, "%s,%s,=", taken, dst);
	}
}

static const char *arm64_esil_cond_alt(int id) {
	switch (id) {
	case ARM64_INS_CINC:
	case ARM64_INS_CSINC:
		return "1,%s,+";
	case ARM64_INS_CINV:
	case ARM64_INS_CSINV:
		return "%s,-1,^";
	default:
		return "%s,0,-";
	}
}

// byte-reversal granularity for arm64_esil_rev_dword/arm64_esil_rev_vector
#define REV_GRAN_64 0
#define REV_GRAN_32 1
#define REV_GRAN_16 2

// reverse bytes of the 64-bit chunk src into dst, per whole chunk, word or halfword;
// the tmp staging lets src and dst alias (e.g. rev x0, x0)
static void arm64_esil_rev_dword(RStrBuf *sb, const char *src, const char *dst, int variant) {
	switch (variant) {
	case REV_GRAN_16:
		// REV16: swap bytes within each 16-bit halfword
		r_strbuf_appendf (sb,
			"8,0xff00ff00ff00ff00,%s,&,>>,tmp,=,"
			"8,0x00ff00ff00ff00ff,%s,&,<<,tmp,|=,tmp,%s,=",
			src, src, dst);
		break;
	case REV_GRAN_32:
		// REV32: reverse bytes within each 32-bit word
		r_strbuf_appendf (sb,
			"24,0x000000ff000000ff,%s,&,<<,tmp,=,"
			"16,0x000000ff000000ff,8,%s,>>,&,<<,tmp,|=,"
			"8,0x000000ff000000ff,16,%s,>>,&,<<,tmp,|=,"
			"0x000000ff000000ff,24,%s,>>,&,tmp,|=,tmp,%s,=",
			src, src, src, src, dst);
		break;
	default:
		// REV64: reverse bytes across the whole chunk
		r_strbuf_appendf (sb,
			"56,0xff,%s,&,<<,tmp,=,"
			"48,0xff,8,%s,>>,&,<<,tmp,|=,"
			"40,0xff,16,%s,>>,&,<<,tmp,|=,"
			"32,0xff,24,%s,>>,&,<<,tmp,|=,"
			"24,0xff,32,%s,>>,&,<<,tmp,|=,"
			"16,0xff,40,%s,>>,&,<<,tmp,|=,"
			"8,0xff,48,%s,>>,&,<<,tmp,|=,"
			"0xff,56,%s,>>,&,tmp,|=,tmp,%s,=",
			src, src, src, src, src, src, src, src, dst);
		break;
	}
}

// vector REV* act per container; a D-register destination zeroes the upper half
static void arm64_esil_rev_vector(RAnalOp *op, csh *handle, cs_insn *insn, int variant) {
	cs_arm64_op src = INSOP64 (1);
	const int halves = (vas_count (src.vas) * vector_size (&src) == 128)? 2: 1;
	const char *suffix[2] = { "l", "h" };
	int i;
	for (i = 0; i < halves; i++) {
		char src_name[24], dst_name[24];
		if (i > 0) {
			COMMA (&op->esil);
		}
		snprintf (src_name, sizeof (src_name), "%s%s", REG64 (1), suffix[i]);
		snprintf (dst_name, sizeof (dst_name), "%s%s", REG64 (0), suffix[i]);
		arm64_esil_rev_dword (&op->esil, src_name, dst_name, variant);
	}
}

// apply a per-lane unary op over each vas lane of src into dst; scale is the
// fixed-point fraction bits of the scvtf/ucvtf/fcvtzs/fcvtzu #imm forms
static void arm64_esil_vec_unary(RAnalOp *op, csh *handle, cs_insn *insn, int scale) {
	cs_arm64_op src = INSOP64 (1);
	int lanes = vas_count (src.vas), lane_bits = vector_size (&src);
	int i;
	for (i = 0; i < lanes; i++) {
		if (i > 0) {
			COMMA (&op->esil);
		}
		switch (insn->id) {
		case ARM64_INS_CNT:
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",POPCNT,");
			break;
		case ARM64_INS_CLS:
			// flip the lane when its sign bit is set, then count the leading
			// zeros of the low lane_bits-1 bits (the sign bit itself excluded)
			r_strbuf_appendf (&op->esil, "%d,%d,", lane_bits - 1, lane_bits - 1);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",>>,1,&,0,-,");
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_appendf (&op->esil, ",^,0x%" PFMT64x ",&,CLZ,",
				bitmask_by_width[lane_bits - 2]);
			break;
		case ARM64_INS_CLZ:
			r_strbuf_appendf (&op->esil, "%d,", lane_bits);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",CLZ,");
			break;
		case ARM64_INS_SCVTF:
			// sign-extend the lane, then scale by 2^-scale for the
			// fixed-point form before converting the integer to fp
			r_strbuf_appendf (&op->esil, "%d,%d,", lane_bits, lane_bits);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",~,I2D,");
			if (scale) {
				r_strbuf_appendf (&op->esil, "0x%" PFMT64x ",I2D,SWAP,F/,", (ut64)1 << scale);
			}
			r_strbuf_append (&op->esil, "D2F,");
			break;
		case ARM64_INS_UCVTF:
			r_strbuf_appendf (&op->esil, "%d,", lane_bits);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",U2D,");
			if (scale) {
				r_strbuf_appendf (&op->esil, "0x%" PFMT64x ",I2D,SWAP,F/,", (ut64)1 << scale);
			}
			r_strbuf_append (&op->esil, "D2F,");
			break;
		case ARM64_INS_FCVTZS:
		case ARM64_INS_FCVTZU:
			// D2I truncates toward zero like the Z forms; the fixed-point
			// form scales the double before the truncation
			r_strbuf_appendf (&op->esil, "%d,", lane_bits);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",F2D,");
			if (scale) {
				r_strbuf_appendf (&op->esil, "0x%" PFMT64x ",I2D,F*,", (ut64)1 << scale);
			}
			r_strbuf_append (&op->esil, "D2I,");
			break;
		case ARM64_INS_FRINTN:
		case ARM64_INS_FRINTI:
		case ARM64_INS_FRINTX:
		case ARM64_INS_FRINTA:
		case ARM64_INS_FRINTP:
		case ARM64_INS_FRINTM:
		{
			const char *rounder = (insn->id == ARM64_INS_FRINTA ||
				insn->id == ARM64_INS_FRINTP)? "CEIL":
				insn->id == ARM64_INS_FRINTM? "FLOOR": "ROUND";
			r_strbuf_appendf (&op->esil, "%d,DUP,", lane_bits);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_appendf (&op->esil, ",F2D,%s,D2F,", rounder);
			break;
		}
		case ARM64_INS_FRINTZ:
			// toward zero: ceil when negative, floor otherwise
			r_strbuf_appendf (&op->esil, "%d,DUP,", lane_bits);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",F2D,DUP,0,I2D,SWAP,F<,?{,CEIL,}{,FLOOR,},D2F,");
			break;
		case ARM64_INS_FABS:
			// mask off the lane sign bit, no fp roundtrip needed
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_appendf (&op->esil, ",0x%" PFMT64x ",&,",
				(ut64)(bitmask_by_width[lane_bits - 1] & ~(1ULL << (lane_bits - 1))));
			break;
		case ARM64_INS_FNEG:
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_appendf (&op->esil, ",0x%" PFMT64x ",^,", (ut64)(1ULL << (lane_bits - 1)));
			break;
		case ARM64_INS_RBIT:
		{
			int s;
			// xor-shift conditional bit swaps, one stage per bit position;
			// the running lane value lives in tmp so every subexpression
			// stays within 64 bits
			static const ut64 swap_masks[] = {
				0x5555555555555555ULL, 0x3333333333333333ULL, 0x0F0F0F0F0F0F0F0FULL,
				0x00FF00FF00FF00FFULL, 0x0000FFFF0000FFFFULL, 0x00000000FFFFFFFFULL
			};
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",tmp,=");
			for (s = 0; (1 << s) < lane_bits; s++) {
				r_strbuf_appendf (&op->esil,
					",%d,tmp,>>,tmp,^,0x%" PFMT64x ",&,DUP,%d,SWAP,<<,tmp,^,^,tmp,=",
					1 << s, swap_masks[s], 1 << s);
			}
			r_strbuf_append (&op->esil, ",tmp,");
			break;
		}
		}
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
	}
}

// zero-compare forms: every lane becomes all-ones or all-zeros by the
// predicate against zero; fp16 lanes are left unemulated by the caller
static void arm64_esil_vec_cmpzero(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op src = INSOP64 (1);
	// scalar simd&fp forms act on the s/d register view with one lane
	bool vector = is_vector_op (&src);
	int lanes = vector? vas_count (src.vas): 1;
	int esize = vector? vector_size (&src): REGSIZE64 (1) * 8;
	int up = 64 - esize;
	int i;
	for (i = 0; i < lanes; i++) {
		if (i > 0) {
			COMMA (&op->esil);
		}
		switch (insn->id) {
		case ARM64_INS_FCMGT:
		case ARM64_INS_FCMGE:
			// 0 < v and 0 <= v with the VM's NaN-quiet FP compares
			r_strbuf_appendf (&op->esil, "%d,", esize);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",F2D,0,I2D,");
			r_strbuf_append (&op->esil,
				insn->id == ARM64_INS_FCMGT? "F<,": "F<=,");
			break;
		case ARM64_INS_FCMLT:
		case ARM64_INS_FCMLE:
			// SWAP brings the value to the top so it becomes the first
			// operand of the compare against 0
			r_strbuf_appendf (&op->esil, "%d,", esize);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",F2D,0,I2D,SWAP,");
			r_strbuf_append (&op->esil,
				insn->id == ARM64_INS_FCMLT? "F<,": "F<=,");
			break;
		case ARM64_INS_FCMEQ:
			r_strbuf_appendf (&op->esil, "%d,", esize);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",F2D,0,I2D,F==,");
			break;
		case ARM64_INS_CMEQ:
			// ! (esil_neg) is the equality predicate against zero
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",!,");
			break;
		case ARM64_INS_CMGT:
			r_strbuf_append (&op->esil, "0,");
			r_strbuf_appendf (&op->esil, "%d,%d,", up, up);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",<<,ASR,>,");
			break;
		case ARM64_INS_CMGE:
			r_strbuf_append (&op->esil, "0,");
			r_strbuf_appendf (&op->esil, "%d,%d,", up, up);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",<<,ASR,<,!,");
			break;
		case ARM64_INS_CMLE:
			r_strbuf_append (&op->esil, "0,");
			r_strbuf_appendf (&op->esil, "%d,%d,", up, up);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",<<,ASR,>,!,");
			break;
		case ARM64_INS_CMLT:
			r_strbuf_append (&op->esil, "0,");
			r_strbuf_appendf (&op->esil, "%d,%d,", up, up);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",<<,ASR,<,");
			break;
		default:
			break;
		}
		// negate the 0/1 predicate so true lanes become the all-ones mask;
		// the dst append then truncates it to the lane width
		r_strbuf_append (&op->esil, "0,-,");
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
	}
}

// register forms of the compares: every lane becomes all-ones or all-zeros
// by the predicate between the two source lanes; fp16 lanes are left
// unemulated by the caller and the fp forms also cover the scalar s/d views
static void arm64_esil_vec_cmpreg(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op src = INSOP64 (1);
	bool vector = is_vector_op (&src);
	int lanes = vector? vas_count (src.vas): 1, esize = vector? vector_size (&src): REGSIZE64 (1) * 8;
	int up = 64 - esize;
	ut64 signbit = 1ULL << (esize - 1);
	int i;
	for (i = 0; i < lanes; i++) {
		RStrBuf lane_a, lane_b;
		const char *a, *b;
		if (i > 0) {
			COMMA (&op->esil);
		}
		r_strbuf_init (&lane_a);
		r_strbuf_init (&lane_b);
		VECARG64_APPEND (&lane_a, 1, i, 0);
		VECARG64_APPEND (&lane_b, 2, i, 0);
		a = r_strbuf_get (&lane_a);
		b = r_strbuf_get (&lane_b);
		switch (insn->id) {
		case ARM64_INS_CMEQ:
			// xor then the zero test stands in for integer equality
			r_strbuf_appendf (&op->esil, "%s,%s,^,!,", a, b);
			break;
		case ARM64_INS_CMGE:
			r_strbuf_appendf (&op->esil,
				"%d,%d,%s,<<,ASR,%d,%d,%s,<<,ASR,<,!,", up, up, b, up, up, a);
			break;
		case ARM64_INS_CMGT:
			r_strbuf_appendf (&op->esil,
				"%d,%d,%s,<<,ASR,%d,%d,%s,<<,ASR,<,", up, up, a, up, up, b);
			break;
		case ARM64_INS_CMHI:
			// flipping the sign bit and re-reading the lane as a signed
			// value orders the lanes correctly for the VM's signed compare
			r_strbuf_appendf (&op->esil,
				"%d,%d,0x%" PFMT64x ",%s,^,<<,ASR,%d,%d,0x%" PFMT64x ",%s,^,<<,ASR,>,",
				up, up, signbit, b, up, up, signbit, a);
			break;
		case ARM64_INS_CMHS:
			r_strbuf_appendf (&op->esil,
				"%d,%d,0x%" PFMT64x ",%s,^,<<,ASR,%d,%d,0x%" PFMT64x ",%s,^,<<,ASR,<,!,",
				up, up, signbit, b, up, up, signbit, a);
			break;
		case ARM64_INS_CMTST:
			r_strbuf_appendf (&op->esil, "%s,%s,&,!,!,", a, b);
			break;
		case ARM64_INS_FCMEQ:
			r_strbuf_appendf (&op->esil, "%d,%s,F2D,%d,%s,F2D,F==,", esize, a, esize, b);
			break;
		case ARM64_INS_FCMGE:
			// b <= a ordered, matching a >= b
			r_strbuf_appendf (&op->esil, "%d,%s,F2D,%d,%s,F2D,F<=,", esize, a, esize, b);
			break;
		case ARM64_INS_FCMGT:
			r_strbuf_appendf (&op->esil, "%d,%s,F2D,%d,%s,F2D,F<,", esize, a, esize, b);
			break;
		default:
			break;
		}
		// negate the 0/1 predicate so true lanes become the all-ones mask;
		// the dst append then truncates it to the lane width
		r_strbuf_append (&op->esil, "0,-,");
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&lane_a);
		r_strbuf_fini (&lane_b);
	}
}

// value expression implementing FPProcessNaNs for the lane bit strings a
// and b: a signaling NaN wins with its payload quieted by the quiet bit,
// otherwise the first quiet NaN operand keeps its bits; aneg negates operand
// a first, as the fused reciprocal steps do before processing NaNs
static void arm64_esil_fp_propnans(RStrBuf *out, int esize, const char *a, const char *b,
	bool aneg) {
	const ut64 nanc = (esize == 32)? 0x7fc00000ULL: 0x7ff8000000000000ULL;
	const ut64 qbit = (esize == 32)? 0x00400000ULL: 0x0008000000000000ULL;
	const ut64 signlane = 1ULL << (esize - 1);
	RStrBuf nan_a, nan_b, qnan_a, qnan_b, snan_a, snan_b, a_quieted, a_value;
	const char *is_nan_a, *is_nan_b, *is_qnan_a, *is_qnan_b, *is_snan_a, *is_snan_b;
	const char *a_quiet, *a_bits;
	r_strbuf_init (&nan_a);
	r_strbuf_init (&nan_b);
	r_strbuf_init (&qnan_a);
	r_strbuf_init (&qnan_b);
	r_strbuf_init (&snan_a);
	r_strbuf_init (&snan_b);
	r_strbuf_init (&a_quieted);
	r_strbuf_init (&a_value);
	r_strbuf_setf (&nan_a, "%d,%s,F2D,DUP,F==,!", esize, a);
	r_strbuf_setf (&nan_b, "%d,%s,F2D,DUP,F==,!", esize, b);
	is_nan_a = r_strbuf_get (&nan_a);
	is_nan_b = r_strbuf_get (&nan_b);
	r_strbuf_setf (&qnan_a, "%s,0x%" PFMT64x ",%s,&,!,!,&", is_nan_a, qbit, a);
	r_strbuf_setf (&qnan_b, "%s,0x%" PFMT64x ",%s,&,!,!,&", is_nan_b, qbit, b);
	is_qnan_a = r_strbuf_get (&qnan_a);
	is_qnan_b = r_strbuf_get (&qnan_b);
	r_strbuf_setf (&snan_a, "%s,%s,-", is_nan_a, is_qnan_a);
	r_strbuf_setf (&snan_b, "%s,%s,-", is_nan_b, is_qnan_b);
	is_snan_a = r_strbuf_get (&snan_a);
	is_snan_b = r_strbuf_get (&snan_b);
	if (aneg) {
		r_strbuf_setf (&a_quieted, "%s,0x%" PFMT64x ",^,0x%" PFMT64x ",|", a, signlane, qbit);
		r_strbuf_setf (&a_value, "%s,0x%" PFMT64x ",^", a, signlane);
	} else {
		r_strbuf_setf (&a_quieted, "%s,0x%" PFMT64x ",|", a, qbit);
		r_strbuf_setf (&a_value, "%s", a);
	}
	a_quiet = r_strbuf_get (&a_quieted);
	a_bits = r_strbuf_get (&a_value);
	r_strbuf_setf (out, "%s,?{,%s,}{,%s,?{,%s,0x%" PFMT64x ",|,}{,%s,?{,%s,}{,%s,?{,%s,"
		"}{,0x%" PFMT64x ",},},},},", is_snan_a, a_quiet, is_snan_b, b, qbit, is_qnan_a,
		a_bits, is_qnan_b, b, nanc);
	r_strbuf_fini (&nan_a);
	r_strbuf_fini (&nan_b);
	r_strbuf_fini (&qnan_a);
	r_strbuf_fini (&qnan_b);
	r_strbuf_fini (&snan_a);
	r_strbuf_fini (&snan_b);
	r_strbuf_fini (&a_quieted);
	r_strbuf_fini (&a_value);
}


// close a value still held as double bits into an esize lane value; the VM
// turns FP overflow into a NaN so callers whose overflow must saturate pass
// the 0/1 expression carrying the lost sign and NaN becomes signed infinity
static void arm64_esil_f2lane(RStrBuf *out, int esize, const char *d, const char *sgn) {
	const bool wide = esize == 64;
	const ut64 infbits = wide? 0x7ff0000000000000ULL: 0x7f800000ULL;
	const ut64 nanc = wide? 0x7ff8000000000000ULL: 0x7fc00000ULL, msbval = 1ULL << (esize - 1);
	RStrBuf nan_value;
	r_strbuf_init (&nan_value);
	if (sgn) {
		r_strbuf_setf (&nan_value, "%s,0x%" PFMT64x ",*,0x%" PFMT64x ",|", sgn, msbval, infbits);
	} else {
		r_strbuf_setf (&nan_value, "0x%" PFMT64x, nanc);
	}
	if (wide) {
		r_strbuf_setf (out, "%s,0x7ff0000000000000,&,0x7ff0000000000000,-,!,!,?{,64,%s,D2F,}{,%s,DUP,F==,!,?{,%s,}{,%s,0x8000000000000000,&,0x7ff0000000000000,|,},},",
			d, d, d, r_strbuf_get (&nan_value), d);
	} else {
		r_strbuf_setf (out, "%s,0x7ff0000000000000,&,0x7ff0000000000000,-,!,!,?{,32,%s,D2F,}{,%s,DUP,F==,!,?{,%s,}{,32,%s,0x8000000000000000,&,>>,0x7f800000,|,},},",
			d, d, d, r_strbuf_get (&nan_value), d);
	}
	r_strbuf_fini (&nan_value);
}

// value expression for FPMin/FPMax of the lane bit strings a and b, or
// the FPMinNum/FPMaxNum variant selected by num; shared by the lane-wise
// minmax and the across-vector FP reductions
static void arm64_esil_minmax_expr(RStrBuf *out, int esize, bool ismax, bool num, const char *a, const char *b) {
	const ut64 nanc = (esize == 32)? 0x7fc00000ULL: 0x7ff8000000000000ULL;
	const ut64 qbit = (esize == 32)? 0x00400000ULL: 0x0008000000000000ULL;
	const ut64 zmask = (1ULL << (esize - 1)) - 1; // magnitude bits of a lane
	RStrBuf nan_a, nan_b, qnan_a, qnan_b, snan_a, snan_b, quiet_a, quiet_b, propagate, num_nan,
		pick, normalize;
	const char *is_nan_a, *is_nan_b, *is_qnan_a, *is_qnan_b, *is_snan_a, *is_snan_b,
		*a_quieted, *b_quieted, *propagated;
	const char *nanbody, *picked, *normal;
	r_strbuf_init (&nan_a);
	r_strbuf_init (&nan_b);
	r_strbuf_init (&qnan_a);
	r_strbuf_init (&qnan_b);
	r_strbuf_init (&snan_a);
	r_strbuf_init (&snan_b);
	r_strbuf_init (&quiet_a);
	r_strbuf_init (&quiet_b);
	r_strbuf_init (&propagate);
	r_strbuf_init (&num_nan);
	r_strbuf_init (&pick);
	r_strbuf_init (&normalize);
	// 0/1 expressions for the NaN-ness and quiet-NaN-ness of a lane
	r_strbuf_appendf (&nan_a, "%d,%s,F2D,DUP,F==,!", esize, a);
	r_strbuf_appendf (&nan_b, "%d,%s,F2D,DUP,F==,!", esize, b);
	is_nan_a = r_strbuf_get (&nan_a);
	is_nan_b = r_strbuf_get (&nan_b);
	r_strbuf_appendf (&qnan_a, "%s,0x%" PFMT64x ",%s,&,!,!,&", is_nan_a, qbit, a);
	r_strbuf_appendf (&qnan_b, "%s,0x%" PFMT64x ",%s,&,!,!,&", is_nan_b, qbit, b);
	is_qnan_a = r_strbuf_get (&qnan_a);
	is_qnan_b = r_strbuf_get (&qnan_b);
	r_strbuf_appendf (&snan_a, "%s,%s,-", is_nan_a, is_qnan_a);
	r_strbuf_appendf (&snan_b, "%s,%s,-", is_nan_b, is_qnan_b);
	is_snan_a = r_strbuf_get (&snan_a);
	is_snan_b = r_strbuf_get (&snan_b);
	r_strbuf_appendf (&quiet_a, "%s,0x%" PFMT64x ",|", a, qbit);
	r_strbuf_appendf (&quiet_b, "%s,0x%" PFMT64x ",|", b, qbit);
	a_quieted = r_strbuf_get (&quiet_a);
	b_quieted = r_strbuf_get (&quiet_b);
	// FPProcessNaNs: the first signaling NaN wins quieted by the quiet bit,
	// else the first quiet NaN operand keeps its payload bits
	r_strbuf_appendf (&propagate, "%s,?{,%s,}{,%s,?{,%s,}{,%s,?{,%s,}{,%s,?{,%s,"
		"}{,0x%" PFMT64x ",},},},},", is_snan_a, a_quieted, is_snan_b, b_quieted, is_qnan_a,
		a, is_qnan_b, b, nanc);
	propagated = r_strbuf_get (&propagate);
	nanbody = propagated;
	if (num) {
		// FPMinNum and FPMaxNum replace a lone quiet NaN with an infinity so
		// it loses to the other operand; two NaN lanes keep the first
		// signaling NaN quieted or operand 1's payload
		r_strbuf_appendf (&num_nan, "%s,%s,!,&,?{,%s,?{,%s,}{,%s,},}{,%s,%s,!,&,?{,%s,"
			"?{,%s,}{,%s,},}{,%s,?{,%s,}{,%s,},},},", is_qnan_a, is_qnan_b, is_nan_b, b_quieted, b,
			is_qnan_b, is_qnan_a, is_nan_a, a_quieted, a, is_nan_a, a_quieted, b_quieted);
		nanbody = r_strbuf_get (&num_nan);
	}
	// numeric selection by the ordered FP compare; equal lanes take
	// operand 2 as FPMin and FPMax do
	r_strbuf_appendf (&pick, "%d,%s,F2D,%d,%s,F2D,F<,?{,%s,}{,%s,},",
		esize, ismax? a: b, esize, ismax? b: a, a, b);
	picked = r_strbuf_get (&pick);
	// both lanes zero: FPMin keeps the sign present in either operand,
	// FPMax keeps the sign shared by both, so +/-0 pairs become -0 and
	// +0 respectively
	r_strbuf_appendf (&normalize, "0x%" PFMT64x ",%s,&,!,0x%" PFMT64x ",%s,&,!,&,?{,",
		zmask, a, zmask, b);
	if (ismax) {
		r_strbuf_appendf (&normalize, "%s,%s,&,}{,%s,},", a, b, picked);
	} else {
		r_strbuf_appendf (&normalize, "%s,%s,|,}{,%s,},", a, b, picked);
	}
	normal = r_strbuf_get (&normalize);
	r_strbuf_setf (out, "%s,%s,|,?{,%s,}{,%s,},", is_nan_a, is_nan_b, nanbody, normal);
	r_strbuf_fini (&nan_a);
	r_strbuf_fini (&nan_b);
	r_strbuf_fini (&qnan_a);
	r_strbuf_fini (&qnan_b);
	r_strbuf_fini (&quiet_a);
	r_strbuf_fini (&quiet_b);
	r_strbuf_fini (&propagate);
	r_strbuf_fini (&num_nan);
	r_strbuf_fini (&pick);
	r_strbuf_fini (&normalize);
}

// fmin/fmax/fminnm/fmaxnm per lane; the selection keeps the raw bits of the
// chosen operand so the NaN payloads and the signed-zero sign forced by the
// ISA survive without a float round-trip
static void arm64_esil_vec_minmax(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op src = INSOP64 (1);
	bool vector = is_vector_op (&src), ismax = false, num = false;
	int lanes = vector? vas_count (src.vas): 1, esize = vector? vector_size (&src): REGSIZE64 (1) * 8;
	int i;
	switch (insn->id) {
	case ARM64_INS_FMAX:
		ismax = true;
		break;
	case ARM64_INS_FMINNM:
		num = true;
		break;
	case ARM64_INS_FMAXNM:
		ismax = true;
		num = true;
		break;
	default:
		break;
	}
	for (i = 0; i < lanes; i++) {
		RStrBuf lane_a, lane_b, combined;
		if (i > 0) {
			COMMA (&op->esil);
		}
		r_strbuf_init (&lane_a);
		r_strbuf_init (&lane_b);
		r_strbuf_init (&combined);
		VECARG64_APPEND (&lane_a, 1, i, 0);
		VECARG64_APPEND (&lane_b, 2, i, 0);
		arm64_esil_minmax_expr (&combined, esize, ismax, num, r_strbuf_get (&lane_a), r_strbuf_get (&lane_b));
		r_strbuf_append (&op->esil, r_strbuf_get (&combined));
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&lane_a);
		r_strbuf_fini (&lane_b);
		r_strbuf_fini (&combined);
	}
}

// value expression for FPProcessNaN of a single lane a: the payload survives
// and a signaling NaN is quieted by its quiet bit, the default NaN appearing
// only when FPCR.DN selects it
static void arm64_esil_fp_procnan(RStrBuf *out, int esize, const char *a) {
	const ut64 qbit = (esize == 32)? 0x00400000ULL: 0x0008000000000000ULL;
	r_strbuf_setf (out, "%s,0x%" PFMT64x ",|", a, qbit);
}

// fmla/fmls per lane over the destination accumulator; the product and the
// add round separately, matching the existing scalar FMADD ESIL, while the
// NaN and infinity classes follow FPMulAdd and FPProcessNaNs3
static void arm64_esil_vec_fmac(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op dst, src, src2;
	bool element, sub;
	ut64 signlane, qbit, nanc;
	int esize, lanes, i;
	if (OPCOUNT64 () != 3 || !ISREG64 (0) || !ISREG64 (1) || !ISREG64 (2)) {
		return;
	}
	dst = INSOP64 (0);
	src = INSOP64 (1);
	src2 = INSOP64 (2);
	if (!is_vector_op (&dst) || !is_vector_op (&src)) {
		return;
	}
	esize = vector_size (&dst);
	lanes = vas_count (dst.vas);
	if ((esize != 32 && esize != 64) || vector_size (&src) != esize || vas_count (src.vas) != lanes) {
		return;
	}
	element = src2.vector_index != -1;
	if (element) {
		if (!is_vector_op (&src2) && esize != 64) {
			return;
		}
	} else if (!is_vector_op (&src2) || vector_size (&src2) != esize || vas_count (src2.vas) != lanes) {
		return;
	}
	signlane = 1ULL << (esize - 1);
	qbit = (esize == 32)? 0x00400000ULL: 0x0008000000000000ULL;
	nanc = (esize == 32)? 0x7fc00000ULL: 0x7ff8000000000000ULL;
	sub = insn->id == ARM64_INS_FMLS;
	for (i = 0; i < lanes; i++) {
		RStrBuf lane_a, lane_b, lane_acc, fma_value, lane, sign, sab, prod, closed, nan3, nanbody,
			invpair, infp, signneq, nan_a, nan_b, nan_c, qnan_a, qnan_b, qnan_c, snan_a, snan_b,
			snan_c, zero_a, zero_b, inf_a, inf_b, inf_c, ac_q, b_q, a_flip, a_flip_q;
		const char *a, *b, *ac, *is_nan_a, *is_nan_b, *is_nan_c, *is_qnan_a, *is_qnan_b,
			*is_qnan_c, *is_snan_a, *is_snan_b, *is_snan_c, *is_zero_a, *is_zero_b, *is_inf_a,
			*is_inf_b, *is_inf_c;
		r_strbuf_init (&lane_a);
		r_strbuf_init (&lane_b);
		r_strbuf_init (&lane_acc);
		r_strbuf_init (&fma_value);
		r_strbuf_init (&lane);
		r_strbuf_init (&sign);
		r_strbuf_init (&sab);
		r_strbuf_init (&prod);
		r_strbuf_init (&closed);
		r_strbuf_init (&nan3);
		r_strbuf_init (&nanbody);
		r_strbuf_init (&invpair);
		r_strbuf_init (&infp);
		r_strbuf_init (&signneq);
		r_strbuf_init (&nan_a);
		r_strbuf_init (&nan_b);
		r_strbuf_init (&nan_c);
		r_strbuf_init (&qnan_a);
		r_strbuf_init (&qnan_b);
		r_strbuf_init (&qnan_c);
		r_strbuf_init (&snan_a);
		r_strbuf_init (&snan_b);
		r_strbuf_init (&snan_c);
		r_strbuf_init (&zero_a);
		r_strbuf_init (&zero_b);
		r_strbuf_init (&inf_a);
		r_strbuf_init (&inf_b);
		r_strbuf_init (&inf_c);
		r_strbuf_init (&ac_q);
		r_strbuf_init (&b_q);
		r_strbuf_init (&a_flip);
		r_strbuf_init (&a_flip_q);
		if (i > 0) {
			COMMA (&op->esil);
		}
		VECARG64_APPEND (&lane_a, 1, i, 0);
		if (element && !is_vector_op (&src2)) {
			// bare .D[index] forms carry no arrangement
			const char *rn = cs_reg_name (*handle, src2.reg);
			r_strbuf_setf (&lane_b, "%s%s", rn, src2.vector_index? "h": "l");
		} else {
			VECARG64_APPEND (&lane_b, 2, i, 0);
		}
		VECARG64_APPEND (&lane_acc, 0, i, 0);
		a = r_strbuf_get (&lane_a);
		b = r_strbuf_get (&lane_b);
		ac = r_strbuf_get (&lane_acc);
		// product sign, negated for fmls where operand 1 enters FPMulAdd negated
		r_strbuf_setf (&sab, "%s,0x%" PFMT64x ",&,%s,0x%" PFMT64x ",&,^", a, signlane, b, signlane);
		if (sub) {
			r_strbuf_appendf (&sab, ",0x%" PFMT64x ",^", signlane);
		}
		r_strbuf_setf (&sign, "%s,?{,1,}{,0,},", r_strbuf_get (&sab));
		// 0/1 classification expressions for the three operands
		r_strbuf_setf (&nan_a, "%d,%s,F2D,DUP,F==,!", esize, a);
		r_strbuf_setf (&nan_b, "%d,%s,F2D,DUP,F==,!", esize, b);
		r_strbuf_setf (&nan_c, "%d,%s,F2D,DUP,F==,!", esize, ac);
		is_nan_a = r_strbuf_get (&nan_a);
		is_nan_b = r_strbuf_get (&nan_b);
		is_nan_c = r_strbuf_get (&nan_c);
		r_strbuf_setf (&qnan_a, "%s,0x%" PFMT64x ",%s,&,!,!,&", is_nan_a, qbit, a);
		r_strbuf_setf (&qnan_b, "%s,0x%" PFMT64x ",%s,&,!,!,&", is_nan_b, qbit, b);
		r_strbuf_setf (&qnan_c, "%s,0x%" PFMT64x ",%s,&,!,!,&", is_nan_c, qbit, ac);
		is_qnan_a = r_strbuf_get (&qnan_a);
		is_qnan_b = r_strbuf_get (&qnan_b);
		is_qnan_c = r_strbuf_get (&qnan_c);
		r_strbuf_setf (&snan_a, "%s,%s,-", is_nan_a, is_qnan_a);
		r_strbuf_setf (&snan_b, "%s,%s,-", is_nan_b, is_qnan_b);
		r_strbuf_setf (&snan_c, "%s,%s,-", is_nan_c, is_qnan_c);
		is_snan_a = r_strbuf_get (&snan_a);
		is_snan_b = r_strbuf_get (&snan_b);
		is_snan_c = r_strbuf_get (&snan_c);
		r_strbuf_setf (&zero_a, "%d,%s,F2D,0x7fffffffffffffff,&,0,-,!", esize, a);
		r_strbuf_setf (&zero_b, "%d,%s,F2D,0x7fffffffffffffff,&,0,-,!", esize, b);
		is_zero_a = r_strbuf_get (&zero_a);
		is_zero_b = r_strbuf_get (&zero_b);
		r_strbuf_setf (&inf_a, "%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!", esize, a);
		r_strbuf_setf (&inf_b, "%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!", esize, b);
		r_strbuf_setf (&inf_c, "%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!", esize, ac);
		is_inf_a = r_strbuf_get (&inf_a);
		is_inf_b = r_strbuf_get (&inf_b);
		is_inf_c = r_strbuf_get (&inf_c);
		r_strbuf_setf (&invpair, "%s,%s,&,%s,%s,&,|", is_inf_a, is_zero_b, is_zero_a, is_inf_b);
		r_strbuf_setf (&infp, "%s,%s,|", is_inf_a, is_inf_b);
		r_strbuf_setf (&signneq, "%s,%s,0x%" PFMT64x ",&,^,0,-,!,!,", r_strbuf_get (&sab), ac, signlane);
		r_strbuf_setf (&ac_q, "%s,0x%" PFMT64x ",|", ac, qbit);
		r_strbuf_setf (&b_q, "%s,0x%" PFMT64x ",|", b, qbit);
		if (sub) {
			r_strbuf_setf (&a_flip, "%s,0x%" PFMT64x ",^", a, signlane);
		} else {
			r_strbuf_setf (&a_flip, "%s", a);
		}
		r_strbuf_setf (&a_flip_q, "%s,0x%" PFMT64x ",|", r_strbuf_get (&a_flip), qbit);
		// the product in double bits; a NaN in tmp is a double-domain overflow
		r_strbuf_setf (&prod, "%d,%s,F2D,%d,%s,F2D,F*", esize, a, esize, b);
		if (sub) {
			r_strbuf_append (&prod, ",-F");
		}
		r_strbuf_setf (&fma_value, "tmp,%d,%s,F2D,F+", esize, ac);
		arm64_esil_f2lane (&closed, esize, r_strbuf_get (&fma_value), r_strbuf_get (&sign));
		// FPProcessNaNs3 over addend, operand 1 and operand 2: the first
		// signaling NaN wins quieted, else the first quiet NaN with the
		// addend ahead, an invalid (inf, 0) product overriding the addend
		r_strbuf_setf (&nan3, "%s,%s,|,%s,|", is_nan_a, is_nan_b, is_nan_c);
		r_strbuf_setf (&nanbody, "%s,?{,%s,}{,", is_snan_c, r_strbuf_get (&ac_q));
		r_strbuf_appendf (&nanbody, "%s,?{,%s,}{,", is_snan_a, r_strbuf_get (&a_flip_q));
		r_strbuf_appendf (&nanbody, "%s,?{,%s,}{,", is_snan_b, r_strbuf_get (&b_q));
		r_strbuf_appendf (&nanbody, "%s,?{,%s,?{,0x%" PFMT64x ",}{,%s,},}{,", is_qnan_c,
			r_strbuf_get (&invpair), nanc, ac);
		r_strbuf_appendf (&nanbody, "%s,?{,%s,}{,%s,?{,%s,}{,0x%" PFMT64x ",},},},},},}",
			is_qnan_a, r_strbuf_get (&a_flip), is_qnan_b, b, nanc);
		// non-NaN lanes: zero times infinity and opposite-signed infinite
		// sums are invalid, an overflowed product becomes a signed infinity
		r_strbuf_setf (&lane, "%s,?{,%s,}{,", r_strbuf_get (&nan3), r_strbuf_get (&nanbody));
		r_strbuf_appendf (&lane, "%s,?{,0x%" PFMT64x ",}{,", r_strbuf_get (&invpair), nanc);
		r_strbuf_appendf (&lane, "%s,%s,&,%s,&,?{,0x%" PFMT64x ",}{,", r_strbuf_get (&infp),
			is_inf_c, r_strbuf_get (&signneq), nanc);
		r_strbuf_appendf (&lane, "%s,tmp,=,tmp,DUP,F==,!,%s,&,%s,&,?{,0x%" PFMT64x ",}{,",
			r_strbuf_get (&prod), is_inf_c, r_strbuf_get (&signneq), nanc);
		r_strbuf_append (&lane, r_strbuf_get (&closed));
		r_strbuf_append (&lane, ",},},},},");
		r_strbuf_append (&op->esil, r_strbuf_get (&lane));
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&lane_a);
		r_strbuf_fini (&lane_b);
		r_strbuf_fini (&lane_acc);
		r_strbuf_fini (&fma_value);
		r_strbuf_fini (&lane);
		r_strbuf_fini (&sign);
		r_strbuf_fini (&sab);
		r_strbuf_fini (&prod);
		r_strbuf_fini (&closed);
		r_strbuf_fini (&nan3);
		r_strbuf_fini (&nanbody);
		r_strbuf_fini (&invpair);
		r_strbuf_fini (&infp);
		r_strbuf_fini (&signneq);
		r_strbuf_fini (&nan_a);
		r_strbuf_fini (&nan_b);
		r_strbuf_fini (&nan_c);
		r_strbuf_fini (&qnan_a);
		r_strbuf_fini (&qnan_b);
		r_strbuf_fini (&qnan_c);
		r_strbuf_fini (&snan_a);
		r_strbuf_fini (&snan_b);
		r_strbuf_fini (&snan_c);
		r_strbuf_fini (&zero_a);
		r_strbuf_fini (&zero_b);
		r_strbuf_fini (&inf_a);
		r_strbuf_fini (&inf_b);
		r_strbuf_fini (&inf_c);
		r_strbuf_fini (&ac_q);
		r_strbuf_fini (&b_q);
		r_strbuf_fini (&a_flip);
		r_strbuf_fini (&a_flip_q);
	}
}


// fmaxp/fminp/fmaxnmp/fminnmp pairwise over the operand2::operand1 concatenation
static void arm64_esil_vec_minmaxp(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op dst, src, src2;
	bool ismax = false, num = false;
	int esize, lanes, half, n, j, i;
	if (OPCOUNT64 () != 3 || !ISREG64 (0) || !ISREG64 (1) || !ISREG64 (2)) {
		return;
	}
	dst = INSOP64 (0);
	src = INSOP64 (1);
	src2 = INSOP64 (2);
	if (!is_vector_op (&dst) || !is_vector_op (&src) || !is_vector_op (&src2)) {
		return;
	}
	esize = vector_size (&src);
	lanes = vas_count (src.vas);
	if (esize != 32 && esize != 64) {
		return;
	}
	if (vector_size (&dst) != esize || vas_count (dst.vas) != lanes || lanes < 2 || (lanes & 1) ||
		vector_size (&src2) != esize || vas_count (src2.vas) != lanes) {
		return;
	}
	switch (insn->id) {
	case ARM64_INS_FMAXP:
		ismax = true;
		break;
	case ARM64_INS_FMAXNMP:
		ismax = true;
		num = true;
		break;
	case ARM64_INS_FMINNMP:
		num = true;
		break;
	default:
		break;
	}
	half = lanes / 2;
	for (i = 0; i < lanes; i++) {
		RStrBuf lane_a, lane_b, combined;
		r_strbuf_init (&lane_a);
		r_strbuf_init (&lane_b);
		r_strbuf_init (&combined);
		if (i > 0) {
			COMMA (&op->esil);
		}
		n = i < half? 1: 2;
		j = 2 * (i % half);
		VECARG64_APPEND (&lane_a, n, j, 0);
		VECARG64_APPEND (&lane_b, n, j + 1, 0);
		arm64_esil_minmax_expr (&combined, esize, ismax, num, r_strbuf_get (&lane_a), r_strbuf_get (&lane_b));
		r_strbuf_append (&op->esil, r_strbuf_get (&combined));
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&lane_a);
		r_strbuf_fini (&lane_b);
		r_strbuf_fini (&combined);
	}
}


// fsqrt per lane; the raw bits are kept for zero and infinity so the 32-bit
// lanes never see the 64-bit NaN and infinity bits D2F would emit for them
static void arm64_esil_vec_sqrt(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op src;
	ut64 signlane, nanc, expmant;
	bool vector;
	int esize, lanes, i;
	if (OPCOUNT64 () != 2 || !ISREG64 (0) || !ISREG64 (1)) {
		return;
	}
	src = INSOP64 (1);
	vector = is_vector_op (&src);
	lanes = vector? vas_count (src.vas): 1;
	esize = vector? vector_size (&src): REGBITS64 (1);
	if (esize != 32 && esize != 64) {
		return;
	}
	signlane = 1ULL << (esize - 1);
	nanc = (esize == 32)? 0x7fc00000ULL: 0x7ff8000000000000ULL;
	expmant = (esize == 32)? 0x7f800000ULL: 0x7ff0000000000000ULL;
	for (i = 0; i < lanes; i++) {
		RStrBuf lane_a, nan_value, sqrt_value, closed, lane;
		const char *a;
		r_strbuf_init (&lane_a);
		r_strbuf_init (&nan_value);
		r_strbuf_init (&sqrt_value);
		r_strbuf_init (&closed);
		r_strbuf_init (&lane);
		if (i > 0) {
			COMMA (&op->esil);
		}
		VECARG64_APPEND (&lane_a, 1, i, 0);
		a = r_strbuf_get (&lane_a);
		arm64_esil_fp_procnan (&nan_value, esize, a);
		r_strbuf_setf (&sqrt_value, "%d,%s,F2D,SQRT", esize, a);
		arm64_esil_f2lane (&closed, esize, r_strbuf_get (&sqrt_value), NULL);
		// NaN, then the signed zero and +inf keeping raw bits, then the
		// default NaN for every negative and SQRT for the plain values
		r_strbuf_setf (&lane, "%d,%s,F2D,DUP,F==,!,?{,%s,}{,", esize, a, r_strbuf_get (&nan_value));
		r_strbuf_appendf (&lane, "%s,0x%" PFMT64x ",&,0,-,!,?{,%s,}{,", a, signlane - 1, a);
		r_strbuf_appendf (&lane, "%s,0x%" PFMT64x ",&,?{,0x%" PFMT64x ",}{,", a, signlane, nanc);
		r_strbuf_appendf (&lane, "%s,0x%" PFMT64x ",-,!,?{,0x%" PFMT64x ",}{,", a, expmant, expmant);
		r_strbuf_appendf (&lane, "%s,},},},},", r_strbuf_get (&closed));
		r_strbuf_append (&op->esil, r_strbuf_get (&lane));
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&lane_a);
		r_strbuf_fini (&nan_value);
		r_strbuf_fini (&sqrt_value);
		r_strbuf_fini (&closed);
		r_strbuf_fini (&lane);
	}
}


// frecpe/frsqrte estimate per lane: the special inputs follow the ISA table
// entry exactly, while the normal range runs on a bit-hack seed refined by
// Newton-Raphson steps through tmp instead of the 8-bit hardware lookup
static void arm64_esil_vec_est(RAnalOp *op, csh *handle, cs_insn *insn) {
	// calibrated seeds of the double-width bit-hack estimates
	const ut64 recip_seed = 0x7fded6fa82e87a93ULL, rsq_seed = 0x5fe6eb50c7b537a9ULL;
	cs_arm64_op src;
	ut64 signlane, explane, nanc;
	bool vector, rsq;
	int esize, lanes, i, step;
	if (OPCOUNT64 () != 2 || !ISREG64 (0) || !ISREG64 (1)) {
		return;
	}
	src = INSOP64 (1);
	vector = is_vector_op (&src);
	lanes = vector? vas_count (src.vas): 1;
	esize = vector? vector_size (&src): REGBITS64 (1);
	if (esize != 32 && esize != 64) {
		return;
	}
	rsq = insn->id == ARM64_INS_FRSQRTE;
	signlane = 1ULL << (esize - 1);
	explane = (esize == 32)? 0x7f800000ULL: 0x7ff0000000000000ULL;
	nanc = (esize == 32)? 0x7fc00000ULL: 0x7ff8000000000000ULL;
	for (i = 0; i < lanes; i++) {
		RStrBuf lane_a, nan_value, exact, newton, closed, lane;
		const char *a;
		r_strbuf_init (&lane_a);
		r_strbuf_init (&nan_value);
		r_strbuf_init (&exact);
		r_strbuf_init (&newton);
		r_strbuf_init (&closed);
		r_strbuf_init (&lane);
		if (i > 0) {
			COMMA (&op->esil);
		}
		VECARG64_APPEND (&lane_a, 1, i, 0);
		a = r_strbuf_get (&lane_a);
		arm64_esil_fp_procnan (&nan_value, esize, a);
		// zero and subnormal inputs (plus huge ones for the reciprocal) run
		// on the exact 1/x and 1/sqrt with the input sign re-applied
		if (rsq) {
			r_strbuf_setf (&exact, "%d,%s,F2D,0x7fffffffffffffff,&,SQRT,0x3ff0000000000000,F/",
				esize, a);
		} else {
			r_strbuf_setf (&exact, "%d,%s,F2D,0x7fffffffffffffff,&,0x3ff0000000000000,F/",
				esize, a);
		}
		arm64_esil_f2lane (&closed, esize, r_strbuf_get (&exact), "0");
		r_strbuf_setf (&exact, "%s,0x%" PFMT64x ",&,%s,|", a, signlane, r_strbuf_get (&closed));
		// seed tmp with the bit-hack estimate, then chain the NR steps
		if (rsq) {
			r_strbuf_setf (&newton, "1,%d,%s,F2D,>>,0x%" PFMT64x ",-,tmp,=,", esize, a, rsq_seed);
			for (step = 0; step < 4; step++) {
				r_strbuf_appendf (&newton, "tmp,%d,%s,F2D,F*,tmp,F*,0x3fe0000000000000,F*,"
					"-F,0x3ff8000000000000,F+,tmp,F*,tmp,=,", esize, a);
			}
		} else {
			r_strbuf_setf (&newton, "%d,%s,F2D,0x%" PFMT64x ",-,tmp,=,", esize, a, recip_seed);
			for (step = 0; step < 4; step++) {
				r_strbuf_appendf (&newton, "tmp,%d,%s,F2D,F*,-F,0x4000000000000000,F+,tmp,F*,tmp,=,",
					esize, a);
			}
		}
		r_strbuf_fini (&closed);
		r_strbuf_init (&closed);
		arm64_esil_f2lane (&closed, esize, "tmp", NULL);
		r_strbuf_append (&newton, r_strbuf_get (&closed));
		if (rsq) {
			// NaN, signed zero and subnormals exact, any negative (also
			// -inf) to the default NaN, +inf to +0, else the NR estimate
			r_strbuf_setf (&lane, "%d,%s,F2D,DUP,F==,!,?{,%s,}{,", esize, a, r_strbuf_get (&nan_value));
			r_strbuf_appendf (&lane, "%s,0x%" PFMT64x ",&,0,-,!,%s,0x%" PFMT64x ",&,0,-,!,&,%s,0x%" PFMT64x ",&,0,-,!,|,?{,%s,}{,",
				a, explane, a, signlane, a, signlane - 1, r_strbuf_get (&exact));
			r_strbuf_appendf (&lane, "%s,0x%" PFMT64x ",&,?{,0x%" PFMT64x ",}{,", a, signlane, nanc);
			r_strbuf_appendf (&lane, "%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!,?{,0,}{,",
				esize, a);
			r_strbuf_appendf (&lane, "%s,},},},},", r_strbuf_get (&newton));
		} else {
			r_strbuf_setf (&lane, "%d,%s,F2D,DUP,F==,!,?{,%s,}{,", esize, a, r_strbuf_get (&nan_value));
			r_strbuf_appendf (&lane, "%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!,?{,%s,0x%" PFMT64x ",&,}{,",
				esize, a, a, signlane);
			r_strbuf_appendf (&lane, "%s,0x%" PFMT64x ",&,0,-,!,", a, explane);
			r_strbuf_appendf (&lane, "0x7fe0000000000000,%d,%s,F2D,0x7fe0000000000000,&,>=,|,?{,%s,}{,",
				esize, a, r_strbuf_get (&exact));
			r_strbuf_appendf (&lane, "%s,},},},", r_strbuf_get (&newton));
		}
		r_strbuf_append (&op->esil, r_strbuf_get (&lane));
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&lane_a);
		r_strbuf_fini (&nan_value);
		r_strbuf_fini (&exact);
		r_strbuf_fini (&newton);
		r_strbuf_fini (&closed);
		r_strbuf_fini (&lane);
	}
}


// frecps/frsqrts per lane: the fused steps of the reciprocal and reciprocal
// square root Newton-Raphson iterations, D = 2 - n * m and (3 - n * m) / 2
static void arm64_esil_vec_fstep(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op dst, src, src2;
	ut64 infbits, pairc;
	bool vector, rsq;
	int esize, lanes, i;
	if (OPCOUNT64 () != 3 || !ISREG64 (0) || !ISREG64 (1) || !ISREG64 (2)) {
		return;
	}
	src = INSOP64 (1);
	src2 = INSOP64 (2);
	if (src.vector_index != -1 || src2.vector_index != -1) {
		return;
	}
	vector = is_vector_op (&src);
	lanes = vector? vas_count (src.vas): 1;
	esize = vector? vector_size (&src): REGBITS64 (1);
	if (esize != 32 && esize != 64) {
		return;
	}
	if (vector) {
		dst = INSOP64 (0);
		if (!is_vector_op (&dst) || !is_vector_op (&src2) || vector_size (&dst) != esize ||
			vas_count (dst.vas) != lanes || vector_size (&src2) != esize || vas_count (src2.vas) != lanes) {
			return;
		}
	}
	rsq = insn->id == ARM64_INS_FRSQRTS;
	infbits = (esize == 32)? 0x7f800000ULL: 0x7ff0000000000000ULL;
	// the constant the step collapses to for the (inf, 0) input pair
	pairc = rsq
		? ((esize == 32)? 0x3fc00000ULL: 0x3ff8000000000000ULL)
		: ((esize == 32)? 0x40000000ULL: 0x4000000000000000ULL);
	for (i = 0; i < lanes; i++) {
		RStrBuf lane_a, lane_b, propagate, step_value, sign, closed, classes, lane;
		const char *a, *b;
		r_strbuf_init (&lane_a);
		r_strbuf_init (&lane_b);
		r_strbuf_init (&propagate);
		r_strbuf_init (&step_value);
		r_strbuf_init (&sign);
		r_strbuf_init (&closed);
		r_strbuf_init (&classes);
		r_strbuf_init (&lane);
		if (i > 0) {
			COMMA (&op->esil);
		}
		VECARG64_APPEND (&lane_a, 1, i, 0);
		VECARG64_APPEND (&lane_b, 2, i, 0);
		a = r_strbuf_get (&lane_a);
		b = r_strbuf_get (&lane_b);
		arm64_esil_fp_propnans (&propagate, esize, a, b, true);
		if (rsq) {
			r_strbuf_setf (&step_value, "%d,%s,F2D,%d,%s,F2D,F*,0x3fe0000000000000,F*,-F,0x3ff8000000000000,F+",
				esize, a, esize, b);
		} else {
			r_strbuf_setf (&step_value, "%d,%s,F2D,%d,%s,F2D,F*,-F,0x4000000000000000,F+",
				esize, a, esize, b);
		}
		// an overflowing step result flips to the opposite of the product sign
		r_strbuf_setf (&sign, "%d,%s,F2D,0x8000000000000000,&,%d,%s,F2D,0x8000000000000000,&,^,!,?{,1,}{,0,},",
			esize, a, esize, b);
		arm64_esil_f2lane (&closed, esize, r_strbuf_get (&step_value), r_strbuf_get (&sign));
		// classify the operands in the double domain: an infinite operand
		// paired with a zero gives the positive constant, a lone infinity a
		// signed infinity, the rest runs through the fused step
		r_strbuf_setf (&classes, "%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!,"
			"%d,%s,F2D,0x7fffffffffffffff,&,0,-,!,&,", esize, a, esize, b);
		r_strbuf_appendf (&classes, "%d,%s,F2D,0x7fffffffffffffff,&,0,-,!,"
			"%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!,&,|,?{,0x%" PFMT64x ",}{,",
			esize, a, esize, b, pairc);
		r_strbuf_appendf (&classes, "%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!,"
			"%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!,|,?{,", esize, a, esize, b);
		if (esize == 32) {
			r_strbuf_appendf (&classes, "32,%d,%s,F2D,0x8000000000000000,&,%d,%s,F2D,0x8000000000000000,&,^,"
				"0x8000000000000000,^,>>,0x%" PFMT64x ",|,}{,%s,", esize, a, esize, b, infbits,
				r_strbuf_get (&closed));
		} else {
			r_strbuf_appendf (&classes, "%d,%s,F2D,0x8000000000000000,&,%d,%s,F2D,0x8000000000000000,&,^,"
				"0x8000000000000000,^,0x%" PFMT64x ",|,}{,%s,", esize, a, esize, b, infbits,
				r_strbuf_get (&closed));
		}
		r_strbuf_setf (&lane, "%d,%s,F2D,DUP,F==,!,%d,%s,F2D,DUP,F==,!,|,?{,%s,}{,",
			esize, a, esize, b, r_strbuf_get (&propagate));
		r_strbuf_appendf (&lane, "%s,},},},", r_strbuf_get (&classes));
		r_strbuf_append (&op->esil, r_strbuf_get (&lane));
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&lane_a);
		r_strbuf_fini (&lane_b);
		r_strbuf_fini (&propagate);
		r_strbuf_fini (&step_value);
		r_strbuf_fini (&sign);
		r_strbuf_fini (&closed);
		r_strbuf_fini (&classes);
		r_strbuf_fini (&lane);
	}
}


// fmulx per lane: zeros behave like infinities of the same sign, so the
// (inf, 0) pair gives a signed 2.0 and a lone zero gives a signed zero
static void arm64_esil_vec_fmulx(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op dst, src, src2;
	ut64 infbits, twobits;
	bool vector, element;
	int esize, lanes, i;
	if (OPCOUNT64 () != 3 || !ISREG64 (0) || !ISREG64 (1) || !ISREG64 (2)) {
		return;
	}
	dst = INSOP64 (0);
	src = INSOP64 (1);
	src2 = INSOP64 (2);
	vector = is_vector_op (&src);
	if (vector != is_vector_op (&dst)) {
		return;
	}
	esize = vector? vector_size (&src): REGBITS64 (1);
	lanes = vector? vas_count (src.vas): 1;
	if (esize != 32 && esize != 64) {
		return;
	}
	if (vector && (vector_size (&dst) != esize || vas_count (dst.vas) != lanes)) {
		return;
	}
	element = src2.vector_index != -1;
	if (element) {
		if (!is_vector_op (&src2) && (esize != 64 || !vector)) {
			return;
		}
	} else if (vector && (!is_vector_op (&src2) || vector_size (&src2) != esize ||
		vas_count (src2.vas) != lanes)) {
		return;
	} else if (!vector && (is_vector_op (&src2) || REGBITS64 (2) != esize)) {
		return;
	}
	infbits = (esize == 32)? 0x7f800000ULL: 0x7ff0000000000000ULL;
	twobits = (esize == 32)? 0x40000000ULL: 0x4000000000000000ULL;
	for (i = 0; i < lanes; i++) {
		RStrBuf lane_a, lane_b, propagate, product, sign, closed, classes, sign_xor, lane;
		const char *a, *b, *sign_bits;
		r_strbuf_init (&lane_a);
		r_strbuf_init (&lane_b);
		r_strbuf_init (&propagate);
		r_strbuf_init (&product);
		r_strbuf_init (&sign);
		r_strbuf_init (&closed);
		r_strbuf_init (&classes);
		r_strbuf_init (&sign_xor);
		r_strbuf_init (&lane);
		if (i > 0) {
			COMMA (&op->esil);
		}
		VECARG64_APPEND (&lane_a, 1, i, 0);
		if (element && !is_vector_op (&src2)) {
			const char *rn = cs_reg_name (*handle, src2.reg);
			r_strbuf_setf (&lane_b, "%s%s", rn, src2.vector_index? "h": "l");
		} else {
			VECARG64_APPEND (&lane_b, 2, i, 0);
		}
		a = r_strbuf_get (&lane_a);
		b = r_strbuf_get (&lane_b);
		arm64_esil_fp_propnans (&propagate, esize, a, b, false);
		r_strbuf_setf (&product, "%d,%s,F2D,%d,%s,F2D,F*", esize, a, esize, b);
		r_strbuf_setf (&sign, "%d,%s,F2D,0x8000000000000000,&,%d,%s,F2D,0x8000000000000000,&,^,?{,1,}{,0,},",
			esize, a, esize, b);
		arm64_esil_f2lane (&closed, esize, r_strbuf_get (&product), r_strbuf_get (&sign));
		// the shared sign-xor prefix for the three special classes
		r_strbuf_setf (&sign_xor, "%d,%s,F2D,0x8000000000000000,&,%d,%s,F2D,0x8000000000000000,&,^,",
			esize, a, esize, b);
		sign_bits = r_strbuf_get (&sign_xor);
		r_strbuf_setf (&classes, "%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!,"
			"%d,%s,F2D,0x7fffffffffffffff,&,0,-,!,&,", esize, a, esize, b);
		r_strbuf_appendf (&classes, "%d,%s,F2D,0x7fffffffffffffff,&,0,-,!,"
			"%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!,&,|,?{,", esize, a, esize, b);
		if (esize == 32) {
			r_strbuf_appendf (&classes, "32,%s,>>,0x%" PFMT64x ",|,}{,", sign_bits, twobits);
		} else {
			r_strbuf_appendf (&classes, "%s,0x%" PFMT64x ",|,}{,", sign_bits, twobits);
		}
		r_strbuf_appendf (&classes, "%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!,"
			"%d,%s,F2D,0x7ff0000000000000,&,0x7ff0000000000000,-,!,|,?{,", esize, a, esize, b);
		if (esize == 32) {
			r_strbuf_appendf (&classes, "32,%s,>>,0x%" PFMT64x ",|,}{,", sign_bits, infbits);
		} else {
			r_strbuf_appendf (&classes, "%s,0x%" PFMT64x ",|,}{,", sign_bits, infbits);
		}
		r_strbuf_appendf (&classes, "%d,%s,F2D,0x7fffffffffffffff,&,0,-,!,"
			"%d,%s,F2D,0x7fffffffffffffff,&,0,-,!,|,?{,", esize, a, esize, b);
		if (esize == 32) {
			r_strbuf_appendf (&classes, "32,%s,>>,}{,%s,", sign_bits, r_strbuf_get (&closed));
		} else {
			r_strbuf_appendf (&classes, "%s,}{,%s,", sign_bits, r_strbuf_get (&closed));
		}
		r_strbuf_setf (&lane, "%d,%s,F2D,DUP,F==,!,%d,%s,F2D,DUP,F==,!,|,?{,%s,}{,",
			esize, a, esize, b, r_strbuf_get (&propagate));
		r_strbuf_appendf (&lane, "%s,},},},},", r_strbuf_get (&classes));
		r_strbuf_append (&op->esil, r_strbuf_get (&lane));
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&lane_a);
		r_strbuf_fini (&lane_b);
		r_strbuf_fini (&propagate);
		r_strbuf_fini (&product);
		r_strbuf_fini (&sign);
		r_strbuf_fini (&closed);
		r_strbuf_fini (&classes);
		r_strbuf_fini (&sign_xor);
		r_strbuf_fini (&lane);
	}
}


// frecpx: mirror the biased exponent bits, with zeros and subnormals going
// to the max normal and NaNs handled by FPProcessNaN
static void arm64_esil_frecpx(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op src;
	const char *a;
	ut64 signlane, explane, mantmask, qbit, maxc;
	int esize;
	if (OPCOUNT64 () != 2 || !ISREG64 (0) || !ISREG64 (1)) {
		return;
	}
	src = INSOP64 (1);
	if (is_vector_op (&src)) {
		return;
	}
	esize = REGBITS64 (1);
	if (esize != 32 && esize != 64) {
		return;
	}
	signlane = 1ULL << (esize - 1);
	explane = (esize == 32)? 0x7f800000ULL: 0x7ff0000000000000ULL;
	mantmask = (1ULL << (esize == 32? 23: 52)) - 1;
	qbit = (esize == 32)? 0x00400000ULL: 0x0008000000000000ULL;
	maxc = explane - (1ULL << (esize == 32? 23: 52));
	a = REG64 (1);
	// NaN keeps its payload, quieted by the quiet bit
	r_strbuf_setf (&op->esil, "%s,0x%" PFMT64x ",&,0x%" PFMT64x ",-,!,%s,0x%" PFMT64x ",&,!,!,&,?{,",
		a, explane, explane, a, mantmask);
	r_strbuf_appendf (&op->esil, "%s,0x%" PFMT64x ",|,}{,", a, qbit);
	// zeros and subnormals take the max normal, normals mirror the exponent
	r_strbuf_appendf (&op->esil, "%s,0x%" PFMT64x ",&,0,-,!,?{,%s,0x%" PFMT64x ",&,0x%" PFMT64x ",|,}{,",
		a, explane, a, signlane, maxc);
	r_strbuf_appendf (&op->esil, "%s,0x%" PFMT64x ",&,0x%" PFMT64x ",^,%s,0x%" PFMT64x ",&,|,",
		a, explane, explane, a, signlane);
	r_strbuf_append (&op->esil, "},},");
	VEC64_DST_APPEND (&op->esil, 0, 0);
	r_strbuf_append (&op->esil, ",=");
}


// narrowing/widening fp lane pairs for fcvtn/fcvtn2/fcvtl/fcvtl2
static void arm64_esil_vec_fcvtnl(RAnalOp *op, csh *handle, cs_insn *insn) {
	bool upper = false, narrow = false;
	int i;
	switch (insn->id) {
	case ARM64_INS_FCVTN:
		narrow = true;
		break;
	case ARM64_INS_FCVTN2:
		narrow = true;
		upper = true;
		break;
	case ARM64_INS_FCVTL:
		break;
	case ARM64_INS_FCVTL2:
		upper = true;
		break;
	default:
		break;
	}
	for (i = 0; i < 2; i++) {
		int src_i, dst_i;
		if (i > 0) {
			COMMA (&op->esil);
		}
		// the *2 forms read or write the upper two lanes of the wide side
		src_i = (!narrow && upper)? i + 2: i;
		dst_i = (narrow && upper)? i + 2: i;
		r_strbuf_appendf (&op->esil, "%d,%d,", vector_size (&INSOP64 (0)),
			vector_size (&INSOP64 (1)));
		VECARG64_APPEND (&op->esil, 1, src_i, 0);
		r_strbuf_append (&op->esil, ",F2D,D2F,");
		VEC64_DST_APPEND (&op->esil, 0, dst_i);
		r_strbuf_append (&op->esil, ",=");
	}
}

// shifts whose count comes from the matching lane of the third operand; the
// ISA takes SInt(op2_lane[7:0]) so only the low 8 bits of the lane matter
static void arm64_esil_vec_shift_reg(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op src = INSOP64 (1);
	int lanes = vas_count (src.vas), lane_bits = vector_size (&src);
	ut64 mask = bitmask_by_width[lane_bits - 1];
	bool unsrc = false, rounded = false, sat = false;
	int up, i;
	switch (insn->id) {
	case ARM64_INS_SSHL:
		break;
	case ARM64_INS_USHL:
		unsrc = true;
		break;
	case ARM64_INS_SRSHL:
		rounded = true;
		break;
	case ARM64_INS_URSHL:
		unsrc = true;
		rounded = true;
		break;
	case ARM64_INS_SQSHL:
		sat = true;
		break;
	case ARM64_INS_UQSHL:
		unsrc = true;
		sat = true;
		break;
	case ARM64_INS_SQRSHL:
		sat = true;
		rounded = true;
		break;
	case ARM64_INS_UQRSHL:
		unsrc = true;
		sat = true;
		rounded = true;
		break;
	default:
		break;
	}
	up = 64 - lane_bits;
	for (i = 0; i < lanes; i++) {
		RStrBuf value_lane, shift_lane, shift_expr, sextended, sat_limit, pos_probe, neg_probe, left_shift, right_shift;
		const char *val, *shift, *scount, *sext, *right, *left;
		ut64 signbit, maxs;
		if (i > 0) {
			COMMA (&op->esil);
		}
		r_strbuf_init (&value_lane);
		r_strbuf_init (&shift_lane);
		r_strbuf_init (&shift_expr);
		r_strbuf_init (&sextended);
		r_strbuf_init (&sat_limit);
		r_strbuf_init (&pos_probe);
		r_strbuf_init (&neg_probe);
		r_strbuf_init (&left_shift);
		r_strbuf_init (&right_shift);
		VECARG64_APPEND (&value_lane, 1, i, 0);
		VECARG64_APPEND (&shift_lane, 2, i, 0);
		val = r_strbuf_get (&value_lane);
		shift = r_strbuf_get (&shift_lane);
		// signed shift count from the low 8 bits of the shift lane
		r_strbuf_appendf (&shift_expr, "0xff,%s,&,56,SWAP,<<,56,SWAP,ASR", shift);
		scount = r_strbuf_get (&shift_expr);
		// sign-extended source lane (identity for the unsigned source forms)
		r_strbuf_appendf (&sextended, "%d,%d,%s,<<,ASR", up, up, val);
		sext = r_strbuf_get (&sextended);
		// right by -scount: sign fill unless the source is unsigned; when
		// rounding, RShr's half unit becomes (val ASR n) + ((val ASR (n-1)) & 1)
		if (unsrc) {
			if (rounded) {
				r_strbuf_appendf (&right_shift, "%s,0,-,%s,>>,1,%s,0,-,-,%s,>>,1,&,+",
					scount, val, scount, val);
			} else {
				r_strbuf_appendf (&right_shift, "%s,0,-,%s,>>", scount, val);
			}
		} else if (rounded) {
			r_strbuf_appendf (&right_shift,
				"%s,0,-,%d,%d,%s,<<,ASR,ASR,1,%s,0,-,-,%d,%d,%s,<<,ASR,ASR,1,&,+",
				scount, up, up, val, scount, up, up, val);
		} else {
			r_strbuf_appendf (&right_shift, "%s,0,-,%d,%d,%s,<<,ASR,ASR", scount, up, up, val);
		}
		right = r_strbuf_get (&right_shift);
		// left by scount: plain, or saturating where the unsigned lanes go all
		// ones and the signed lanes go to the signed max/min via the P,N
		// probes (val > max >> scount and -val > max >> scount); the unsigned probe
		// flips the sign bit so the VM'shift signed compare orders it correctly
		signbit = 1ULL << 63;
		maxs = bitmask_by_width[lane_bits - 2];
		if (!sat) {
			r_strbuf_appendf (&left_shift, "%s,%s,<<", scount, val);
		} else if (unsrc) {
			r_strbuf_appendf (&left_shift,
				"%s,0x%" PFMT64x ",>>,0x%" PFMT64x ",^,%s,0x%" PFMT64x ",^,>,"
				"0x%" PFMT64x ",*,%s,%s,<<,|",
				scount, (ut64)mask, signbit, val, signbit, (ut64)mask, scount, val);
		} else {
			const char *limit, *pos_over, *neg_over;
			r_strbuf_appendf (&sat_limit, "%s,0x%" PFMT64x ",>>", scount, (ut64)maxs);
			limit = r_strbuf_get (&sat_limit);
			r_strbuf_appendf (&pos_probe, "%s,%s,>", limit, sext);
			pos_over = r_strbuf_get (&pos_probe);
			r_strbuf_appendf (&neg_probe, "%s,%s,0,-,>", limit, sext);
			neg_over = r_strbuf_get (&neg_probe);
			r_strbuf_appendf (&left_shift,
				"%s,%s,+,0x%" PFMT64x ",*,%s,0x%" PFMT64x ",*,%s,0x%" PFMT64x ",*,+,&,"
				"%s,%s,+,0x%" PFMT64x ",*,0xffffffffffffffff,^,%s,%s,<<,&,|",
				pos_over, neg_over, (ut64)mask, pos_over, (ut64)maxs,
				neg_over, (ut64)(~maxs & mask), pos_over, neg_over, (ut64)mask, scount, val);
		}
		left = r_strbuf_get (&left_shift);
		// scount >= 0 selects the left branch (scount == 0 must not round)
		r_strbuf_appendf (&op->esil, "0,%s,<,!,?{,%s,}{,%s,},", scount, left, right);
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&value_lane);
		r_strbuf_fini (&shift_lane);
		r_strbuf_fini (&shift_expr);
		r_strbuf_fini (&sextended);
		r_strbuf_fini (&sat_limit);
		r_strbuf_fini (&pos_probe);
		r_strbuf_fini (&neg_probe);
		r_strbuf_fini (&left_shift);
		r_strbuf_fini (&right_shift);
	}
}

// widening shift left long; destination lanes are twice as wide as the
// source lanes and the 2 forms read the upper half of the source register
static void arm64_esil_vec_shll(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op dst = INSOP64 (0);
	int lanes = vas_count (dst.vas);
	bool upper = false, sgn = false;
	int src_bits, up, amount, i;
	switch (insn->id) {
	case ARM64_INS_SSHLL:
		sgn = true;
		break;
	case ARM64_INS_SSHLL2:
		sgn = true;
		upper = true;
		break;
	case ARM64_INS_USHLL:
		break;
	case ARM64_INS_USHLL2:
		upper = true;
		break;
	default:
		break;
	}
	src_bits = vector_size (&INSOP64 (1));
	up = 64 - src_bits;
	amount = IMM64 (2);
	for (i = 0; i < lanes; i++) {
		int src_i;
		if (i > 0) {
			COMMA (&op->esil);
		}
		src_i = upper? i + lanes: i;
		if (sgn) {
			// sign-extend the narrow lane before shifting so the sign bits
			// spread across the widened lane (SInt(opelt) << shift)
			r_strbuf_appendf (&op->esil, "%d,%d,%d,", amount, up, up);
			VECARG64_APPEND (&op->esil, 1, src_i, 0);
			r_strbuf_append (&op->esil, ",<<,ASR,<<,");
		} else {
			r_strbuf_appendf (&op->esil, "%d,", amount);
			VECARG64_APPEND (&op->esil, 1, src_i, 0);
			r_strbuf_append (&op->esil, ",<<,");
		}
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
	}
}

// narrowing shift right; source lanes are twice as wide as the destination
// lanes and the 2 forms write the upper half of the destination register
static void arm64_esil_vec_shrn(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op dst = INSOP64 (0);
	int lanes = vas_count (dst.vas), esize = vector_size (&dst);
	bool upper = false, rounded = false, unsrc = false, satun = false;
	int elements, up, amount, i;
	ut64 mask, maxs, mins;
	switch (insn->id) {
	case ARM64_INS_SHRN:
		unsrc = true;
		break;
	case ARM64_INS_SHRN2:
		unsrc = true;
		upper = true;
		break;
	case ARM64_INS_RSHRN:
		unsrc = true;
		rounded = true;
		break;
	case ARM64_INS_RSHRN2:
		unsrc = true;
		rounded = true;
		upper = true;
		break;
	case ARM64_INS_SQSHRN:
		break;
	case ARM64_INS_SQSHRN2:
		upper = true;
		break;
	case ARM64_INS_SQRSHRN:
		rounded = true;
		break;
	case ARM64_INS_SQRSHRN2:
		rounded = true;
		upper = true;
		break;
	case ARM64_INS_SQSHRUN:
		satun = true;
		break;
	case ARM64_INS_SQSHRUN2:
		satun = true;
		upper = true;
		break;
	case ARM64_INS_SQRSHRUN:
		satun = true;
		rounded = true;
		break;
	case ARM64_INS_SQRSHRUN2:
		satun = true;
		rounded = true;
		upper = true;
		break;
	default:
		break;
	}
	elements = upper? lanes / 2: lanes;
	up = 64 - esize * 2;
	amount = IMM64 (2);
	mask = bitmask_by_width[esize - 1];
	maxs = bitmask_by_width[esize - 2];
	mins = ~maxs;
	for (i = 0; i < elements; i++) {
		int dst_i;
		RStrBuf src_lane, asr_expr, lshr_expr;
		const char *val;
		if (i > 0) {
			COMMA (&op->esil);
		}
		dst_i = upper? i + elements: i;
		r_strbuf_init (&src_lane);
		r_strbuf_init (&asr_expr);
		r_strbuf_init (&lshr_expr);
		VECARG64_APPEND (&src_lane, 1, i, 0);
		val = r_strbuf_get (&src_lane);
		if (unsrc) {
			// logical shift then truncate; RShr's half unit becomes
			// (val >> n) + ((val >> (n - 1)) & 1) when rounding
			if (rounded) {
				r_strbuf_appendf (&lshr_expr, "%d,%s,>>,1,%d,-,%s,>>,1,&,+",
					amount, val, amount, val);
			} else {
				r_strbuf_appendf (&lshr_expr, "%d,%s,>>", amount, val);
			}
			r_strbuf_appendf (&op->esil, "%s,", r_strbuf_get (&lshr_expr));
		} else {
			const char *asr, *y;
			// arithmetic shift of the sign-extended lane, kept in tmp so
			// the saturation probes do not repeat the whole expression
			r_strbuf_appendf (&asr_expr, "%d,%d,%s,<<,ASR", up, up, val);
			asr = r_strbuf_get (&asr_expr);
			if (rounded) {
				r_strbuf_appendf (&lshr_expr, "%d,%s,ASR,1,%d,-,%s,ASR,1,&,+",
					amount, asr, amount, asr);
			} else {
				r_strbuf_appendf (&lshr_expr, "%d,%s,ASR", amount, asr);
			}
			y = r_strbuf_get (&lshr_expr);
			if (satun) {
				// clamp to [0, maxu]: the shifted value is sign extended
				// and below 2^63, so plain signed compares decide; the
				// positive probe must not fire for negative results
				r_strbuf_appendf (&op->esil,
					"%s,tmp,=,"
					"0x%"PFMT64x",tmp,>,0,tmp,<,!,*,0x%"PFMT64x",*,"
					"0x%"PFMT64x",tmp,>,0,tmp,<,!,*,0,tmp,<,|,0x%"PFMT64x",*,"
					"0xffffffffffffffff,^,tmp,&,|,",
					y, mask, mask, mask, mask);
			} else {
				// clamp to [mins, maxs]: (tmp & ~om) | (P*maxs + N*mins)
				r_strbuf_appendf (&op->esil,
					"%s,tmp,=,"
					"0x%"PFMT64x",tmp,>,0x%"PFMT64x",*,0x%"PFMT64x",tmp,<,0x%"PFMT64x",*,+,"
					"0x%"PFMT64x",tmp,>,0x%"PFMT64x",*,0x%"PFMT64x",tmp,<,0x%"PFMT64x",*,|,"
					"0xffffffffffffffff,^,tmp,&,|,",
					y,
					maxs, maxs, mins, mins,
					maxs, mask, mins, mask);
			}
		}
		VEC64_DST_APPEND (&op->esil, 0, dst_i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&src_lane);
		r_strbuf_fini (&asr_expr);
		r_strbuf_fini (&lshr_expr);
	}
}

// LD1/ST1/LD2-4/ST2-4 single and multiple structures and LD1R/LD2R-4R:
// contiguous per-element accesses in the ISA loop order (for r { for e }
// for the LD1/ST1 family, for e { for r } when interleaving), plus
// post-index writeback
static void arm64_esil_vec_ldst(RAnalOp *op, csh *handle, cs_insn *insn) {
	const ut32 id = insn->id;
	const int argc = OPCOUNT64 ();
	int memi = argc - 1;
	bool is_store, interleave, replicate, indexed;
	int nregs, r, lanes, ebytes, total, k;
	int lane; // shared lane index of the indexed (single structure) forms
	cs_arm64_op op0;
	const char *base;
	st64 sdisp;
	ut64 disp, off;
	if (!ISMEM64 (memi)) {
		memi--; // LD1 keeps the post-index offset in a separate operand
	}
	if (memi < 1 || !ISMEM64 (memi) || !ISREG64 (0) || !is_vector_op (&INSOP64 (0))) {
		return;
	}
	is_store = false;
	interleave = false;
	replicate = false;
	switch (id) {
	case ARM64_INS_ST1:
		is_store = true;
		break;
	case ARM64_INS_ST2:
	case ARM64_INS_ST3:
	case ARM64_INS_ST4:
		is_store = true;
		interleave = true;
		break;
	case ARM64_INS_LD2:
	case ARM64_INS_LD3:
	case ARM64_INS_LD4:
		interleave = true;
		break;
	case ARM64_INS_LD1R:
	case ARM64_INS_LD2R:
	case ARM64_INS_LD3R:
	case ARM64_INS_LD4R:
		replicate = true;
		break;
	default:
		break;
	}
	nregs = memi;
	lane = -1;
	for (r = 0; r < nregs; r++) {
		if (!ISREG64 (r) || !is_vector_op (&INSOP64 (r))) {
			return;
		}
		if (INSOP64 (r).vector_index != -1) {
			lane = INSOP64 (r).vector_index;
		}
	}
	op0 = INSOP64 (0);
	indexed = lane != -1;
	lanes = indexed? 1: vas_count (op0.vas);
	ebytes = vector_size (&op0) / 8;
	if (lanes < 1 || ebytes < 1 || ebytes > 8 || nregs < 1 || nregs > 4) {
		return;
	}
	base = MEMBASE64 (memi);
	sdisp = MEMDISP64 (memi);
	disp = sdisp < 0? -(ut64)sdisp: (ut64)sdisp;
	// one memory access per (register, lane) element: linear per register for
	// LD1/ST1, per lane across registers when interleaving, one element
	// replicated over the lanes for LDxR, shared lane for the indexed forms
	total = indexed? nregs: nregs * lanes;
	off = disp;
	for (k = 0; k < total; k++) {
		int rr, el;
		if (indexed) {
			rr = k;
			el = lane;
			off = disp + (ut64)k * ebytes;
		} else if (replicate) {
			rr = k / lanes;
			el = k % lanes;
			off = disp + (ut64)rr * ebytes; // re-read for each lane
		} else if (interleave) {
			rr = k % nregs;
			el = k / nregs;
			off = disp + (ut64)k * ebytes;
		} else {
			rr = k / lanes;
			el = k % lanes;
			off = disp + (ut64)k * ebytes;
		}
		if (k > 0) {
			COMMA (&op->esil);
		}
		if (is_store) {
			VECARG64_APPEND (&op->esil, rr, el, 0);
			r_strbuf_appendf (&op->esil, ",0x%" PFMT64x ",%s,+,=[%d]", off, base, ebytes);
		} else {
			r_strbuf_appendf (&op->esil, "0x%" PFMT64x ",%s,+,[%d],", off, base, ebytes);
			VEC64_DST_APPEND (&op->esil, rr, el);
			r_strbuf_append (&op->esil, ",=");
		}
	}
	if (!indexed && nregs > 1 && lanes * ebytes == 8) {
		// D-form structures zero the upper half of v1..v3; the zext pass
		// only covers the first destination register
		for (r = 1; r < nregs; r++) {
			r_strbuf_appendf (&op->esil, ",0,%sh,=", REG64 (r));
		}
	}
	if (insn->detail->arm64.writeback) {
		if (memi + 1 < argc && ISIMM64 (memi + 1)) {
			off = (ut64)IMM64 (memi + 1);
		} else if (memi + 1 < argc && ISREG64 (memi + 1)) {
			r_strbuf_appendf (&op->esil, ",%s,%s,+,%s,=", REG64 (memi + 1), base, base);
			return;
		} else {
			// Capstone omits the fixed post-index immediate of these forms
			off = (indexed || replicate)? (ut64)nregs * ebytes:
				(ut64)nregs * lanes * ebytes;
		}
		r_strbuf_appendf (&op->esil, ",0x%" PFMT64x ",%s,+,%s,=", off, base, base);
	}
}

// DUP (element and general): replicate a source element or the low bits of
// a GPR over all lanes of the destination
static void arm64_esil_vec_dup(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op src, dst;
	int esize, lanes, ebytes, e;
	RStrBuf element;
	const char *element_expr;
	if (OPCOUNT64 () != 2 || !ISREG64 (0) || !ISREG64 (1)) {
		return;
	}
	src = INSOP64 (1);
	dst = INSOP64 (0);
	esize = vector_size (&dst);
	lanes = vas_count (dst.vas);
	if (esize < 8 || esize > 64 || lanes < 1 || lanes > 16) {
		return;
	}
	ebytes = esize / 8;
	r_strbuf_init (&element);
	if (is_vector_op (&src)) {
		int off;
		if (src.vector_index == -1) {
			r_strbuf_fini (&element);
			return;
		}
		// the ISA indexes the element in destination-size units
		off = src.vector_index * ebytes;
		if (off + ebytes > 16) {
			r_strbuf_fini (&element);
			return;
		}
		r_strbuf_appendf (&element, "%d,%s%s,>>", (off % 8) * 8, REG64 (1), off < 8? "l": "h");
	} else {
		r_strbuf_appendf (&element, "%s", REG64 (1));
	}
	if (esize < 64) {
		r_strbuf_appendf (&element, ",0x%" PFMT64x ",&", (ut64)((1ULL << esize) - 1));
	}
	element_expr = r_strbuf_get (&element);
	for (e = 0; e < lanes; e++) {
		if (e > 0) {
			COMMA (&op->esil);
		}
		r_strbuf_append (&op->esil, element_expr);
		COMMA (&op->esil);
		VEC64_DST_APPEND (&op->esil, 0, e);
		r_strbuf_append (&op->esil, ",=");
	}
	r_strbuf_fini (&element);
}

// UMOV/SMOV: move a vector element to a GPR with zero or sign extension;
// the d-lane-to-x form reaches analop64_esil renamed to MOV by Capstone
static void arm64_esil_vec_umov(RAnalOp *op, csh *handle, cs_insn *insn, bool sgn) {
	cs_arm64_op src, dst;
	int esize, dbits, ebytes, off;
	if (OPCOUNT64 () != 2 || !ISREG64 (0) || !ISREG64 (1)) {
		return;
	}
	src = INSOP64 (1);
	dst = INSOP64 (0);
	if (is_vector_op (&dst) || !is_vector_op (&src) || src.vector_index == -1) {
		return;
	}
	esize = vector_size (&src);
	dbits = REGBITS64 (0);
	if (esize < 8 || esize > 64 || esize > dbits) {
		return;
	}
	ebytes = esize / 8;
	off = src.vector_index * ebytes;
	if (off + ebytes > 16) {
		return;
	}
	r_strbuf_setf (&op->esil, "%d,%s%s,>>", (off % 8) * 8, REG64 (1), off < 8? "l": "h");
	if (esize < 64) {
		r_strbuf_appendf (&op->esil, ",0x%" PFMT64x ",&", (ut64)((1ULL << esize) - 1));
	}
	if (sgn && esize < dbits) {
		// flip the sign bit then subtract it: sign-extends esize to 64 bits,
		// the register write truncates w destinations to 32
		const ut64 sb = 1ULL << (esize - 1);
		r_strbuf_appendf (&op->esil, ",0x%" PFMT64x ",SWAP,^,0x%" PFMT64x ",SWAP,-", sb, sb);
	}
	r_strbuf_appendf (&op->esil, ",%s,=", REG64 (0));
}

// MOVI/MVNI: replicate the expanded immediate over all lanes; Capstone
// reports the raw imm8 and the shift, so the element pattern is rebuilt
// here (MSL inserts the inverted imm8 into a ones element)
static void arm64_esil_vec_movi(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op dst, immop;
	int esize, lanes, k;
	const char *base;
	char vbuf[8];
	ut64 emask, pat, lo, hi;
	if (OPCOUNT64 () != 2 || !ISREG64 (0) || !ISIMM64 (1)) {
		return;
	}
	dst = INSOP64 (0);
	base = REG64 (0);
	if (is_vector_op (&dst)) {
		esize = vector_size (&dst);
		lanes = vas_count (dst.vas);
	} else {
		if (!base || (base[0] != 'd' && base[0] != 's')) {
			return;
		}
		esize = base[0] == 'd'? 64: 32;
		lanes = 1;
		snprintf (vbuf, sizeof (vbuf), "v%s", base + 1);
		base = vbuf;
	}
	if (esize < 8 || esize > 64 || lanes < 1 || lanes > 16) {
		return;
	}
	emask = esize == 64? UT64_MAX: ((1ULL << esize) - 1);
	pat = (ut64)IMM64 (1);
	immop = INSOP64 (1);
	if (esize != 64) {
		if (immop.shift.type == ARM64_SFT_MSL) {
			pat = ~(pat << immop.shift.value);
		} else if (immop.shift.type == ARM64_SFT_LSL) {
			pat <<= immop.shift.value;
		}
	}
	pat &= emask;
	if (insn->id == ARM64_INS_MVNI) {
		pat = ~pat & emask;
	}
	lo = 0;
	hi = 0;
	for (k = 0; k < lanes; k++) {
		ut64 *half = (k * esize < 64)? &lo: &hi;
		*half |= pat << ((k * esize) % 64);
	}
	r_strbuf_setf (&op->esil, "0x%" PFMT64x ",%sl,=,0x%" PFMT64x ",%sh,=",
		lo, base, hi, base);
}

// TBL/TBX: byte lookup in a table of one to four vector registers indexed
// by the source bytes; each candidate chunk matches on its base, which
// also rejects out-of-range indices, and TBX keeps the old byte when the
// index is out of range
static void arm64_esil_vec_tbl(RAnalOp *op, csh *handle, cs_insn *insn, bool ext) {
	const int argc = OPCOUNT64 (), nregs = argc - 2;
	int r, lanes, bound, i, c;
	const char *mreg, *dreg;
	if (nregs < 1 || nregs > 4) {
		return;
	}
	for (r = 0; r < argc; r++) {
		if (!ISREG64 (r) || !is_vector_op (&INSOP64 (r))) {
			return;
		}
	}
	lanes = vas_count (INSOP64 (0).vas);
	if (lanes < 1 || lanes > 16) {
		return;
	}
	mreg = REG64 (argc - 1);
	dreg = REG64 (0);
	bound = 16 * nregs;
	for (i = 0; i < lanes; i++) {
		if (i > 0) {
			COMMA (&op->esil);
		}
		// tmp holds the unsigned index byte of this lane
		r_strbuf_appendf (&op->esil, "%d,%s%s,>>,0xff,&,tmp,=",
			(i % 8) * 8, mreg, i < 8? "l": "h");
		for (c = 0; c < 2 * nregs; c++) {
			// each chunk contributes its byte only when the index matches
			// its base, otherwise zero; no branches are needed
			r_strbuf_appendf (&op->esil,
				",%s%s,tmp,7,&,8,*,SWAP,>>,0xff,&,tmp,0xf8,&,%d,^,!,*",
				REG64 (1 + (c >> 1)), (c & 1)? "h": "l", 8 * c);
			if (c > 0) {
				r_strbuf_append (&op->esil, ",+");
			}
		}
		if (ext) {
			r_strbuf_appendf (&op->esil,
				",%d,tmp,<,*,%d,tmp,<,!,%d,%s%s,>>,0xff,&,*,|",
				bound, bound, (i % 8) * 8, dreg, i < 8? "l": "h");
		}
		COMMA (&op->esil);
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
	}
}

// ADDV and the S/U MAXV/MINV forms fold all lanes into the low element of
// the destination with the rest zeroed; the fold runs left to right through
// tmp, which the ISA tree reduction agrees with for associative integer ops
static void arm64_esil_vec_reduceint(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op dst, src;
	const char *dname;
	int vnum, esize, lanes, i;
	bool sum, ismin, sgn;
	ut64 mask, sb;
	RStrBuf lane_expr;
	if (OPCOUNT64 () != 2 || !ISREG64 (0) || !ISREG64 (1)) {
		return;
	}
	dst = INSOP64 (0);
	src = INSOP64 (1);
	if (is_vector_op (&dst) || !is_vector_op (&src)) {
		return;
	}
	dname = cs_reg_name (*handle, dst.reg);
	if (!dname || !strchr ("bhsd", dname[0]) || !isdigit ((ut8)dname[1])) {
		return;
	}
	vnum = atoi (dname + 1);
	esize = vector_size (&src);
	lanes = vas_count (src.vas);
	if (vnum < 0 || vnum > 31 || esize < 8 || esize > 64 || lanes < 2 || lanes * esize > 128) {
		return;
	}
	sum = false;
	ismin = false;
	sgn = false;
	switch (insn->id) {
	case ARM64_INS_ADDV:
		sum = true;
		break;
	case ARM64_INS_SMAXV:
		sgn = true;
		break;
	case ARM64_INS_SMINV:
		sgn = true;
		ismin = true;
		break;
	case ARM64_INS_UMAXV:
		break;
	case ARM64_INS_UMINV:
		ismin = true;
		break;
	default:
		return;
	}
	mask = esize == 64? UT64_MAX: ((1ULL << esize) - 1);
	sb = 1ULL << (esize - 1);
	r_strbuf_init (&lane_expr);
	VECARG64_APPEND (&lane_expr, 1, 0, 0);
	r_strbuf_setf (&op->esil, "%s,tmp,=", r_strbuf_get (&lane_expr));
	for (i = 1; i < lanes; i++) {
		const char *lane;
		r_strbuf_fini (&lane_expr);
		r_strbuf_init (&lane_expr);
		VECARG64_APPEND (&lane_expr, 1, i, 0);
		lane = r_strbuf_get (&lane_expr);
		r_strbuf_append (&op->esil, ",");
		if (sum) {
			r_strbuf_appendf (&op->esil, "tmp,%s,+,tmp,=", lane);
		} else if (sgn && ismin) {
			// flipping the sign bit orders signed lanes as unsigned
			r_strbuf_appendf (&op->esil, "tmp,0x%" PFMT64x ",^,%s,0x%" PFMT64x ",^,<,?{,%s,tmp,=,},",
				sb, lane, sb, lane);
		} else if (sgn) {
			r_strbuf_appendf (&op->esil, "%s,0x%" PFMT64x ",^,tmp,0x%" PFMT64x ",^,<,?{,%s,tmp,=,},",
				lane, sb, sb, lane);
		} else if (ismin) {
			r_strbuf_appendf (&op->esil, "tmp,%s,<,?{,%s,tmp,=,},", lane, lane);
		} else {
			r_strbuf_appendf (&op->esil, "%s,tmp,<,?{,%s,tmp,=,},", lane, lane);
		}
	}
	r_strbuf_fini (&lane_expr);
	r_strbuf_appendf (&op->esil, ",0x%" PFMT64x ",tmp,&,v%dl,=", mask, vnum);
}

// FMAXV/FMINV/FMAXNMV/FMINNMV fold all lanes through tmp with the same
// FPMax/FPMin (Num) combine as the lane-wise forms; the halving tree of the
// ISA reduction agrees with the left fold under its NaN and zero rules
static void arm64_esil_vec_reducefp(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op dst, src;
	int esize, lanes, i;
	bool ismax, num;
	RStrBuf lane_expr, combined;
	if (OPCOUNT64 () != 2 || !ISREG64 (0) || !ISREG64 (1)) {
		return;
	}
	dst = INSOP64 (0);
	src = INSOP64 (1);
	if (is_vector_op (&dst) || !is_vector_op (&src)) {
		return;
	}
	esize = vector_size (&src);
	lanes = vas_count (src.vas);
	if (esize != 32 && esize != 64) {
		return; // fp16 forms are rejected
	}
	if (lanes < 2 || lanes * esize > 128) {
		return;
	}
	ismax = false;
	num = false;
	switch (insn->id) {
	case ARM64_INS_FMAXV:
		ismax = true;
		break;
	case ARM64_INS_FMAXNMV:
		ismax = true;
		num = true;
		break;
	case ARM64_INS_FMINNMV:
		num = true;
		break;
	default:
		break;
	}
	r_strbuf_init (&lane_expr);
	r_strbuf_init (&combined);
	VECARG64_APPEND (&lane_expr, 1, 0, 0);
	r_strbuf_setf (&op->esil, "%s,tmp,=", r_strbuf_get (&lane_expr));
	for (i = 1; i < lanes; i++) {
		r_strbuf_fini (&lane_expr);
		r_strbuf_init (&lane_expr);
		VECARG64_APPEND (&lane_expr, 1, i, 0);
		arm64_esil_minmax_expr (&combined, esize, ismax, num, "tmp", r_strbuf_get (&lane_expr));
		r_strbuf_append (&op->esil, ",");
		r_strbuf_append (&op->esil, r_strbuf_get (&combined));
		r_strbuf_append (&op->esil, "tmp,=");
	}
	r_strbuf_fini (&lane_expr);
	r_strbuf_fini (&combined);
	r_strbuf_append (&op->esil, ",tmp,");
	VEC64_DST_APPEND (&op->esil, 0, 0);
	r_strbuf_append (&op->esil, ",=");
}

// ADDP/FADDP: pairwise adds of adjacent lanes; the 3-register form folds
// operand 1 into the low result half and operand 2 into the high one (the
// ISA concatenates them as operand2::operand1), while the 2-register form
// reduces one pair to a scalar
static void arm64_esil_vec_pdp(RAnalOp *op, csh *handle, cs_insn *insn, bool fp) {
	const int argc = OPCOUNT64 ();
	int r, esize, lanes, dlanes, half, i;
	cs_arm64_op dst, src;
	if (argc < 2 || argc > 3) {
		return;
	}
	for (r = 0; r < argc; r++) {
		if (!ISREG64 (r)) {
			return;
		}
	}
	dst = INSOP64 (0);
	src = INSOP64 (1);
	if (!is_vector_op (&src)) {
		return;
	}
	esize = vector_size (&src);
	lanes = vas_count (src.vas);
	if (fp? (esize != 32 && esize != 64): (esize < 8 || esize > 64)) {
		return;
	}
	if (!is_vector_op (&dst)) {
		const char *dname = cs_reg_name (*handle, dst.reg), *want = fp? "sd": "d";
		RStrBuf lane_a, lane_b;
		if (argc != 2 || lanes != 2 || !dname || !strchr (want, dname[0])) {
			return;
		}
		r_strbuf_init (&lane_a);
		r_strbuf_init (&lane_b);
		VECARG64_APPEND (&lane_a, 1, 0, 0);
		VECARG64_APPEND (&lane_b, 1, 1, 0);
		if (fp) {
			r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F+,D2F,",
				esize, r_strbuf_get (&lane_a), esize, r_strbuf_get (&lane_b));
		} else {
			r_strbuf_setf (&op->esil, "%s,%s,+,", r_strbuf_get (&lane_a), r_strbuf_get (&lane_b));
		}
		VEC64_DST_APPEND (&op->esil, 0, 0);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&lane_a);
		r_strbuf_fini (&lane_b);
		return;
	}
	dlanes = vas_count (dst.vas);
	if (argc != 3 || dlanes != lanes || vector_size (&dst) != esize || lanes < 2 || (lanes & 1)) {
		return;
	}
	half = lanes / 2;
	for (i = 0; i < lanes; i++) {
		RStrBuf lane_a, lane_b;
		int n, j;
		if (i > 0) {
			COMMA (&op->esil);
		}
		r_strbuf_init (&lane_a);
		r_strbuf_init (&lane_b);
		n = i < half? 1: 2;
		j = 2 * (i % half);
		VECARG64_APPEND (&lane_a, n, j, 0);
		VECARG64_APPEND (&lane_b, n, j + 1, 0);
		if (fp) {
			r_strbuf_appendf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F+,D2F,",
				esize, r_strbuf_get (&lane_a), esize, r_strbuf_get (&lane_b));
		} else {
			r_strbuf_appendf (&op->esil, "%s,%s,+,", r_strbuf_get (&lane_a), r_strbuf_get (&lane_b));
		}
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&lane_a);
		r_strbuf_fini (&lane_b);
	}
}

// MLA/MLS: the per-lane product of the sources is added to or subtracted
// from the destination lane; by-element forms fold the element index into
// the second source through vector64_append
static void arm64_esil_vec_mac(RAnalOp *op, csh *handle, cs_insn *insn, bool sub) {
	cs_arm64_op dst, src, src2;
	int esize, lanes, i;
	if (OPCOUNT64 () != 3 || !ISREG64 (0) || !ISREG64 (1) || !ISREG64 (2)) {
		return;
	}
	dst = INSOP64 (0);
	src = INSOP64 (1);
	src2 = INSOP64 (2);
	if (!is_vector_op (&dst) || !is_vector_op (&src) || !is_vector_op (&src2)) {
		return;
	}
	esize = vector_size (&src);
	lanes = vas_count (src.vas);
	if (esize < 8 || esize > 32 || vector_size (&dst) != esize ||
		vas_count (dst.vas) != lanes || vector_size (&src2) != esize) {
		return;
	}
	for (i = 0; i < lanes; i++) {
		RStrBuf prod, factor, acc;
		r_strbuf_init (&prod);
		r_strbuf_init (&factor);
		r_strbuf_init (&acc);
		VECARG64_APPEND (&prod, 1, i, 0);
		VECARG64_APPEND (&factor, 2, i, 0);
		VECARG64_APPEND (&acc, 0, i, 0);
		if (i > 0) {
			COMMA (&op->esil);
		}
		r_strbuf_appendf (&op->esil, "%s,%s,*,%s,%c,",
			r_strbuf_get (&factor), r_strbuf_get (&prod), r_strbuf_get (&acc),
			sub? '-': '+');
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&prod);
		r_strbuf_fini (&factor);
		r_strbuf_fini (&acc);
	}
}

// SMIN/SMAX/UMIN/UMAX: per-lane selection through the VM compare; the signed
// forms flip the sign bit so the 64-bit signed compare orders the lanes
static void arm64_esil_vec_minmax_int(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op dst, src, src2;
	const char *a, *b;
	ut64 sb;
	bool sgn, ismin;
	int esize, lanes, i;
	if (OPCOUNT64 () != 3 || !ISREG64 (0) || !ISREG64 (1) || !ISREG64 (2)) {
		return;
	}
	dst = INSOP64 (0);
	src = INSOP64 (1);
	src2 = INSOP64 (2);
	if (!is_vector_op (&dst) || !is_vector_op (&src) || !is_vector_op (&src2)) {
		return;
	}
	esize = vector_size (&src);
	lanes = vas_count (src.vas);
	if (esize < 8 || esize > 32 || vector_size (&dst) != esize ||
		vas_count (dst.vas) != lanes || vector_size (&src2) != esize ||
		vas_count (src2.vas) != lanes) {
		return;
	}
	sgn = false;
	ismin = false;
	switch (insn->id) {
	case ARM64_INS_SMIN:
		sgn = true;
		ismin = true;
		break;
	case ARM64_INS_SMAX:
		sgn = true;
		break;
	case ARM64_INS_UMIN:
		ismin = true;
		break;
	case ARM64_INS_UMAX:
		break;
	default:
		return;
	}
	sb = 1ULL << (esize - 1);
	for (i = 0; i < lanes; i++) {
		RStrBuf lane_a, lane_b;
		r_strbuf_init (&lane_a);
		r_strbuf_init (&lane_b);
		VECARG64_APPEND (&lane_a, 1, i, 0);
		VECARG64_APPEND (&lane_b, 2, i, 0);
		a = r_strbuf_get (&lane_a);
		b = r_strbuf_get (&lane_b);
		if (i > 0) {
			COMMA (&op->esil);
		}
		if (sgn) {
			r_strbuf_appendf (&op->esil, "%s,0x%" PFMT64x ",^,%s,0x%" PFMT64x ",^,%c,?{,%s,}{,%s,},",
				b, sb, a, sb, ismin? '<': '>', a, b);
		} else {
			r_strbuf_appendf (&op->esil, "%s,%s,%c,?{,%s,}{,%s,},",
				b, a, ismin? '<': '>', a, b);
		}
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&lane_a);
		r_strbuf_fini (&lane_b);
	}
}

// SABD/UABD: absolute per-lane difference; d < 0 is detected by comparing
// the raw lanes (unsigned) or the flipped lanes (signed) and folded back as
// (d ^ m) + p through the 0/-1 sign mask
static void arm64_esil_vec_absdiff(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op dst, src, src2;
	const char *a, *b;
	ut64 sb;
	bool sgn;
	int esize, lanes, i;
	if (OPCOUNT64 () != 3 || !ISREG64 (0) || !ISREG64 (1) || !ISREG64 (2)) {
		return;
	}
	dst = INSOP64 (0);
	src = INSOP64 (1);
	src2 = INSOP64 (2);
	if (!is_vector_op (&dst) || !is_vector_op (&src) || !is_vector_op (&src2)) {
		return;
	}
	esize = vector_size (&src);
	lanes = vas_count (src.vas);
	if (esize < 8 || esize > 32 || vector_size (&dst) != esize ||
		vas_count (dst.vas) != lanes || vector_size (&src2) != esize ||
		vas_count (src2.vas) != lanes) {
		return;
	}
	switch (insn->id) {
	case ARM64_INS_SABD:
		sgn = true;
		break;
	case ARM64_INS_UABD:
		sgn = false;
		break;
	default:
		return;
	}
	sb = 1ULL << (esize - 1);
	for (i = 0; i < lanes; i++) {
		RStrBuf lane_a, lane_b, neg;
		r_strbuf_init (&lane_a);
		r_strbuf_init (&lane_b);
		r_strbuf_init (&neg);
		VECARG64_APPEND (&lane_a, 1, i, 0);
		VECARG64_APPEND (&lane_b, 2, i, 0);
		a = r_strbuf_get (&lane_a);
		b = r_strbuf_get (&lane_b);
		if (sgn) {
			r_strbuf_appendf (&neg, "%s,0x%" PFMT64x ",^,%s,0x%" PFMT64x ",^,<", a, sb, b, sb);
		} else {
			r_strbuf_appendf (&neg, "%s,%s,<", a, b);
		}
		if (i > 0) {
			COMMA (&op->esil);
		}
		r_strbuf_appendf (&op->esil, "%s,%s,-,%s,0,-,^,%s,+,",
			a, b, r_strbuf_get (&neg), r_strbuf_get (&neg));
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		r_strbuf_fini (&lane_a);
		r_strbuf_fini (&lane_b);
		r_strbuf_fini (&neg);
	}
}

// SADDLP/UADDLP/SADALP/UADALP: add adjacent narrow pairs into wide lanes,
// accumulating into the destination in the ALP forms
static void arm64_esil_vec_pwl(RAnalOp *op, csh *handle, cs_insn *insn) {
	cs_arm64_op dst, src;
	int desize, esize, lanes, e;
	bool sgn, acc;
	ut64 sb;
	if (OPCOUNT64 () != 2 || !ISREG64 (0) || !ISREG64 (1)) {
		return;
	}
	dst = INSOP64 (0);
	src = INSOP64 (1);
	if (!is_vector_op (&dst) || !is_vector_op (&src)) {
		return;
	}
	desize = vector_size (&dst);
	esize = vector_size (&src);
	lanes = vas_count (dst.vas);
	if (desize != 2 * esize || esize < 8 || esize > 32 || lanes * desize != 128 ||
		vas_count (src.vas) != 2 * lanes) {
		return;
	}
	sgn = false;
	acc = false;
	switch (insn->id) {
	case ARM64_INS_SADDLP:
		sgn = true;
		break;
	case ARM64_INS_SADALP:
		sgn = true;
		acc = true;
		break;
	case ARM64_INS_UADALP:
		acc = true;
		break;
	default:
		break;
	}
	sb = 1ULL << (esize - 1);
	for (e = 0; e < lanes; e++) {
		int k;
		if (e > 0) {
			COMMA (&op->esil);
		}
		for (k = 0; k < 2; k++) {
			RStrBuf pair_lane;
			r_strbuf_init (&pair_lane);
			VECARG64_APPEND (&pair_lane, 1, 2 * e + k, 0);
			if (k > 0) {
				r_strbuf_append (&op->esil, ",");
			}
			r_strbuf_append (&op->esil, r_strbuf_get (&pair_lane));
			if (sgn) {
				// flip the sign bit then subtract it to sign-extend
				r_strbuf_appendf (&op->esil, ",0x%" PFMT64x ",SWAP,^,0x%" PFMT64x ",SWAP,-", sb, sb);
			}
			r_strbuf_fini (&pair_lane);
		}
		r_strbuf_append (&op->esil, ",+");
		if (acc) {
			RStrBuf acc_lane;
			r_strbuf_init (&acc_lane);
			VECARG64_APPEND (&acc_lane, 0, e, 0);
			r_strbuf_appendf (&op->esil, ",%s,+", r_strbuf_get (&acc_lane));
			r_strbuf_fini (&acc_lane);
		}
		COMMA (&op->esil);
		VEC64_DST_APPEND (&op->esil, 0, e);
		r_strbuf_append (&op->esil, ",=");
	}
}

// per-lane shifts by #imm
static void arm64_esil_vec_shift(RAnalOp *op, csh *handle, cs_insn *insn, int amount) {
	cs_arm64_op src = INSOP64 (1);
	int lanes = vas_count (src.vas);
	int lane_bits = vector_size (&src);
	ut64 mask = bitmask_by_width[lane_bits - 1];
	int i;
	for (i = 0; i < lanes; i++) {
		if (i > 0) {
			COMMA (&op->esil);
		}
		switch (insn->id) {
		case ARM64_INS_SHL:
			r_strbuf_appendf (&op->esil, "%d,", amount);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_appendf (&op->esil, ",<<,0x%" PFMT64x ",&,", (ut64)mask);
			break;
		case ARM64_INS_USHR:
			r_strbuf_appendf (&op->esil, "%d,", amount);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_append (&op->esil, ",>>,");
			break;
		case ARM64_INS_SSHR:
			// left-align the lane so its sign bit lands on bit 63 and ASR
			// replicates it; the total shift covers the #imm as well
			r_strbuf_appendf (&op->esil, "%d,%d,", 64 - lane_bits + amount, 64 - lane_bits);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_appendf (&op->esil, ",<<,ASR,0x%" PFMT64x ",&,", (ut64)mask);
			break;
		case ARM64_INS_SQSHLU:
			// overflow iff a bit above lane_bits-amount survives the right
			// shift; the all-ones mask then saturates the left shift
			r_strbuf_appendf (&op->esil, "%d,", lane_bits - amount);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_appendf (&op->esil, ",>>,!,!,0,-,DUP,%d,", amount);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_appendf (&op->esil, ",<<,0x%" PFMT64x ",&,^,|,", (ut64)mask);
			break;
		case ARM64_INS_SLI:
			// keep the low amount bits of the destination lane
			r_strbuf_appendf (&op->esil, "0x%" PFMT64x ",",
				(ut64)(amount? bitmask_by_width[amount - 1]: 0));
			VECARG64_APPEND (&op->esil, 0, i, 0);
			r_strbuf_appendf (&op->esil, ",&,%d,", amount);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_appendf (&op->esil, ",<<,0x%" PFMT64x ",&,|,", (ut64)mask);
			break;
		case ARM64_INS_SRI:
		{
			// keep the high amount bits of the destination lane
			ut64 low = amount < lane_bits? (ut64)bitmask_by_width[lane_bits - amount - 1]: 0;
			r_strbuf_appendf (&op->esil, "0x%" PFMT64x ",", mask ^ low);
			VECARG64_APPEND (&op->esil, 0, i, 0);
			r_strbuf_appendf (&op->esil, ",&,%d,", amount);
			VECARG64_APPEND (&op->esil, 1, i, 0);
			r_strbuf_appendf (&op->esil, ",>>,0x%" PFMT64x ",&,|,", low);
			break;
		}
		}
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
	}
}

static int analop64_esil(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn) {
	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");

	const char *postfix = arm_prefix_cond (op, insn->detail->arm64.cc);

	switch (insn->id) {
	case ARM64_INS_BRK:
		r_strbuf_setf (&op->esil, "0,%d,TRAP", (int) (IMM64 (0) & 0xffff));
		break;
	case ARM64_INS_REV:
	case ARM64_INS_REV64:
	{
		cs_arm64_op src = INSOP64 (1);
		if (is_vector_op (&src)) {
			arm64_esil_rev_vector (op, handle, insn, REV_GRAN_64);
		} else if (REGSIZE64 (1) == 8) {
			arm64_esil_rev_dword (&op->esil, REG64 (1), REG64 (0), REV_GRAN_64);
		} else {
			// REV Wd, Wn reverses the whole word
			r_strbuf_setf (&op->esil,
				"24,0xff,%s,&,<<,tmp,=,"
				"16,0xff,8,%s,>>,&,<<,tmp,|=,"
				"8,0xff,16,%s,>>,&,<<,tmp,|=,"
				"0xff,24,%s,>>,&,tmp,|=,tmp,%s,=",
				REG64 (1), REG64 (1), REG64 (1), REG64 (1), REG64 (0));
		}
		break;
	}
	case ARM64_INS_REV32:
	{
		cs_arm64_op src = INSOP64 (1);
		if (is_vector_op (&src)) {
			arm64_esil_rev_vector (op, handle, insn, REV_GRAN_32);
		} else {
			arm64_esil_rev_dword (&op->esil, REG64 (1), REG64 (0), REV_GRAN_32);
		}
		break;
	}
	case ARM64_INS_REV16:
	{
		cs_arm64_op src = INSOP64 (1);
		if (is_vector_op (&src)) {
			arm64_esil_rev_vector (op, handle, insn, REV_GRAN_16);
		} else if (REGSIZE64 (1) == 8) {
			arm64_esil_rev_dword (&op->esil, REG64 (1), REG64 (0), REV_GRAN_16);
		} else {
			// REV16 Wd, Wn swaps bytes within each 16-bit halfword of the word
			r_strbuf_setf (&op->esil,
				"8,0xff00ff00,%s,&,>>,tmp,=,"
				"8,0x00ff00ff,%s,&,<<,tmp,|=,tmp,%s,=",
				REG64 (1), REG64 (1), REG64 (0));
		}
		break;
	}
	case ARM64_INS_ADR:
		// TODO: must be 21bit signed
		r_strbuf_setf (&op->esil,
			"%"PFMT64d",%s,=", IMM64 (1), REG64 (0));
		break;
	case ARM64_INS_SMADDL:
		r_strbuf_setf (&op->esil, "%d,%s,~,%d,%s,~,*,%s,+,%s,=",
			REGBITS64 (1), REG64 (2), REGBITS64 (1), REG64 (1), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_SMSUBL:
		r_strbuf_setf (&op->esil, "%d,%s,~,%d,%s,~,*,%s,-,%s,=",
			REGBITS64 (1), REG64 (2), REGBITS64 (1), REG64 (1), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_UMADDL:
#if CS_API_MAJOR >= 6
	case ARM64_INS_MADDPT:
#endif
	case ARM64_INS_MADD:
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,+,%s,=",
			REG64 (2), REG64 (1), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_UMSUBL:
#if CS_API_MAJOR >= 6
	case ARM64_INS_MSUBPT:
#endif
	case ARM64_INS_MSUB:
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,-,%s,=",
			REG64 (2), REG64 (1), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_MNEG:
		r_strbuf_setf (&op->esil, "%s,%s,*,0,-,%s,=",
			REG64 (2), REG64 (1), REG64 (0));
		break;
#if CS_API_MAJOR >= 6
	case ARM64_INS_ADDPT:
		if (REG64 (0)[0] != 'z') {
			OPCALL ("+");
		}
		break;
#endif
#if CS_API_MAJOR > 4
	case ARM64_INS_ADDG:
#endif
	case ARM64_INS_ADD:
		OPCALL ("+");
		break;
	case ARM64_INS_ADC:
		r_strbuf_setf (&op->esil, "cf,%s,+,%s,+,%s,=",
			REG64 (2), REG64 (1), REG64 (0));
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_SUBG:
		// Model address subtraction without the system-controlled tag selection.
		OPCALL ("-");
		break;
	case ARM64_INS_SUBP:
		arm64_subp_esil (op, handle, insn, false, false);
		break;
	case ARM64_INS_SUBPS:
		arm64_subp_esil (op, handle, insn, true, false);
		break;
#if CS_API_MAJOR == 5
	case ARM64_INS_CMPP:
		arm64_subp_esil (op, handle, insn, true, true);
		break;
#endif
#endif
#if CS_API_MAJOR >= 6
	case ARM64_INS_SUBPT:
		if (REG64 (0)[0] != 'z') {
			OPCALL ("-");
		}
		break;
#endif
	case ARM64_INS_SUB:
		OPCALL ("-");
		break;
	case ARM64_INS_SBC:
	case ARM64_INS_NGC: {
		// rd = rn + ~rm + C; ngc is the rn=xzr form
		const bool ngc = OPCOUNT64 () == 2;
		const char *rn = ngc? "0": REG64 (1);
		const char *rm = ngc? REG64 (1): REG64 (2);
		r_strbuf_setf (&op->esil, "cf,%s,-1,^,+,%s,+,%s,=", rm, rn, REG64 (0));
		break;
	}
	case ARM64_INS_NGCS:
#if CS_API_MAJOR > 4
	case ARM64_INS_SBCS:
#endif
	{
		// AddWithCarry (rn, ~rm, C) like ADCS; V reduces to ((rn^rm)&(rn^r))>>msb
		const int bits = REGBITS64 (0);
		const bool ngc = OPCOUNT64 () == 2;
		const char *rn = ngc? "0": REG64 (1);
		const char *rm = ngc? REG64 (1): REG64 (2);
		char sum[80];
		if (bits == 32) {
			snprintf (sum, sizeof (sum), "0xffffffff,cf,%s,-1,^,+,%s,+,&", rm, rn);
		} else {
			snprintf (sum, sizeof (sum), "cf,%s,-1,^,+,%s,+", rm, rn);
		}
		r_strbuf_setf (&op->esil,
			"0,%s,==,$z,zf,:=,%d,$s,nf,:=,"
			"%s,%s,==,%d,$b,cf,%s,%s,^,!,&,|,"
			"%d,%s,%s,^,%s,%s,^,&,>>,vf,:=,"
			"cf,%s,-1,^,+,%s,+,%s,=,cf,:=",
			sum, bits - 1,
			rn, sum, bits, rn, sum,
			bits - 1, rm, rn, sum, rn,
			rm, rn, REG64 (0));
		break;
	}
	case ARM64_INS_SMULL2:
	case ARM64_INS_SMULL:
		OPCALL_SIGN ("*", REGBITS64 (1));
		break;
	case ARM64_INS_UMULL2:
	case ARM64_INS_UMULL:
	case ARM64_INS_MUL:
		OPCALL ("*");
		break;
	case ARM64_INS_UMULH:
		r_strbuf_setf (&op->esil, "%s,%s,L*,SWAP,%s,=",
			REG64 (2), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_SMULH:
		// the unsigned high half, corrected by the sign of each source
		r_strbuf_setf (&op->esil, "63,%s,>>,%s,*,63,%s,>>,%s,*,+,%s,%s,L*,POP,-,%s,=",
			REG64 (1), REG64 (2), REG64 (2), REG64 (1), REG64 (2), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_AND:
		OPCALL ("&");
		break;
	case ARM64_INS_ORR:
		OPCALL ("|");
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_NAND:
		OPCALL_NEG ("&");
		break;
	case ARM64_INS_ADDS:
		OPCALL_FLAGS ("+", 'a');
		break;
	case ARM64_INS_ADCS: {
		const int bits = REGBITS64 (0);
		char sum[64];
		if (bits == 32) {
			snprintf (sum, sizeof (sum), "0xffffffff,cf,%s,+,%s,+,&", REG64 (2), REG64 (1));
		} else {
			snprintf (sum, sizeof (sum), "cf,%s,+,%s,+", REG64 (2), REG64 (1));
		}
		// C=(r<a)|(cf&(r==a)) and V=(~(a^b)&(a^r))>>msb; the new carry stays on the stack until the sum stored below has read the old cf
		r_strbuf_setf (&op->esil,
			"0,%s,==,$z,zf,:=,%d,$s,nf,:=,"
			"%s,%s,==,%d,$b,cf,%s,%s,^,!,&,|,"
			"%d,%s,%s,^,-1,^,%s,%s,^,&,>>,vf,:=,"
			"cf,%s,+,%s,+,%s,=,cf,:=",
			sum, bits - 1,
			REG64 (1), sum, bits, REG64 (1), sum,
			bits - 1, REG64 (2), REG64 (1), sum, REG64 (1),
			REG64 (2), REG64 (1), REG64 (0));
		break;
	}
	case ARM64_INS_SUBS:
		OPCALL_FLAGS ("-", 's');
		break;
	case ARM64_INS_ANDS:
		OPCALL_FLAGS ("&", 'l');
		break;
	case ARM64_INS_BICS:
	case ARM64_INS_NANDS:
		OPCALL_NEG_FLAGS ("&", 'l');
		break;
	case ARM64_INS_ORRS:
		OPCALL_FLAGS ("|", 'l');
		break;
	case ARM64_INS_EORS:
		OPCALL_FLAGS ("^", 'l');
		break;
	case ARM64_INS_ORNS:
		OPCALL_NEG_FLAGS ("|", 'l');
		break;
#endif
	case ARM64_INS_EOR:
		OPCALL ("^");
		break;
	case ARM64_INS_ORN:
		OPCALL_NEG ("|");
		break;
	case ARM64_INS_EON:
		OPCALL_NEG ("^");
		break;
	case ARM64_INS_LSR:
	{
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);
		const int size = REGSIZE64 (0)*8;

		if (ISREG64(2)) {
			if (LSHIFT2_64 (2) || EXT64 (2)) {
				ARG64_APPEND (&op->esil, 2);
				r_strbuf_appendf (&op->esil, ",%d,%%,%s,>>,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64 (2);
				r_strbuf_setf (&op->esil, "%d,%s,%%,%s,>>,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = IMM64 (2);
			r_strbuf_setf (&op->esil, "%"PFMT64d",%s,>>,%s,=", i2 % (ut64)size, r1, r0);
		}
		//OPCALL (">>");
		break;
	}
	case ARM64_INS_LSL:
	{
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);
		const int size = REGSIZE64 (0)*8;

		if (ISREG64 (2)) {
			if (LSHIFT2_64 (2) || EXT64 (2)) {
				ARG64_APPEND (&op->esil, 2);
				r_strbuf_appendf (&op->esil, ",%d,%%,%s,<<,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64 (2);
				r_strbuf_setf (&op->esil, "%d,%s,%%,%s,<<,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = IMM64 (2);
			r_strbuf_setf (&op->esil, "%"PFMT64d",%s,<<,%s,=", i2 % (ut64)size, r1, r0);
		}
		//OPCALL ("<<");
		break;
	}
	case ARM64_INS_ROR:
		OPCALL ("ROR");
		break;
	case ARM64_INS_NOP:
		r_strbuf_set (&op->esil, ",");
		break;
	case ARM64_INS_MOV:
	case ARM64_INS_FMOV:
	{
		cs_arm64_op dst = INSOP64 (0);
		cs_arm64_op src = INSOP64 (1);

		if (dst.vas && src.vas && dst.vector_index == -1 && src.vector_index == -1) {
			r_strbuf_setf (&op->esil, "%sh,%sh,=,%sl,%sl,=",
				REG64 (1), REG64 (0), REG64 (1), REG64 (0));
		} else if (!is_vector_op (&dst) && is_vector_op (&src) && src.vector_index != -1) {
			// umov of a d lane to an x register is renamed to MOV by Capstone
			arm64_esil_vec_umov (op, handle, insn, false);
		} else if (is_vector_op (&dst) && is_vector_op (&src) && dst.vector_index == -1) {
			// mov Vd.T, Vn.T[i] is the DUP (general) alias
			arm64_esil_vec_dup (op, handle, insn);
		} else {
			// lane insert; the src lane comes from its vector_index when the
			// source is a vector (ins/mov v0.s[1], v1.s[2] arrives as MOV)
			ARG64_APPEND (&op->esil, 1);
			r_strbuf_append (&op->esil, ",");
			VEC64_DST_APPEND (&op->esil, 0, -1);
			r_strbuf_append (&op->esil, ",=");
		}
		break;
	}
	case ARM64_INS_FCMP:
	case ARM64_INS_FCMPE:
	case ARM64_INS_FCCMP:
	case ARM64_INS_FCCMPE:
		// setf would wipe the cond guard emitted before the switch
		if (ISREG64 (1)) {
			// an unordered compare sets NZCV=0011, so vf feeds cf
			r_strbuf_appendf (&op->esil,
				"%d,%s,F2D,NAN,%d,%s,F2D,NAN,|,vf,:="
				",%d,%s,F2D,%d,%s,F2D,F==,zf,:="
				",%d,%s,F2D,%d,%s,F2D,F<,nf,:="
				",nf,!,vf,|,cf,:=",
				REGBITS64 (1), REG64 (1), REGBITS64 (1), REG64 (0),
				REGBITS64 (1), REG64 (1), REGBITS64 (1), REG64 (0),
				REGBITS64 (1), REG64 (1), REGBITS64 (1), REG64 (0)
			);
		} else {
			// operand 1 is an fp immediate, width comes from op 0
			r_strbuf_appendf (&op->esil,
				"%d,%s,F2D,NAN,vf,:="
				",0,I2D,%d,%s,F2D,F==,zf,:="
				",0,I2D,%d,%s,F2D,F<,nf,:="
				",nf,!,vf,|,cf,:=",
				REGBITS64 (0), REG64 (0),
				REGBITS64 (0), REG64 (0),
				REGBITS64 (0), REG64 (0)
			);
		}

		// an AL cond opens no ?{, so there is no else arm
		if (*postfix && (insn->id == ARM64_INS_FCCMP || insn->id == ARM64_INS_FCCMPE)) {
			r_strbuf_appendf (&op->esil, ",}{,pstate,1,28,1,<<,-,&,0x%"PFMT64x",|,pstate,:=", IMM64 (2) << 28);
		}
		break;
	case ARM64_INS_FCVTN:
	case ARM64_INS_FCVTN2:
	case ARM64_INS_FCVTL:
	case ARM64_INS_FCVTL2:
		arm64_esil_vec_fcvtnl (op, handle, insn);
		break;
	case ARM64_INS_CMEQ:
	case ARM64_INS_CMGE:
	case ARM64_INS_CMGT:
	case ARM64_INS_CMHI:
	case ARM64_INS_CMHS:
	case ARM64_INS_CMLE:
	case ARM64_INS_CMLT:
	case ARM64_INS_CMTST:
		// cmle/cmlt only have the zero forms, cmtst only the register form
		if (insn->detail->arm64.op_count > 2 && is_vector_op (&INSOP64 (0))
			&& is_vector_op (&INSOP64 (1)) && is_vector_op (&INSOP64 (2))) {
			arm64_esil_vec_cmpreg (op, handle, insn);
		} else if (insn->detail->arm64.op_count > 2 && is_vector_op (&INSOP64 (0))
			&& is_vector_op (&INSOP64 (1)) && ISIMM64 (2) && !IMM64 (2)) {
			arm64_esil_vec_cmpzero (op, handle, insn);
		}
		break;
	case ARM64_INS_FCMEQ:
	case ARM64_INS_FCMGE:
	case ARM64_INS_FCMGT:
	case ARM64_INS_FCMLE:
	case ARM64_INS_FCMLT:
	{
		cs_arm64_op src = INSOP64 (1);
		int esize = is_vector_op (&src)? vector_size (&src): REGSIZE64 (1) * 8;
		if (insn->detail->arm64.op_count > 2 && ISREG64 (0) && ISREG64 (1)
			&& ISREG64 (2) && (esize == 32 || esize == 64)) {
			arm64_esil_vec_cmpreg (op, handle, insn);
		} else if (insn->detail->arm64.op_count > 2 && ISREG64 (0) && ISREG64 (1)
			&& ISIMM64 (2) && !IMM64 (2) && (esize == 32 || esize == 64)) {
			arm64_esil_vec_cmpzero (op, handle, insn);
		}
		break;
	}
	case ARM64_INS_FCVT:
		r_strbuf_setf (&op->esil, "%d,%d,%s,F2D,D2F,%s,=",
			REGBITS64 (0), REGBITS64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_SCVTF:
	{
		cs_arm64_op src = INSOP64 (1);
		if (is_vector_op (&src)) {
			int scale = insn->detail->arm64.op_count > 2? (int)IMM64 (2): 0;
			arm64_esil_vec_unary (op, handle, insn, scale);
			break;
		}
		r_strbuf_setf (&op->esil, "%d,", REGBITS64 (0));
		ARG64_SIGN_APPEND (&op->esil, 1, REGBITS64 (1));
		r_strbuf_append (&op->esil, ",I2D,D2F,");
		VEC64_DST_APPEND (&op->esil, 0, -1);
		r_strbuf_append (&op->esil, ",=");
		break;
	}
	case ARM64_INS_UCVTF:
	{
		cs_arm64_op src = INSOP64 (1);
		if (is_vector_op (&src)) {
			int scale = insn->detail->arm64.op_count > 2? (int)IMM64 (2): 0;
			arm64_esil_vec_unary (op, handle, insn, scale);
			break;
		}
		r_strbuf_setf (&op->esil, "%d,", REGBITS64 (0));
		ARG64_APPEND (&op->esil, 1);
		r_strbuf_append (&op->esil, ",U2D,D2F,");
		VEC64_DST_APPEND (&op->esil, 0, -1);
		r_strbuf_append (&op->esil, ",=");
		break;
	}
	case ARM64_INS_FCVTAU:
	case ARM64_INS_FCVTAS:
	case ARM64_INS_FCVTMU:
	case ARM64_INS_FCVTMS:
	case ARM64_INS_FCVTNU:
	case ARM64_INS_FCVTNS:
	case ARM64_INS_FCVTPU:
	case ARM64_INS_FCVTPS:
	case ARM64_INS_FCVTZU:
	case ARM64_INS_FCVTZS:
	{
		cs_arm64_op src = INSOP64 (1);
		if ((insn->id == ARM64_INS_FCVTZU || insn->id == ARM64_INS_FCVTZS)
			&& is_vector_op (&src)) {
			int scale = insn->detail->arm64.op_count > 2? (int)IMM64 (2): 0;
			arm64_esil_vec_unary (op, handle, insn, scale);
			break;
		}
		// TODO: unsigned int won't be right, idk entirely what it even means
		// also the rounding mode... idk i hate floats
		r_strbuf_setf (&op->esil, "%d,", REGBITS64 (1));
		ARG64_APPEND (&op->esil, 1);
		r_strbuf_append (&op->esil, ",F2D,D2I,");
		VEC64_DST_APPEND (&op->esil, 0, -1);
		r_strbuf_append (&op->esil, ",=");
		break;
	}
	case ARM64_INS_FRINTA:
	case ARM64_INS_FRINTI:
	case ARM64_INS_FRINTN:
	case ARM64_INS_FRINTX:
	case ARM64_INS_FRINTZ:
	case ARM64_INS_FRINTP:
	case ARM64_INS_FRINTM:
	{
		cs_arm64_op src = INSOP64 (1);
		if (is_vector_op (&src)) {
			arm64_esil_vec_unary (op, handle, insn, 0);
			break;
		}
		char* rounder = "ROUND";
		if (insn->id == ARM64_INS_FRINTM) {
			rounder = "FLOOR";
		} else if (insn->id == ARM64_INS_FRINTP || insn->id == ARM64_INS_FRINTA) {
			rounder = "CEIL";
		}
		r_strbuf_setf (&op->esil, "%d,DUP,", REGBITS64 (1));
		ARG64_APPEND (&op->esil, 1);
		r_strbuf_appendf (&op->esil, ",F2D,%s,D2F,", rounder);
		VEC64_DST_APPEND (&op->esil, 0, -1);
		r_strbuf_append (&op->esil, ",=");
		break;
	}
	case ARM64_INS_FABS:
	{
		cs_arm64_op src = INSOP64 (1);
		if (is_vector_op (&src)) {
			arm64_esil_vec_unary (op, handle, insn, 0);
			break;
		}
		// F< compares top<second, so swap to test val<0
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,DUP,0,I2D,SWAP,F<,?{,-F,},D2F,%s,=",
			REGBITS64 (1), REG64 (1), REG64 (0));
		break;
	}
	case ARM64_INS_FNEG:
	{
		cs_arm64_op src = INSOP64 (1);
		if (is_vector_op (&src)) {
			arm64_esil_vec_unary (op, handle, insn, 0);
			break;
		}
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,-F,D2F,%s,=",
			REGBITS64 (1), REG64 (1), REG64 (0));
		break;
	}
	case ARM64_INS_FMIN:
	case ARM64_INS_FMAX:
	case ARM64_INS_FMINNM:
	case ARM64_INS_FMAXNM:
	{
		cs_arm64_op src = INSOP64 (1);
		int esize = is_vector_op (&src)? vector_size (&src): REGSIZE64 (1) * 8;
		if (insn->detail->arm64.op_count > 2 && ISREG64 (0) && ISREG64 (1)
			&& ISREG64 (2) && (esize == 32 || esize == 64)) {
			arm64_esil_vec_minmax (op, handle, insn);
		}
		break;
	}
	case ARM64_INS_FMLA:
	case ARM64_INS_FMLS:
		arm64_esil_vec_fmac (op, handle, insn);
		break;
	case ARM64_INS_FMAXP:
	case ARM64_INS_FMINP:
	case ARM64_INS_FMAXNMP:
	case ARM64_INS_FMINNMP:
		arm64_esil_vec_minmaxp (op, handle, insn);
		break;
	case ARM64_INS_FSQRT:
		arm64_esil_vec_sqrt (op, handle, insn);
		break;
	case ARM64_INS_FRECPE:
	case ARM64_INS_FRSQRTE:
		arm64_esil_vec_est (op, handle, insn);
		break;
	case ARM64_INS_FRECPS:
	case ARM64_INS_FRSQRTS:
		arm64_esil_vec_fstep (op, handle, insn);
		break;
	case ARM64_INS_FMULX:
		arm64_esil_vec_fmulx (op, handle, insn);
		break;
	case ARM64_INS_FRECPX:
		arm64_esil_frecpx (op, handle, insn);
		break;
	case ARM64_INS_FADD:
		FPOPCALL ("+");
		break;
	case ARM64_INS_FSUB:
		FPOPCALL ("-");
		break;
	case ARM64_INS_FMUL:
		FPOPCALL ("*");
		break;
	case ARM64_INS_FNMUL:
		FPOPCALL_NEGATE ("*");
		break;
	case ARM64_INS_FMADD:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F*,%d,%s,F2D,F+,D2F,%s,=",
			REGBITS64 (1), REG64 (1),
			REGBITS64 (2), REG64 (2),
			REGBITS64 (3), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_FNMADD:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F*,-F,%d,%s,F2D,F+,-F,D2F,%s,=",
			REGBITS64 (1), REG64 (1),
			REGBITS64 (2), REG64 (2),
			REGBITS64 (3), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_FMSUB:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F*,%d,%s,F2D,F-,D2F,%s,=",
			REGBITS64 (1), REG64 (1),
			REGBITS64 (2), REG64 (2),
			REGBITS64 (3), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_FNMSUB:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F*,-F,%d,%s,F2D,F-,-F,D2F,%s,=",
			REGBITS64 (1), REG64 (1),
			REGBITS64 (2), REG64 (2),
			REGBITS64 (3), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_FDIV:
		FPOPCALL ("/");
		break;
	case ARM64_INS_SDIV:
		r_strbuf_setf (&op->esil, "%s,!,?{,0,%s,=,}{,", REG64 (2), REG64 (0));
		OPCALL_SIGN ("~/", REGBITS64 (1));
		r_strbuf_append (&op->esil, ",}");
		break;
	case ARM64_INS_UDIV:
		/* TODO: support WZR XZR to specify 32, 64bit op */
		// arm64 does not have a div-by-zero exception, just quietly sets R0 to 0
		r_strbuf_setf (&op->esil, "%s,!,?{,0,%s,=,}{,", REG64 (2), REG64 (0));
		OPCALL("/");
		r_strbuf_append (&op->esil, ",}");
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_BRAA:
	case ARM64_INS_BRAAZ:
	case ARM64_INS_BRAB:
	case ARM64_INS_BRABZ:
		r_strbuf_setf (&op->esil, "%s,pc,+,%s,+,pc,:=", REG64 (0), REG64(1));
		break;
#endif
	case ARM64_INS_BR:
		r_strbuf_setf (&op->esil, "%s,pc,:=", REG64 (0));
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_BC:
#endif
	case ARM64_INS_B:
		/* capstone precompute resulting address, using PC + IMM */
		r_strbuf_appendf (&op->esil, "%"PFMT64d",pc,:=", IMM64 (0));
		break;
	case ARM64_INS_BL:
		r_strbuf_setf (&op->esil, "pc,lr,:=,%"PFMT64d",pc,:=", IMM64 (0));
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_BLRAA:
	case ARM64_INS_BLRAAZ:
	case ARM64_INS_BLRAB:
	case ARM64_INS_BLRABZ:
#endif
	case ARM64_INS_BLR:
		r_strbuf_setf (&op->esil, "pc,lr,:=,%s,pc,:=", REG64 (0));
		break;
	case ARM64_INS_CLS:
	{
		cs_arm64_op src = INSOP64 (1);
		int bits = 8 * REGSIZE64 (0);
		if (is_vector_op (&src)) {
			arm64_esil_vec_unary (op, handle, insn, 0);
		} else {
			// count leading sign bits: flip negative values, then count the
			// leading zeros of the low bits-1 bits (the sign bit itself is
			// excluded); same trick as the CLS case
			r_strbuf_setf (&op->esil, "%d,%d,%s,>>,1,&,0,-,%s,^,0x%" PFMT64x ",&,CLZ,%s,=",
				bits - 1, bits - 1, REG64 (1), REG64 (1), bitmask_by_width[bits - 2], REG64 (0));
		}
		break;
	}
	case ARM64_INS_CLZ:
	{
		cs_arm64_op src = INSOP64 (1);
		if (is_vector_op (&src)) {
			arm64_esil_vec_unary (op, handle, insn, 0);
		} else {
			r_strbuf_setf (&op->esil, "%d,%s,CLZ,%s,=",
				8 * REGSIZE64 (0), REG64 (1), REG64 (0));
		}
		break;
	}
	case ARM64_INS_CNT:
	{
		cs_arm64_op src = INSOP64 (1);
		// scalar cnt is a base A64 instruction gated by FEAT_CSSC, which the
		// bundled capstone does not decode, so only the vector form lands here
		if (is_vector_op (&src)) {
			arm64_esil_vec_unary (op, handle, insn, 0);
		}
		break;
	}
	case ARM64_INS_LDRH:
	case ARM64_INS_LDUR:
	case ARM64_INS_LDURB:
	case ARM64_INS_LDURH:
	case ARM64_INS_LDR:
	case ARM64_INS_LDRB:
	case ARM64_INS_LDXR:
	case ARM64_INS_LDXRB:
	case ARM64_INS_LDXRH:
	case ARM64_INS_LDAXR:
	case ARM64_INS_LDAXRB:
	case ARM64_INS_LDAXRH:
	case ARM64_INS_LDAR:
	case ARM64_INS_LDARB:
	case ARM64_INS_LDARH:
	{
		int size = REGSIZE64 (0);
		switch (insn->id) {
		case ARM64_INS_LDRB:
		case ARM64_INS_LDARB:
		case ARM64_INS_LDAXRB:
		case ARM64_INS_LDXRB:
		case ARM64_INS_LDURB:
			size = 1;
			break;
		case ARM64_INS_LDRH:
		case ARM64_INS_LDARH:
		case ARM64_INS_LDXRH:
		case ARM64_INS_LDAXRH:
		case ARM64_INS_LDURH:
			size = 2;
			break;
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDURSW:
			size = 4;
			break;
		default:
			break;
		}
		op->ptrsize = size;
		if (ISMEM64 (1)) {
			if (HASMEMINDEX64 (1)) {
				if (LSHIFT2_64 (1) || EXT64 (1)) {
					ARG64_APPEND (&op->esil, 1);
					r_strbuf_appendf (&op->esil, ",%s,+,[%d],%s,=",
							MEMBASE64 (1), size, REG64 (0));
				} else {
					r_strbuf_appendf (&op->esil, "%s,%s,+,[%d],%s,=",
							MEMBASE64 (1), MEMINDEX64 (1), size, REG64 (0));
				}
			} else {
				if (LSHIFT2_64 (1)) {
					r_strbuf_appendf (&op->esil, "%s,%d,%"PFMT64d",%s,+",
							MEMBASE64 (1), LSHIFT2_64 (1), MEMDISP64 (1), DECODE_SHIFT64 (1));
				} else if ((int)MEMDISP64 (1) < 0) {
					r_strbuf_appendf (&op->esil, "%"PFMT64d",%s,-",
							-(st64)MEMDISP64 (1), MEMBASE64 (1));
				} else {
					r_strbuf_appendf (&op->esil, "%"PFMT64d",%s,+",
							MEMDISP64 (1), MEMBASE64 (1));
				}
				r_strbuf_append (&op->esil, ",DUP,tmp,=");

				// I assume the DUPs here previously were to handle preindexing
				// but it was never finished?
				if (ISPREINDEX64 ()) {
					r_strbuf_appendf (&op->esil, ",tmp,%s,=", REG64 (1));
				}

				r_strbuf_appendf (&op->esil, ",[%d],%s,=", size, REG64 (0));

				if (ISPOSTINDEX64 ()) {
					if (ISREG64 (2)) { // not sure if register valued post indexing exists?
						r_strbuf_appendf (&op->esil, ",tmp,%s,+,%s,=", REG64 (2), REG64 (1));
					} else {
						r_strbuf_appendf (&op->esil, ",tmp,%"PFMT64d",+,%s,=", IMM64 (2), REG64 (1));
					}
				}
			}
			op->refptr = 4;
		} else {
			if (ISREG64 (1)) {
				if (OPCOUNT64 () == 2) {
					r_strbuf_setf (&op->esil, "%s,[%d],%s,=",
						REG64 (1), size, REG64 (0));
				} else if (OPCOUNT64 () == 3) {
					/*
						This seems like a capstone bug:
						instructions like
							ldr x16, [x13, x9]
							ldrb w2, [x19, x23]
						are not detected as ARM64_OP_MEM type and
						fall in this case instead.
					*/
					if (ISREG64 (2)) {
						r_strbuf_setf (&op->esil, "%s,%s,+,[%d],%s,=",
							REG64 (1), REG64 (2), size, REG64 (0));
					}
				}
			} else {
				r_strbuf_setf (&op->esil, "%"PFMT64d",[%d],%s,=",
					IMM64 (1), size, REG64 (0));
			}
		}
		break;
	}
	case ARM64_INS_LDRSB:
	case ARM64_INS_LDRSH:
	case ARM64_INS_LDRSW:
	case ARM64_INS_LDURSB:
	case ARM64_INS_LDURSH:
	case ARM64_INS_LDURSW:
	{
		// handle the sign extended instrs here
		int size = 0;
		switch (insn->id) {
		case ARM64_INS_LDRSB:
		case ARM64_INS_LDURSB:
			size = 1;
			break;
		case ARM64_INS_LDRSH:
		case ARM64_INS_LDURSH:
			size = 2;
			break;
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDURSW:
			size = 4;
			break;
		default:
			size = REGSIZE64 (0);
			break;
		}
		op->ptrsize = size;
		if (ISMEM64 (1)) {
			if (HASMEMINDEX64 (1)) {
				if (LSHIFT2_64 (1) || EXT64 (1)) {
					r_strbuf_appendf (&op->esil, "%d,%s,", size*8, MEMBASE64 (1));
					ARG64_APPEND (&op->esil, 1);
					r_strbuf_appendf (&op->esil, ",+,[%d],~,%s,=", size, REG64 (0));
				} else {
					r_strbuf_appendf (&op->esil, "%d,%s,%s,+,[%d],~,%s,=",
							size*8, MEMBASE64 (1), MEMINDEX64 (1), size, REG64 (0));
				}
			} else {
				if (LSHIFT2_64 (1)) {
					r_strbuf_appendf (&op->esil, "%d,%s,%d,%"PFMT64d",%s",
							size*8, MEMBASE64 (1), LSHIFT2_64 (1), MEMDISP64 (1), DECODE_SHIFT64 (1));
				} else if ((int)MEMDISP64 (1) < 0) {
					r_strbuf_appendf (&op->esil, "%d,%"PFMT64d",%s,-",
							size*8, -(st64)MEMDISP64 (1), MEMBASE64 (1));
				} else {
					r_strbuf_appendf (&op->esil, "%d,%"PFMT64d",%s,+",
							size*8, MEMDISP64 (1), MEMBASE64 (1));
				}

				r_strbuf_append (&op->esil, ",DUP,tmp,=");

				// I assume the DUPs here previously were to handle preindexing
				// but it was never finished?
				if (ISPREINDEX64 ()) {
					r_strbuf_appendf (&op->esil, ",tmp,%s,=", REG64 (1));
				}

				r_strbuf_appendf (&op->esil, ",[%d],~,%s,=", size, REG64 (0));

				if (ISPOSTINDEX64 ()) {
					if (ISREG64 (2)) { // not sure if register valued post indexing exists?
						r_strbuf_appendf (&op->esil, ",tmp,%s,+,%s,=", REG64 (2), REG64 (1));
					} else {
						r_strbuf_appendf (&op->esil, ",tmp,%"PFMT64d",+,%s,=", IMM64 (2), REG64 (1));
					}
				}
			}
			op->refptr = 4;
		} else {
			if (ISREG64 (1)) {
				if (OPCOUNT64 () == 2) {
					r_strbuf_setf (&op->esil, "%d,%s,[%d],~,%s,=",
						size * 8, REG64 (1), size, REG64 (0));
				} else if (OPCOUNT64 () == 3) {
					/*
						This seems like a capstone bug:
						instructions like
							ldr x16, [x13, x9]
							ldrb w2, [x19, x23]
						are not detected as ARM64_OP_MEM type and
						fall in this case instead.
					*/
					if (ISREG64 (2)) {
						r_strbuf_setf (&op->esil, "%d,%s,%s,+,[%d],~,%s,=",
							size * 8, REG64 (1), REG64 (2), size, REG64 (0));
					}
				}
			} else {
				r_strbuf_setf (&op->esil, "%d,%"PFMT64d",[%d],~,%s,=",
					size * 8, IMM64 (1), size, REG64 (0));
			}
		}
		break;
	}
	case ARM64_INS_CCMP:
	case ARM64_INS_CMP: // cmp w8, 0xd
		ARG64_APPEND (&op->esil, 1);
		COMMA (&op->esil);
		ARG64_APPEND (&op->esil, 0);
		r_strbuf_appendf (&op->esil, ",==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,",
			REGBITS64 (0) - 1, REGBITS64 (0), REGBITS64 (0) - 1);
		// $o after == is unsound for subtraction, V needs ((a^b)&(a^(a-b)))>>msb
		ARG64_APPEND (&op->esil, 1);
		COMMA (&op->esil);
		ARG64_APPEND (&op->esil, 0);
		r_strbuf_append (&op->esil, ",^,");
		ARG64_APPEND (&op->esil, 1);
		COMMA (&op->esil);
		ARG64_APPEND (&op->esil, 0);
		r_strbuf_append (&op->esil, ",-,");
		ARG64_APPEND (&op->esil, 0);
		r_strbuf_append (&op->esil, ",^,&,>>,vf,:=");

		// an AL cond opens no ?{, so there is no else arm
		if (*postfix && insn->id == ARM64_INS_CCMP) {
			r_strbuf_appendf (&op->esil, ",}{,pstate,1,28,1,<<,-,&,28,%"PFMT64d",<<,|,pstate,:=", IMM64 (2));
		}
		break;
	case ARM64_INS_CMN:
	case ARM64_INS_CCMN:
		// negate the src operand so old/cur describe the addition
		ARG64_APPEND (&op->esil, 1);
		r_strbuf_append (&op->esil, ",-1,*");
		COMMA (&op->esil);
		ARG64_APPEND (&op->esil, 0);
		r_strbuf_appendf (&op->esil, ",==,$z,zf,:=,%d,$s,nf,:=,%d,$c,cf,:=,%d,$o,vf,:=",
			REGBITS64 (0) - 1, REGBITS64 (0) - 1, REGBITS64 (0) - 1);

		// an AL cond opens no ?{, so there is no else arm
		if (*postfix && insn->id == ARM64_INS_CCMN) {
			r_strbuf_appendf (&op->esil, ",}{,pstate,1,28,1,<<,-,&,28,%"PFMT64d",<<,|,pstate,:=", IMM64 (2));
		}
		break;
	case ARM64_INS_TST: // tst w8, 0xd
		r_strbuf_append (&op->esil, "0,");
		ARG64_APPEND (&op->esil, 1);
		COMMA (&op->esil);
		ARG64_APPEND (&op->esil, 0);
		r_strbuf_appendf (&op->esil,
			",&,==" // (Wn & #imm) == 0
			// NZCV := result<datasize-1>:IsZeroBit(result):'00'
			",%d,$s,nf,:="
			",$z,zf,:="
			",0,cf,:="
			",0,vf,:=",
			REGBITS64 (0) - 1);
		break;
	case ARM64_INS_FCSEL:
	case ARM64_INS_CSEL: // csel Wd, Wn, Wm --> Wd := (cond) ? Wn : Wm
		arm64_esil_cond_select (op, postfix, REG64 (1), REG64 (2), REG64 (0));
		postfix = "";
		break;
	case ARM64_INS_CSET: // cset Wd --> Wd := (cond) ? 1 : 0
		arm64_esil_cond_select (op, postfix, "1", "0", REG64 (0));
		postfix = "";
		break;
	case ARM64_INS_CSETM: // csetm Wd --> Wd := (cond) ? -1 : 0
		arm64_esil_cond_select (op, postfix, REGBITS64 (0) == 32 ? "0xffffffff" : "-1", "0", REG64 (0));
		postfix = "";
		break;
	case ARM64_INS_CINC: // cinc Wd, Wn --> Wd := (cond) ? (Wn+1) : Wn
	case ARM64_INS_CINV: // cinv Wd, Wn --> Wd := (cond) ? NOT(Wn) : Wn
	case ARM64_INS_CNEG: // cneg Wd, Wn --> Wd := (cond) ? -Wn : Wn
		{
			char *alt = r_str_newf (arm64_esil_cond_alt (insn->id), REG64 (1));
			arm64_esil_cond_select (op, postfix, alt, REG64 (1), REG64 (0));
			free (alt);
		}
		postfix = "";
		break;
	case ARM64_INS_CSINC: // csinc Wd, Wn, Wm --> Wd := (cond) ? Wn : (Wm+1)
	case ARM64_INS_CSINV: // csinv Wd, Wn, Wm --> Wd := (cond) ? Wn : NOT(Wm)
	case ARM64_INS_CSNEG: // csneg Wd, Wn, Wm --> Wd := (cond) ? Wn : -Wm
		{
			char *alt = r_str_newf (arm64_esil_cond_alt (insn->id), REG64 (2));
			arm64_esil_cond_select (op, postfix, REG64 (1), alt, REG64 (0));
			free (alt);
		}
		postfix = "";
		break;
	case ARM64_INS_STXRB:
	case ARM64_INS_STXRH:
	case ARM64_INS_STXR:
	case ARM64_INS_STLXR:
	case ARM64_INS_STLXRH:
	case ARM64_INS_STLXRB:
	{
		int size = REGSIZE64 (1);
		switch (insn->id) {
			case ARM64_INS_STLXRB:
			case ARM64_INS_STXRB:
				size = 1;
				break;
			case ARM64_INS_STLXRH:
			case ARM64_INS_STXRH:
				size = 2;
				break;
			default:
				size = 8;
				break;
		}
		r_strbuf_setf (&op->esil, "0,%s,=,%s,%s,%"PFMT64d",+,=[%d]",
			REG64 (0), REG64 (1), MEMBASE64 (1), MEMDISP64 (1), size);
		break;
	}
	case ARM64_INS_STRB:
	case ARM64_INS_STRH:
	case ARM64_INS_STUR:
	case ARM64_INS_STURB:
	case ARM64_INS_STURH:
	case ARM64_INS_STR: // str x6, [x6,0xf90]
	{
		op->type = R_ANAL_OP_TYPE_STORE;
		int size = REGSIZE64 (0);
		if (insn->id == ARM64_INS_STRB || insn->id == ARM64_INS_STURB) {
			size = 1;
		} else if (insn->id == ARM64_INS_STRH || insn->id == ARM64_INS_STURH) {
			size = 2;
		}
		if (ISMEM64 (1)) {
			if (HASMEMINDEX64 (1)) {
				if (LSHIFT2_64 (1) || EXT64 (1)) {
					r_strbuf_appendf (&op->esil, "%s,%s,", REG64 (0), MEMBASE64 (1));
					ARG64_APPEND (&op->esil, 1);
					r_strbuf_appendf (&op->esil, ",+,=[%d]", size);
				} else {
					r_strbuf_appendf (&op->esil, "%s,%s,%s,+,=[%d]",
							REG64 (0), MEMBASE64 (1), MEMINDEX64 (1), size);
				}
			} else {
				if (LSHIFT2_64 (1)) {
					r_strbuf_appendf (&op->esil, "%s,%s,%d,%"PFMT64d",%s,+",
							REG64 (0), MEMBASE64 (1), LSHIFT2_64 (1), MEMDISP64 (1), DECODE_SHIFT64 (1));
				} else if ((int)MEMDISP64 (1) < 0) {
					r_strbuf_appendf (&op->esil, "%s,%"PFMT64d",%s,-",
							REG64 (0), -(st64)MEMDISP64 (1), MEMBASE64 (1));
				} else {
					r_strbuf_appendf (&op->esil, "%s,%"PFMT64d",%s,+",
							REG64 (0), MEMDISP64 (1), MEMBASE64 (1));
				}

				r_strbuf_append (&op->esil, ",DUP,tmp,=");

				// I assume the DUPs here previously were to handle preindexing
				// but it was never finished?
				if (ISPREINDEX64 ()) {
					r_strbuf_appendf (&op->esil, ",tmp,%s,=", REG64 (1));
				}

				r_strbuf_appendf (&op->esil, ",=[%d]", size);

				if (ISPOSTINDEX64 ()) {
					if (ISREG64 (2)) { // not sure if register valued post indexing exists?
						r_strbuf_appendf (&op->esil, ",tmp,%s,+,%s,=", REG64 (2), REG64 (1));
					} else {
						r_strbuf_appendf (&op->esil, ",tmp,%"PFMT64d",+,%s,=", IMM64 (2), REG64 (1));
					}
				}
			}
			op->refptr = 4;
			op->disp = MEMDISP64 (1);
		} else {
			if (ISREG64 (1)) {
				if (OPCOUNT64 () == 2) {
					r_strbuf_setf (&op->esil, "%s,%s,=[%d]",
						REG64 (0), REG64 (1), size);
				} else if (OPCOUNT64 () == 3) {
					/*
						This seems like a capstone bug:
						instructions like
							ldr x16, [x13, x9]
							ldrb w2, [x19, x23]
						are not detected as ARM64_OP_MEM type and
						fall in this case instead.
					*/
					if (ISREG64 (2)) {
						r_strbuf_setf (&op->esil, "%s,%s,%s,+,=[%d]",
							REG64 (0), REG64 (1), REG64 (2), size);
					}
				}
			} else {
				r_strbuf_setf (&op->esil, "%s,%"PFMT64d",=[%d]",
					REG64 (0), IMM64 (1), size);
			}
		}
		break;
	}
	case ARM64_INS_BIC:
		OPCALL_NEG ("&");
		break;
	case ARM64_INS_CBZ:
		r_strbuf_setf (&op->esil, "%s,!,?{,%"PFMT64d",pc,:=,}",
				REG64 (0), IMM64 (1));
		break;
	case ARM64_INS_CBNZ:
		r_strbuf_setf (&op->esil, "%s,?{,%"PFMT64d",pc,:=,}",
				REG64 (0), IMM64 (1));
		break;
	case ARM64_INS_TBZ:
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		r_strbuf_setf (&op->esil, "%" PFMT64d ",1,<<,%s,&,!,?{,%"PFMT64d",pc,:=,}",
				IMM64 (1), REG64 (0), IMM64 (2));
		break;
	case ARM64_INS_TBNZ:
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		r_strbuf_setf (&op->esil, "%" PFMT64d ",1,<<,%s,&,?{,%"PFMT64d",pc,:=,}",
				IMM64 (1), REG64 (0), IMM64 (2));
		break;
	case ARM64_INS_STNP:
	case ARM64_INS_STP: // stp x6, x7, [x6,0xf90]
	{
		int disp = (int)MEMDISP64 (2);
		op->disp = disp;
		char sign = (disp >= 0)?'+':'-';
		st64 abs = (disp >= 0)? MEMDISP64 (2): -(st64)MEMDISP64 (2);
		int size = REGSIZE64 (0);
		// Pre-index case
		if (ISPREINDEX64 ()) {
			// "stp x2, x3, [x8, 0x20]!
			// "32,x8,+=,x2,x8,=[8],x3,x8,8,+,=[8]",
			r_strbuf_setf (&op->esil,
					"%" PFMT64d ",%s,%c=,%s,%s,=[%d],%s,%s,%d,+,=[%d]",
					abs, MEMBASE64 (2), sign,
					REG64 (0), MEMBASE64 (2), size,
					REG64 (1), MEMBASE64 (2), size, size);
		// Post-index case
		} else if (ISPOSTINDEX64 ()) {
			int val = IMM64 (3);
			sign = (val >= 0)?'+':'-';
			abs = (val >= 0)? val: -val;
			// "stp x4, x5, [x8], 0x10"
			// "x4,x8,=[],x5,x8,8,+,=[],16,x8,+="
			r_strbuf_setf (&op->esil,
					"%s,%s,=[%d],%s,%s,%d,+,=[%d],%" PFMT64d ",%s,%c=",
					REG64 (0), MEMBASE64 (2), size,
					REG64 (1), MEMBASE64 (2), size, size,
					abs, MEMBASE64 (2), sign);
		// Everything else
		} else {
			r_strbuf_setf (&op->esil,
					"%s,%s,%"PFMT64d",%c,=[%d],"
					"%s,%s,%"PFMT64d",%c,%d,+,=[%d]",
					REG64 (0), MEMBASE64 (2), abs, sign, size,
					REG64 (1), MEMBASE64 (2), abs, sign, size, size);
		}
		break;
	}
	case ARM64_INS_LDP: // ldp x29, x30, [sp], 0x10
	case ARM64_INS_LDNP: // ldnp q0, q1, [x1] (relaxed non-temporal pair load)
	{
		const int disp = (int)MEMDISP64 (2);
		char sign = (disp >= 0)? '+': '-';
		ut64 abs = (ut64)((disp >= 0)? MEMDISP64 (2): (st64)(-disp));
		const int size = REGSIZE64 (0);
		// a writeback form is unpredictable when rt == rn, so it may write first
		if (ISPREINDEX64 ()) {
			// "ldp x0, x1, [x8, -0x10]!"
			// 16,x8,-=,x8,[8],x0,=,x8,8,+,[8],x1,=
			r_strbuf_setf (&op->esil,
					"%"PFMT64d",%s,%c=,"
					"%s,[%d],%s,=,"
					"%d,%s,+,[%d],%s,=",
					abs, MEMBASE64 (2), sign,
					MEMBASE64 (2), size, REG64 (0),
					size, MEMBASE64 (2), size, REG64 (1));
		} else if (ISPOSTINDEX64 ()) {
			int val = IMM64 (3);
			sign = (val >= 0)?'+':'-';
			abs = (val >= 0)? val: -val;
			// ldp x4, x5, [x8], -0x10
			// x8,[8],x4,=,x8,8,+,[8],x5,=,16,x8,+=
			r_strbuf_setf (&op->esil,
					"%s,[%d],%s,=,"
					"%s,%d,+,[%d],%s,=,"
					"%" PFMT64d ",%s,%c=",
					MEMBASE64 (2), size, REG64 (0),
					MEMBASE64 (2), size, size, REG64 (1),
					abs, MEMBASE64 (2), sign);
		} else {
			// both words are loaded first, so the base may be a destination
			r_strbuf_setf (&op->esil,
					"%"PFMT64d",%s,%c,[%d],"
					"%d,%"PFMT64d",%s,%c,+,[%d],"
					"%s,=,%s,=",
					abs, MEMBASE64 (2), sign, size,
					size, abs, MEMBASE64 (2), sign, size,
					REG64 (1), REG64 (0));
		}
		// scalar SIMD destinations zero the v bits above their width; the
		// zext pass only covers the first register operand
		int i;
		for (i = 0; i < 2; i++) {
			const char *rn = i? REG64 (1): REG64 (0);
			int n = atoi (rn + 1);
			if (rn[0] == 'd') {
				r_strbuf_appendf (&op->esil, ",0,v%dh,=", n);
			} else if (rn[0] == 's') {
				r_strbuf_appendf (&op->esil, ",0xffffffff,v%dl,&=,0,v%dh,=", n, n);
			}
		}
		break;
	}
	case ARM64_INS_ADRP:
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,=", IMM64 (1), REG64 (0));
		break;
	case ARM64_INS_EXTR:
		// (rn:rm) >> lsb: the high half shifts left by regsize - lsb
		r_strbuf_setf (&op->esil, "%" PFMT64d ",%s,>>,%d,%s,<<,|,%s,=",
			IMM64 (3), REG64 (2), (int)(REGBITS64 (1) - IMM64 (3)), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_SHL:
	case ARM64_INS_SSHR:
	case ARM64_INS_USHR:
	case ARM64_INS_SQSHLU:
	case ARM64_INS_SLI:
	case ARM64_INS_SRI:
	{
		cs_arm64_op src = INSOP64 (1);
		if (is_vector_op (&src) && is_vector_op (&INSOP64 (0)) && ISIMM64 (2)) {
			arm64_esil_vec_shift (op, handle, insn, IMM64 (2));
		}
		// SVE predicate forms and anything unexpected stay unemulated
		break;
	}
	case ARM64_INS_SSHL:
	case ARM64_INS_USHL:
	case ARM64_INS_SRSHL:
	case ARM64_INS_URSHL:
	case ARM64_INS_SQSHL:
	case ARM64_INS_UQSHL:
	case ARM64_INS_SQRSHL:
	case ARM64_INS_UQRSHL:
	{
		cs_arm64_op src = INSOP64 (1);
		if (is_vector_op (&src) && is_vector_op (&INSOP64 (0))
			&& is_vector_op (&INSOP64 (2)) && INSOP64 (1).vas == INSOP64 (2).vas) {
			arm64_esil_vec_shift_reg (op, handle, insn);
		}
		// SVE predicated forms stay unemulated
		break;
	}
	case ARM64_INS_SSHLL:
	case ARM64_INS_SSHLL2:
	case ARM64_INS_USHLL:
	case ARM64_INS_USHLL2:
	{
		cs_arm64_op dst = INSOP64 (0);
		if (is_vector_op (&dst) && is_vector_op (&INSOP64 (1)) && ISIMM64 (2)) {
			arm64_esil_vec_shll (op, handle, insn);
		}
		break;
	}
	case ARM64_INS_SHRN:
	case ARM64_INS_SHRN2:
	case ARM64_INS_RSHRN:
	case ARM64_INS_RSHRN2:
	case ARM64_INS_SQSHRN:
	case ARM64_INS_SQSHRN2:
	case ARM64_INS_SQRSHRN:
	case ARM64_INS_SQRSHRN2:
	case ARM64_INS_SQSHRUN:
	case ARM64_INS_SQSHRUN2:
	case ARM64_INS_SQRSHRUN:
	case ARM64_INS_SQRSHRUN2:
	{
		cs_arm64_op dst = INSOP64 (0);
		if (is_vector_op (&dst) && is_vector_op (&INSOP64 (1)) && ISIMM64 (2)
			&& vector_size (&INSOP64 (1)) == vector_size (&dst) * 2) {
			arm64_esil_vec_shrn (op, handle, insn);
		}
		break;
	}
	case ARM64_INS_LD1:
	case ARM64_INS_LD1R:
	case ARM64_INS_LD2:
	case ARM64_INS_LD2R:
	case ARM64_INS_LD3:
	case ARM64_INS_LD3R:
	case ARM64_INS_LD4:
	case ARM64_INS_LD4R:
	case ARM64_INS_ST1:
	case ARM64_INS_ST2:
	case ARM64_INS_ST3:
	case ARM64_INS_ST4:
		arm64_esil_vec_ldst (op, handle, insn);
		break;
	case ARM64_INS_DUP:
		arm64_esil_vec_dup (op, handle, insn);
		break;
	case ARM64_INS_UMOV:
		arm64_esil_vec_umov (op, handle, insn, false);
		break;
	case ARM64_INS_SMOV:
		arm64_esil_vec_umov (op, handle, insn, true);
		break;
	case ARM64_INS_MOVI:
	case ARM64_INS_MVNI:
		arm64_esil_vec_movi (op, handle, insn);
		break;
	case ARM64_INS_TBL:
		arm64_esil_vec_tbl (op, handle, insn, false);
		break;
	case ARM64_INS_TBX:
		arm64_esil_vec_tbl (op, handle, insn, true);
		break;
	case ARM64_INS_ADDV:
	case ARM64_INS_SMAXV:
	case ARM64_INS_SMINV:
	case ARM64_INS_UMAXV:
	case ARM64_INS_UMINV:
		arm64_esil_vec_reduceint (op, handle, insn);
		break;
	case ARM64_INS_FMAXV:
	case ARM64_INS_FMINV:
	case ARM64_INS_FMAXNMV:
	case ARM64_INS_FMINNMV:
		arm64_esil_vec_reducefp (op, handle, insn);
		break;
	case ARM64_INS_ADDP:
		arm64_esil_vec_pdp (op, handle, insn, false);
		break;
	case ARM64_INS_FADDP:
		arm64_esil_vec_pdp (op, handle, insn, true);
		break;
	case ARM64_INS_MLA:
		arm64_esil_vec_mac (op, handle, insn, false);
		break;
	case ARM64_INS_MLS:
		arm64_esil_vec_mac (op, handle, insn, true);
		break;
	case ARM64_INS_SMIN:
	case ARM64_INS_SMAX:
	case ARM64_INS_UMIN:
	case ARM64_INS_UMAX:
		arm64_esil_vec_minmax_int (op, handle, insn);
		break;
	case ARM64_INS_SABD:
	case ARM64_INS_UABD:
		arm64_esil_vec_absdiff (op, handle, insn);
		break;
	case ARM64_INS_SADDLP:
	case ARM64_INS_UADDLP:
	case ARM64_INS_SADALP:
	case ARM64_INS_UADALP:
		arm64_esil_vec_pwl (op, handle, insn);
		break;
	case ARM64_INS_RBIT:
	{
		cs_arm64_op src = INSOP64 (1);
		if (is_vector_op (&src)) {
			arm64_esil_vec_unary (op, handle, insn, 0);
		} else {
			// slightly shorter expression to reverse bits
			r_strbuf_setf (&op->esil, "0,tmp,=,0,DUP,DUP,DUP,%d,-,%s,>>,1,&,<<,tmp,+=,%d,-,?{,++,4,GOTO,},tmp,%s,=",
				REGBITS64 (1)-1, REG64 (1), REGBITS64 (1)-1, REG64 (0));
		}
		break;
	}
	case ARM64_INS_MVN:
	case ARM64_INS_MOVN:
	{
		cs_arm64_op dst = INSOP64 (0);
		cs_arm64_op src = INSOP64 (1);

		if (dst.vas && src.vas) {
			r_strbuf_setf (&op->esil, "%sh,-1,^,%sh,=,%sl,-1,^,%sl,=",
				REG64 (1), REG64 (0), REG64 (1), REG64 (0));
		} else {
			ARG64_APPEND (&op->esil, 1);
			r_strbuf_append (&op->esil, ",-1,^,");
			VEC64_DST_APPEND (&op->esil, 0, -1);
			r_strbuf_append (&op->esil, ",=");
		}
		break;
	}
	case ARM64_INS_MOVK: // movk w8, 0x1290
	{
		ut64 shift = LSHIFT2_64 (1);
		if (shift < 0) {
			shift = 0;
		} else if (shift > 48) {
			shift = 48;
		}
		ut64 shifted_imm = IMM64 (1) << shift;
		ut64 mask = ~(0xffffULL << shift);

		r_strbuf_setf (&op->esil, "0x%"PFMT64x",%s,&,%"PFMT64u",|,%s,=",
			mask,
			REG64 (0),
			shifted_imm,
			REG64 (0));

		break;
	}
	case ARM64_INS_MOVZ:
		r_strbuf_setf (&op->esil, "%"PFMT64u",%s,=",
			SHIFTED_IMM64 (1, REGSIZE64 (0)*8),
			REG64 (0));
		break;
	/* ASR, SXTB, SXTH and SXTW are alias for SBFM */
	case ARM64_INS_ASR:
	{
		//OPCALL (">>>>");
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);
		const int size = REGSIZE64 (0)*8;

		if (ISREG64 (2)) {
			if (LSHIFT2_64 (2)) {
				ARG64_APPEND (&op->esil, 2);
				r_strbuf_appendf (&op->esil, ",%d,%%,%s,ASR,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64 (2);
				r_strbuf_setf (&op->esil, "%d,%s,%%,%s,ASR,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = IMM64 (2);
			r_strbuf_setf (&op->esil, "%"PFMT64d",%s,ASR,%s,=", i2 % (ut64)size, r1, r0);
		}
		break;
	}
	case ARM64_INS_SXTB:
		if (arm64_reg_width(REGID64 (0)) == 32) {
			r_strbuf_setf (&op->esil, "0xffffffff,8,0xff,%s,&,~,&,%s,=",
				REG64 (1), REG64 (0));
		} else {
			r_strbuf_setf (&op->esil, "8,0xff,%s,&,~,%s,=",
				REG64 (1), REG64 (0));
		}
		break;
	case ARM64_INS_SXTH: /* halfword */
		if (arm64_reg_width(REGID64 (0)) == 32) {
			r_strbuf_setf (&op->esil, "0xffffffff,16,0xffff,%s,&,~,&,%s,=",
				REG64 (1), REG64 (0));
		} else {
			r_strbuf_setf (&op->esil, "16,0xffff,%s,&,~,%s,=",
				REG64 (1), REG64 (0));
		}
		break;
	case ARM64_INS_SXTW: /* word */
		r_strbuf_setf (&op->esil, "32,0xffffffff,%s,&,~,%s,=",
				REG64 (1), REG64 (0));
		break;
	case ARM64_INS_UXTB:
		r_strbuf_setf (&op->esil, "%s,0xff,&,%s,=", REG64 (1), REG64 (0));
		break;
	case ARM64_INS_UXTH:
		r_strbuf_setf (&op->esil, "%s,0xffff,&,%s,=", REG64 (1), REG64 (0));
		break;
	case ARM64_INS_MRS:
		{
			const char *sr = arm64_profile_sysreg (insn, 1);
			if (sr && !strcmp (sr, "nzcv")) {
				r_strbuf_setf (&op->esil, "pstate,0xf0000000,&,%s,=", REG64 (0));
			} else if (sr) {
				r_strbuf_setf (&op->esil, "%s,%s,=", sr, REG64 (0));
			}
		}
		break;
	case ARM64_INS_MSR:
		{
			const char *sr = arm64_profile_sysreg (insn, 0);
			if (sr && !strcmp (sr, "nzcv")) {
				r_strbuf_setf (&op->esil, "%s,0xf0000000,&,pstate,0x0fffffff,&,|,pstate,=", REG64 (1));
			} else if (sr) {
				r_strbuf_setf (&op->esil, "%s,%s,=", REG64 (1), sr);
			}
		}
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_RETAA:
	case ARM64_INS_RETAB:
	case ARM64_INS_ERETAA:
	case ARM64_INS_ERETAB:
#endif
	case ARM64_INS_RET:
		// ret xN returns to xN; a plain ret has no operand and returns to lr
		if (OPCOUNT64 () > 0 && ISREG64 (0)) {
			r_strbuf_setf (&op->esil, "%s,pc,:=", REG64 (0));
		} else {
			r_strbuf_set (&op->esil, "lr,pc,:=");
		}
		break;
	case ARM64_INS_ERET:
		r_strbuf_set (&op->esil, "lr,pc,:=");
		break;
	case ARM64_INS_BFXIL:
		if (OPCOUNT64 () >= 3 && ISIMM64 (3) && IMM64 (3) > 0) {
			const ut64 mask = r_num_bitmask (IMM64 (3));
			r_strbuf_setf (&op->esil, "0x%"PFMT64x",%s,&,0x%"PFMT64x",%"PFMT64u",%s,>>,&,|,%s,=",
				~mask, REG64 (0), mask, IMM64 (2), REG64 (1), REG64 (0));
		}
		break;
	case ARM64_INS_BFI: // bfi w8, w8, 2, 1
	{
		if (OPCOUNT64 () >= 3 && ISIMM64 (3) && IMM64 (3) > 0) {
			size_t index = IMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			ut64 mask = bitmask_by_width[index];
			ut64 shift = IMM64 (2);
			ut64 notmask = ~(mask << shift);
			// notmask,dst,&,lsb,mask,src,&,<<,|,dst,=
			r_strbuf_setf (&op->esil, "%"PFMT64u",%s,&,%"PFMT64u",%"PFMT64u",%s,&,<<,|,%s,=",
				notmask, REG64 (0), shift, mask, REG64 (1), REG64 (0));
		}
		break;
	}
	case ARM64_INS_SBFIZ:
		if (IMM64 (3) > 0 && IMM64 (3) <= 64 - IMM64 (2)) {
			size_t index = IMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%" PFMT64d ",%" PFMT64d ",%s,%"PFMT64u",&,~,<<,%s,=",
					IMM64 (2), IMM64 (3), REG64 (1), (ut64)bitmask_by_width[index], REG64 (0));
		}
		break;
	case ARM64_INS_UBFIZ:
		if (IMM64 (3) > 0 && IMM64 (3) <= 64 - IMM64 (2)) {
			size_t index = IMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%" PFMT64d ",%s,%"PFMT64u",&,<<,%s,=",
					IMM64 (2), REG64 (1), (ut64)bitmask_by_width[index], REG64 (0));
		}
		break;
	case ARM64_INS_SBFX:
		if (IMM64 (3) > 0 && IMM64 (3) <= 64 - IMM64 (2)) {
			size_t index = IMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%" PFMT64d ",%" PFMT64d ",%s,%" PFMT64d ",%"PFMT64u",<<,&,>>,~,%s,=",
				IMM64 (3), IMM64 (2), REG64 (1), IMM64 (2) , (ut64)bitmask_by_width[index], REG64 (0));
		}
		break;
	case ARM64_INS_UBFX:
		if (IMM64 (3) > 0 && IMM64 (3) <= 64 - IMM64 (2)) {
			size_t index = IMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%" PFMT64d ",%s,%" PFMT64d ",%"PFMT64u",<<,&,>>,%s,=",
				IMM64 (2), REG64 (1), IMM64 (2) , (ut64)bitmask_by_width[index], REG64 (0));
		}
		break;
	case ARM64_INS_NEG:
	case ARM64_INS_NEGS:
		if (insn->id == ARM64_INS_NEGS) {
			ARG64_APPEND (&op->esil, 1);
			r_strbuf_appendf (&op->esil, ",0,==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,",
				REGBITS64 (0) - 1, REGBITS64 (0), REGBITS64 (0) - 1);
			// V = (b & -b) >> msb, only INT_MIN overflows on negation
			ARG64_APPEND (&op->esil, 1);
			COMMA (&op->esil);
			ARG64_APPEND (&op->esil, 1);
			r_strbuf_append (&op->esil, ",0,-,&,>>,vf,:=,");
		}
		ARG64_APPEND (&op->esil, 1);
		r_strbuf_appendf (&op->esil, ",0,-,%s,=", REG64 (0));
		break;
	case ARM64_INS_SVC:
		r_strbuf_setf (&op->esil, "%" PFMT64u ",$", IMM64 (0));
		break;
	}

	arm64_esil_zext_wregs (op);
	arm64_esil_zext_vupper (op, handle, insn);
	r_strbuf_append (&op->esil, postfix);

	return 0;
}

#define MATH32(opchar) arm32math(as, op, addr, buf, len, handle, insn, pcdelta, str, opchar, 0)
#define MATH32_NEG(opchar) arm32math(as, op, addr, buf, len, handle, insn, pcdelta, str, opchar, 1)
#define MATH32AS(opchar) arm32mathaddsub(as, op, addr, buf, len, handle, insn, pcdelta, str, opchar)

// adc = rn + op2 + c, sbc = rn + ~op2 + c, rsc = op2 + ~rn + c
static void arm32carry(RArchSession *as, RAnalOp *op, csh *handle, cs_insn *insn, RStringShort str[32]) {
	const bool three = OPCOUNT () > 2;
	const char *rn = three? ARG (1): ARG (0);
	const char *op2 = three? ARG (2): ARG (1);
	const bool rev = insn->id == ARM_INS_RSC;
	const char *comp = (insn->id == ARM_INS_ADC)? "": ",0xffffffff,^";
	char sh[80];
	if (OPCOUNT () > 3) { // the modified-immediate form carries its own rotate
		snprintf (sh, sizeof (sh), "%s,%s,ROR", ARG (3), op2);
		op2 = sh;
	}
	r_strbuf_appendf (&op->esil, "cf,%s%s,+,%s,+,0xffffffff,&,%s,=",
		rev? rn: op2, comp, rev? op2: rn, ARG (0));
}

static void arm32math(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len,
	csh *handle, cs_insn *insn, int pcdelta, RStringShort str[32], const char *opchar, int negate) {
	const char *dest = ARG(0);
	const char *op1;
	const char *op2;
	bool rotate_imm = OPCOUNT() > 3;
	if (OPCOUNT() > 2) {
		op1 = ARG(1);
		op2 = ARG(2);
	} else {
		op1 = dest;
		op2 = ARG(1);
	}
	// right operand
	if (rotate_imm) {
		r_strbuf_appendf (&op->esil, "%s,", ARG(3));
	}
	if (!strcmp (op2, "pc")) {
		r_strbuf_appendf (&op->esil, "0x%"PFMT64x, addr + pcdelta);
	} else {
		r_strbuf_append (&op->esil, op2);
	}
	if (rotate_imm) {
		r_strbuf_append (&op->esil, ",ROR");
	}
	if (negate) {
		r_strbuf_append (&op->esil, ",-1,^");
	}
	if (!strcmp (op1, "pc")) {
		r_strbuf_appendf (&op->esil, ",0x%"PFMT64x",%s,0xffffffff,&,%s,=", addr + pcdelta, opchar, dest);
	} else {
		if (ISSHIFTED(1)) {
			r_strbuf_appendf (&op->esil, ",0xffffffff,&,%s,=", dest);
		} else {
			r_strbuf_appendf (&op->esil, ",%s,%s,0xffffffff,&,%s,=", op1, opchar, dest);
		}
	}
}

// a register shift count is Rs[7:0] and saturates, unlike the esil shift ops
static bool arm32shiftreg(RArchSession *as, RAnalOp *op, csh *handle, cs_insn *insn, RStringShort str[32]) {
	const bool three = OPCOUNT () > 2;
	const int ci = three? 2: 1;
	// the two-operand form is thumb's, where the destination is also the source
	if (!ISREG (ci) || ISSHIFTED (ci)) {
		return false;
	}
	const char *src = three? ARG (1): ARG (0);
	const char *cnt = ARG (ci);
	const char *cf, *res;
	switch (insn->id) {
	case ARM_INS_LSL:
		cf = "0xff,%s,&,!,!,?{,1,0xff,%s,&,32,-,%s,>>,&,cf,:=,},";
		// a count of 32 or more shifts every bit out
		res = "0xff,%s,&,DUP,5,SWAP,>>,!,SWAP,0x1f,&,%s,<<,0xffffffff,&,*,%s,=";
		break;
	case ARM_INS_LSR:
		cf = "0xff,%s,&,!,!,?{,1,1,0xff,%s,&,-,%s,>>,&,cf,:=,},";
		res = "0xff,%s,&,%s,>>,0xffffffff,&,%s,=";
		break;
	case ARM_INS_ASR:
		cf = "0xff,%s,&,!,!,?{,1,1,0xff,%s,&,-,%s,ASR,&,cf,:=,},";
		res = "0xff,%s,&,%s,ASR,%s,=";
		break;
	default:
		cf = "0xff,%s,&,!,!,?{,1,0x1f,1,0xff,%s,&,-,&,%s,>>,&,cf,:=,},";
		res = "0xff,%s,&,%s,ROR,0xffffffff,&,%s,=";
		break;
	}
	if (insn->detail->arm.update_flags) {
		r_strbuf_appendf (&op->esil, cf, cnt, cnt, src);
	}
	r_strbuf_appendf (&op->esil, res, cnt, src, ARG (0));
	return true;
}

static void arm32mathaddsub(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len,
	csh *handle, cs_insn *insn, int pcdelta, RStringShort str[32], const char *opchar) {
	const char *dst = ARG (0);
	const char *src;
	bool noflags = false;
	if (!strcmp (dst, "pc")) {	//this is because strbuf_prepend doesn't exist and E_TOO_LAZY
		//		r_strbuf_append (&op->esil, "$$,pc,:=,");
		noflags = true;
	}
	if (OPCOUNT () == 3) {
		r_strbuf_appendf (&op->esil, "%s,0xffffffff,&,%s,=,", ARG (1), dst);
		src = ARG (2);
	} else {
		//		src = (!strcmp (ARG(1), "pc"))? "$$": ARG(1);
		src = ARG (1);
	}
	r_strbuf_appendf (&op->esil, "%s,%s,%s,0xffffffff,&,%s,=", src, dst, opchar, dst);
	if (noflags) {
		return;
	}
	r_strbuf_appendf (&op->esil, ",$z,zf,:=,%s,cf,:=,vf,=,0,nf,=",
		(!strcmp (opchar, "+")? "30,$c,31,$c,^,31,$c": "30,$c,31,$c,^,32,$b"));
}

static int analop_esil(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, bool thumb) {
	int i;
	const char *postfix = NULL;
	RStringShort str[32] = {{0}};
	int msr_flags;
	int pcdelta = (thumb? 4: 8);
	const char *ldext = "0xffffffff,&";
	int ldsz = 4;
	int str_ldr_bytes = 4;
	unsigned int width = 0;

	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");
	postfix = arm_prefix_cond (op, insn->detail->arm.cc);

	switch (insn->id) {
	case ARM_INS_CLZ:
		r_strbuf_appendf (&op->esil, "32,%s,CLZ,%s,=", REG (1), REG (0));
		break;
	case ARM_INS_IT:
		r_strbuf_appendf (&op->esil, "0x%"PFMT64x",pc,:=", addr + 2);
		break;
	case ARM_INS_BKPT:
		r_strbuf_setf (&op->esil, "%d,%d,TRAP", IMM (0), IMM (0));
		break;
	case ARM_INS_NOP:
		r_strbuf_set (&op->esil, ",");
		break;
	case ARM_INS_BL:
	case ARM_INS_BLX:
		r_strbuf_append (&op->esil, "pc,lr,:=,");
		/* fallthrough */
	case ARM_INS_BX:
	case ARM_INS_BXJ:
	case ARM_INS_B:
		if (ISREG (0) && REGID (0) == ARM_REG_PC) {
			r_strbuf_appendf (&op->esil, "0x%" PFMT64x ",pc,:=",
				(ut64)((addr & ~3LL) + pcdelta));
		} else {
			if (ISIMM (0)) {
				r_strbuf_appendf (&op->esil, "%s,pc,:=", ARG (0));
			} else {
				r_strbuf_appendf (&op->esil, "%d,%s,-,pc,:=", thumb, ARG (0));
			}
		}
		break;
	case ARM_INS_UDF:
		r_strbuf_setf (&op->esil, "%s,TRAP", ARG (0));
		break;
	case ARM_INS_SADD16:
	case ARM_INS_SADD8:
		MATH32AS ("+");
		break;
	case ARM_INS_ADDW:
	case ARM_INS_ADD:
		MATH32 ("+");
		break;
	case ARM_INS_ADC:
	case ARM_INS_SBC:
	case ARM_INS_RSC:
		arm32carry (as, op, handle, insn, str);
		break;
	case ARM_INS_SSUB16:
	case ARM_INS_SSUB8:
		MATH32AS ("-");
		break;
	case ARM_INS_SUBW:
	case ARM_INS_SUB:
		MATH32 ("-");
		break;
	case ARM_INS_MUL:
		MATH32 ("*");
		break;
	case ARM_INS_AND:
		MATH32 ("&");
		break;
	case ARM_INS_ORR:
		MATH32 ("|");
		break;
	case ARM_INS_EOR:
		MATH32 ("^");
		break;
	case ARM_INS_ORN:
		MATH32_NEG ("|");
		break;
	case ARM_INS_LSR:
		if (arm32shiftreg (as, op, handle, insn, str)) {
			break;
		}
		if (insn->detail->arm.update_flags) {
			if (OPCOUNT () == 2 && ISSHIFTED (1)) {
				r_strbuf_appendf (&op->esil, "%s,1,%u,-,0x1,<<,&,!,!,cf,:=,", REG (1), LSHIFT2 (1));
			} else if (OPCOUNT () == 2) {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},", ARG (1), ARG (0), ARG (1));
			} else {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},", ARG (2), ARG (1), ARG (2));
			}
		}
		MATH32 (">>");
		break;
	case ARM_INS_LSL:
		if (arm32shiftreg (as, op, handle, insn, str)) {
			break;
		}
		if (insn->detail->arm.update_flags) {
			if (OPCOUNT () == 2 && ISSHIFTED (1)) {
				r_strbuf_appendf (&op->esil, "%s,%u,32,-,0x1,<<,&,!,!,cf,:=,", REG (1), LSHIFT2 (1));
			} else if (OPCOUNT () == 2) {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,32,-,%s,>>,cf,:=,},", ARG (1), ARG (1), ARG (0));
			} else {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,32,-,%s,>>,cf,:=,},", ARG (2), ARG (2), ARG (1));
			}
		}
		MATH32 ("<<");
		break;
	case ARM_INS_RRX:
		// the carry comes from the source, which the result may overwrite
		r_strbuf_appendf (&op->esil, "1,%s,>>,31,cf,<<,|,", REG (1));
		if (insn->detail->arm.update_flags) {
			r_strbuf_appendf (&op->esil, "1,%s,&,cf,:=,", REG (1));
		}
		r_strbuf_appendf (&op->esil, "%s,=", REG (0));
		break;
	case ARM_INS_ROR:
		if (arm32shiftreg (as, op, handle, insn, str)) {
			break;
		}
		if (insn->detail->arm.update_flags) {
			if (OPCOUNT () == 2 && ISSHIFTED (1)) {
				r_strbuf_appendf (&op->esil, "%s,1,%u,-,0x1,<<,&,!,!,cf,:=,", REG (1), LSHIFT2 (1));
			} else if (OPCOUNT () == 2) {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,LSL,&,!,!,cf,:=,},", ARG (1), ARG (0), ARG (1));
			} else {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,LSL,&,!,!,cf,:=,},", ARG (2), ARG (1), ARG (2));
			}
		}
		MATH32 ("ROR");
		break;
	case ARM_INS_SVC:
		r_strbuf_appendf (&op->esil, "%s,$", ARG (0));
		break;
	case ARM_INS_PUSH:
#if 0
PUSH { r4, r5, r6, r7, lr }
4,sp,-=,lr,sp,=[4],
4,sp,-=,r7,sp,=[4],
4,sp,-=,r6,sp,=[4],
4,sp,-=,r5,sp,=[4],
4,sp,-=,r4,sp,=[4]

20,sp,-=,r4,sp,=[4],r5,sp,4,+,=[4],r6,sp,8,+,=[4],r7,sp,12,+,=[4],lr,sp,16,+,=[4]
#endif
		r_strbuf_setf (&op->esil, "%d,sp,-=,%s,sp,=[4]", insn->detail->arm.op_count * 4, REG (0));
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, ",%s,sp,%d,+,=[4]", REG (i), i * 4);
		}
		break;
	case ARM_INS_STMDA:
	case ARM_INS_STMDB:
	case ARM_INS_STM:
	case ARM_INS_STMIB: {
		int direction = (insn->id == ARM_INS_STMDA || insn->id == ARM_INS_STMDB ? -1 : 1);
		int offset = direction > 0 ? -1 : -insn->detail->arm.op_count;
		if (insn->id == ARM_INS_STMDA || insn->id == ARM_INS_STMIB) {
			offset++;
		}
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,%s,%d,+,=[4],",
				REG (i), ARG (0), (i + offset) * 4);
		}
		if (ISWRITEBACK32 ()) { //writeback, reg should be incremented
			r_strbuf_appendf (&op->esil, "%d,%s,+=,",
				direction * (insn->detail->arm.op_count - 1) * 4, ARG (0));
		}
		break;
	}
	case ARM_INS_VSTMIA:
		r_strbuf_set (&op->esil, "");
		width = 0;
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,%d,%s,+,=[%d],",
				REG (i), width, ARG (0), REGSIZE32 (i));
			width += REGSIZE32 (i);
		}
		// increment if writeback
		if (ISWRITEBACK32 ()) {
			r_strbuf_appendf (&op->esil, "%d,%s,+=,", width, ARG (0));
		}
		break;
	case ARM_INS_VSTMDB:
		r_strbuf_set (&op->esil, "");
		width = 0;
		for (i = insn->detail->arm.op_count - 1; i > 0; i--) {
			width += REGSIZE32 (i);
			r_strbuf_appendf (&op->esil, "%s,%d,%s,-,=[%d],",
				REG (i), width, ARG (0), REGSIZE32 (i));
		}
		// decrement writeback is mandatory for VSTMDB
		r_strbuf_appendf (&op->esil, "%d,%s,-=,", width, ARG (0));
		break;
	case ARM_INS_VLDMIA:
		r_strbuf_set (&op->esil, "");
		width = 0;
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%d,%s,+,[%d],%s,=,",
				width, ARG (0), REGSIZE32 (i), REG (i));
			width += REGSIZE32 (i);
		}
		// increment if writeback
		if (ISWRITEBACK32 ()) {
			r_strbuf_appendf (&op->esil, "%d,%s,+=,", width, ARG (0));
		}
		break;
	case ARM_INS_VLDMDB:
		r_strbuf_set (&op->esil, "");
		width = 0;
		for (i = insn->detail->arm.op_count - 1; i > 0; i--) {
			width += REGSIZE32 (i);
			r_strbuf_appendf (&op->esil, "%d,%s,-,[%d],%s,=,",
				width, ARG (0), REGSIZE32 (i), REG (i));
		}
		// decrement writeback is mandatory for VLDMDB
		r_strbuf_appendf (&op->esil, "%d,%s,-=,", width, ARG (0));
		break;
	case ARM_INS_ASR:
		if (arm32shiftreg (as, op, handle, insn, str)) {
			break;
		}
		// suffix 'S' forces conditional flag to be updated
		if (insn->detail->arm.update_flags) {
			if (OPCOUNT () == 2 && ISSHIFTED (1)) {
				r_strbuf_appendf (&op->esil, "%s,1,%u,-,0x1,<<,&,!,!,cf,:=,", REG (1), LSHIFT2 (1));
			} else if (OPCOUNT () == 2) {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},", ARG (1), ARG (0), ARG (1));
			} else if (OPCOUNT () == 3) {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},", ARG (2), ARG (1), ARG (2));
			}
		}
		if (OPCOUNT () == 2) {
			if (ISSHIFTED (1)) {
				r_strbuf_appendf (&op->esil, "%s,%s,=", ARG (1), ARG (0));
			} else {
				r_strbuf_appendf (&op->esil, "%s,%s,ASR,%s,=", ARG (1), ARG (0), ARG (0));
			}
		} else if (OPCOUNT () == 3) {
			r_strbuf_appendf (&op->esil, "%s,%s,ASR,%s,=", ARG (2), ARG (1), ARG (0));
		}
		break;
	case ARM_INS_POP:
#if 0
POP { r4,r5, r6}
r6,r5,r4,3,sp,[*],12,sp,+=
#endif
		for (i = insn->detail->arm.op_count; i > 0; i--) {
			r_strbuf_appendf (&op->esil, "%s,", REG (i - 1));
		}
		r_strbuf_appendf (&op->esil, "%d,sp,[*],",
			insn->detail->arm.op_count);
		r_strbuf_appendf (&op->esil, "%d,sp,+=",
			4 * insn->detail->arm.op_count);
		break;
	case ARM_INS_LDMDA:
	case ARM_INS_LDMDB:
	case ARM_INS_LDM:
	case ARM_INS_LDMIB: {
		int direction = (insn->id == ARM_INS_LDMDA || insn->id == ARM_INS_LDMDB) ? -1 : 1;
		int offset = direction > 0 ? -1 : -insn->detail->arm.op_count;
		if (insn->id == ARM_INS_LDMDA || insn->id == ARM_INS_LDMIB) {
			offset++;
		}
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,%d,+,[4],%s,=,", ARG (0), (i + offset) * 4, REG (i));
		}
		if (ISWRITEBACK32 ()) {
			r_strbuf_appendf (&op->esil, "%d,%s,+=,",
				direction * (insn->detail->arm.op_count - 1) * 4, ARG (0));
		}
		break;
	}
	case ARM_INS_CMP:
		r_strbuf_appendf (&op->esil, "%s,%s,==", ARG (1), ARG (0));
		break;
	case ARM_INS_CMN:
		// rn + op2 as rn - (-op2) so == commits old/cur for the shared $z/$c/$o block
		r_strbuf_appendf (&op->esil, "%s,-1,*,%s,==", ARG (1), ARG (0));
		break;
	case ARM_INS_MOVT:
		// replace rd[31:16] with imm16, preserving rd[15:0]
		r_strbuf_appendf (&op->esil, "16,%s,<<,0xffff,%s,&,|,%s,=", ARG (1), REG (0), REG (0));
		break;
	case ARM_INS_ADR:
		r_strbuf_appendf (&op->esil, "0x%"PFMT64x",%s,+,0xfffffffc,&,%s,=",
			addr + pcdelta, ARG (1), REG (0));
		break;
	case ARM_INS_MOV:
#if CS_API_MAJOR > 4
	case ARM_INS_MOVS: // capstone's id for thumb's 16-bit movs rd, rm and t2 movs.w with a shift
#endif
	case ARM_INS_VMOV:
	case ARM_INS_MOVW:
		// MATH32 ("=") left nothing for its mask, which aborted the esil before the flags
		if (as->config->bits == 16 && !strcmp (ARG (1), "pc")) {
			r_strbuf_appendf (&op->esil, "0x%"PFMT64x",%s,=", addr + pcdelta, REG (0));
		} else {
			r_strbuf_appendf (&op->esil, "%s,%s,=", ARG (1), REG (0));
		}
		break;
	case ARM_INS_CBZ:
		r_strbuf_appendf (&op->esil, "%s,!,?{,%" PFMT32u ",pc,:=,}",
			REG (0), IMM (1));
		break;
	case ARM_INS_CBNZ:
		r_strbuf_appendf (&op->esil, "%s,?{,%" PFMT32u ",pc,:=,}",
			REG (0), IMM (1));
		break;
		// Encapsulated STR/H/B into a code section
	case ARM_INS_STRT:
	case ARM_INS_STR:
	case ARM_INS_STRHT:
	case ARM_INS_STRH:
	case ARM_INS_STRBT:
	case ARM_INS_STRB:
	case ARM_INS_STRD:
	//case ARM_INS_STLXRB: // capstone has no STLXR?
		switch (insn->id) {
		case ARM_INS_STRD:
			str_ldr_bytes = 8; // just an indication, won't be used in esil code
			break;
		case ARM_INS_STRHT:
		case ARM_INS_STRH:
			str_ldr_bytes = 2;
			break;
		case ARM_INS_STRBT:
		case ARM_INS_STRB:
			str_ldr_bytes = 1;
			break;
		default:
			str_ldr_bytes = 4;
		}
		if (OPCOUNT() == 2) {
			if (ISMEM(1) && !HASMEMINDEX(1)) {
				int disp = MEMDISP (1);
				char sign = (disp >= 0)?'+':'-';
				disp = (disp >= 0)? disp: -disp;
				r_strbuf_appendf (&op->esil, "%s,0x%x,%s,%c,0xffffffff,&,=[%d]",
						  REG(0), disp, MEMBASE(1), sign, str_ldr_bytes);
				if (ISWRITEBACK32 ()) {
					r_strbuf_appendf (&op->esil, ",%d,%s,%c,%s,=",
							  disp, MEMBASE(1), sign, MEMBASE(1));
				}
			}
			if (HASMEMINDEX (1)) {	// e.g. 'str r2, [r3, r1]'
				if (ISSHIFTED (1)) { // e.g. 'str r2, [r3, r1, lsl 4]'
					switch (SHIFTTYPE (1)) {
					case ARM_SFT_LSL:
						r_strbuf_appendf (&op->esil, "%s,%s,%d,%s,<<,+,0xffffffff,&,=[%d]",
								  REG(0), MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), str_ldr_bytes);
						if (ISWRITEBACK32 ()) { // e.g. 'str r2, [r3, r1, lsl 4]!'
							r_strbuf_appendf (&op->esil, ",%s,%d,%s,<<,+,%s,=",
									  MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						}
						break;
					case ARM_SFT_LSR:
						r_strbuf_appendf (&op->esil, "%s,%s,%d,%s,>>,+,0xffffffff,&,=[%d]",
								  REG(0), MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), str_ldr_bytes);
						if (ISWRITEBACK32 ()) {
							r_strbuf_appendf (&op->esil, ",%s,%d,%s,>>,+,%s,=",
									  MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						}
						break;
					case ARM_SFT_ASR:
						r_strbuf_appendf (&op->esil, "%s,%s,%d,%s,ASR,+,0xffffffff,&,=[%d]",
								  REG(0), MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), str_ldr_bytes);
						if (ISWRITEBACK32 ()) {
							r_strbuf_appendf (&op->esil, ",%s,%d,%s,ASR,+,%s,=",
										MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						}
						break;
					case ARM_SFT_ROR:
						r_strbuf_appendf (&op->esil, "%s,%s,%d,%s,ROR,+,0xffffffff,&,=[%d]",
								  REG(0), MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), str_ldr_bytes);
						if (ISWRITEBACK32 ()) {
							r_strbuf_appendf (&op->esil, ",%s,%d,%s,ROR,+,%s,=",
										MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						}
						break;
					case ARM_SFT_RRX: // ROR with single bit shift, using previous cf rather than new cf
						//TODO: r2 doesn't mark this as a shift, it falls through to no shift
						break;
					default:
						// Hopefully nothing here
						break;
					}
				} else { // No shift
					r_strbuf_appendf (&op->esil, "%s,%s,%s,+,0xffffffff,&,=[%d]",
							  REG(0), MEMINDEX(1), MEMBASE(1), str_ldr_bytes);
					if (ISWRITEBACK32 ()) {
						r_strbuf_appendf (&op->esil, ",%s,%s,+,%s,=",
								  MEMINDEX(1), MEMBASE(1), MEMBASE(1));
					}
				}
			}
		}
		if (OPCOUNT() == 3) { // e.g. 'str r2, [r3], 4
			if (ISIMM (2) && str_ldr_bytes != 8) { // e.g. 'str r2, [r3], 4
				r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%d,%s,+=",
					       REG(0), MEMBASE(1), str_ldr_bytes, IMM(2), MEMBASE(1));
			} else if (str_ldr_bytes != 8) {
				// if (ISREG(2)) // e.g. 'str r2, [r3], r1
				if (ISSHIFTED (2)) { // e.g. 'str r2, [r3], r1, lsl 4'
					switch (SHIFTTYPE (2)) {
					case ARM_SFT_LSL:
						r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%d,%s,<<,+,%s,=",
							       REG(0), MEMBASE(1), str_ldr_bytes, MEMBASE(1), SHIFTVALUE(2), REG(2), MEMBASE(1));
						break;
					case ARM_SFT_LSR:
						r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%d,%s,>>,+,%s,=",
							       REG(0), MEMBASE(1), str_ldr_bytes, MEMBASE(1), SHIFTVALUE(2), REG(2), MEMBASE(1));
						break;
					case ARM_SFT_ASR:
						r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%d,%s,ASR,+,%s,=",
								      REG(0), MEMBASE(1), str_ldr_bytes, MEMBASE(1), SHIFTVALUE(2), REG(2), MEMBASE(1));
						break;
					case ARM_SFT_ROR:
						r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%d,%s,ROR,+,%s,=",
								      REG(0), MEMBASE(1), str_ldr_bytes, MEMBASE(1), SHIFTVALUE(2), REG(2), MEMBASE(1));
						break;
					case ARM_SFT_RRX:
						//TODO
						break;
					default:
						// Hopefully nothing here
						break;
					}
				} else { // No shift
					r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%s,+=",
						       REG(0), MEMBASE(1), str_ldr_bytes, REG(2), MEMBASE(1));
				}
			}
			if (ISREG (1) && str_ldr_bytes == 8) { // e.g. 'strd r2, r3, [r4]', normally should be the only case for ISREG(1).
				if (!HASMEMINDEX(2)) {
					int disp = MEMDISP (2);
					char sign = (disp >= 0)?'+':'-';
					disp = (disp >= 0)? disp: -disp;
					r_strbuf_appendf (&op->esil, "%s,%d,%s,%c,0xffffffff,&,=[4],%s,4,%d,+,%s,%c,0xffffffff,&,=[4]",
							  REG(0), disp, MEMBASE(2), sign, REG(1), disp, MEMBASE(2), sign);
					if (ISWRITEBACK32 ()) {
						r_strbuf_appendf (&op->esil, ",%d,%s,%c,%s,=",
								  disp, MEMBASE(2), sign, MEMBASE(2));
					}
				} else {
					if (ISSHIFTED (2)) {
						// it seems strd does not support SHIFT which is good, but have a check nonetheless
					} else {
						r_strbuf_appendf (&op->esil, "%s,%s,+,0xffffffff,&,=[4],%s,4,%s,+,0xffffffff,&,=[4]",
								  REG(0), MEMBASE(2), REG(1), MEMBASE(2));
						if (ISWRITEBACK32 ()) {
							const char sign = ISMEMINDEXSUB(2) ? '-' : '+';
							r_strbuf_appendf (&op->esil, ",%s,%s,%c=",
									  MEMINDEX(2), MEMBASE(2), sign);
						}
					}
				}
			}
		}
		if (OPCOUNT() == 4) { // e.g. 'strd r2, r3, [r4], 4' or 'strd r2, r3, [r4], r5'
			if (ISIMM (3)) { // e.g. 'strd r2, r3, [r4], 4'
				r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,4,%s,+,0xffffffff,&,=[%d],%d,%s,+=,",
					       REG(0), MEMBASE(2), str_ldr_bytes, REG(1), MEMBASE(2), str_ldr_bytes, IMM(3), MEMBASE(2));
			}
			if (ISREG(3)) { // e.g. 'strd r2, r3, [r4], r5'
				if (ISSHIFTED(3)) {
					// same as above
				} else {
					r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,4,%s,+,0xffffffff,&,=[%d],%s,%s,+=",
						       REG(0), MEMBASE(2), str_ldr_bytes, REG(1), MEMBASE(2), str_ldr_bytes, REG(3), MEMBASE(2));
				}
			}
		}
		break;
	case ARM_INS_TST:
		r_strbuf_appendf (&op->esil, "0,%s,%s,&,==", ARG(1), ARG(0));
		break;
	case ARM_INS_LDRD:
		addr &= ~3LL;
		if (MEMDISP (2) < 0) {
			if (REGBASE (2) == ARM_REG_PC) {
				op->refptr = 4;
				op->ptr = addr + pcdelta + MEMDISP (2);
				r_strbuf_appendf (&op->esil, "0x%"PFMT64x",2,2,0x%"PFMT64x
					",>>,<<,+,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
					(ut64)MEMDISP (2), addr + pcdelta, REG (0), REG (1));
			} else {
				int disp = MEMDISP (2);
				// not refptr, because we can't grab the reg value statically op->refptr = 4;
				if (disp < 0) {
					r_strbuf_appendf (&op->esil, "0x%"PFMT64x
						",%s,-,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						(ut64)-disp, MEMBASE (2), REG (0), REG (1));
				} else {
					r_strbuf_appendf (&op->esil, "0x%"PFMT64x
						",%s,+,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						(ut64)disp, MEMBASE (2), REG (0), REG (1));
				}
			}
		} else {
			if (REGBASE (2) == ARM_REG_PC) {
				op->refptr = 4;
				op->ptr = addr + pcdelta + MEMDISP (2);
				if (HASMEMINDEX (2) || ISREG (2)) {
					const char op_index = ISMEMINDEXSUB (2)? '-': '+';
					r_strbuf_appendf (&op->esil, "%s,2,2,0x%"PFMT64x
						",>>,<<,%c,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						MEMINDEX (2), addr + pcdelta, op_index, REG (0), REG (1));
				} else {
					r_strbuf_appendf (&op->esil, "2,2,0x%"PFMT64x
						",>>,<<,%d,+,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						addr + pcdelta, MEMDISP (2), REG (0), REG (1));
				}
			} else {
				if (HASMEMINDEX (2)) { // e.g. `ldrd r2, r3 [r4, r1]`
					const char op_index = ISMEMINDEXSUB (2)? '-': '+';
					r_strbuf_appendf (&op->esil, "%s,%s,%c,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						MEMINDEX (2), MEMBASE (2), op_index, REG (0), REG (1));
				} else {
					r_strbuf_appendf (&op->esil, "%d,%s,+,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						MEMDISP (2), MEMBASE (2), REG (0), REG (1));
				}
				if (ISWRITEBACK32 ()) {
					if (ISPOSTINDEX32 ()) {
						if (ISIMM (3)) {
							r_strbuf_appendf (&op->esil, ",%s,%d,+,%s,=",
								MEMBASE (2), IMM (3), MEMBASE (2));
						} else {
							const char op_index = ISMEMINDEXSUB (3)? '-': '+';
							r_strbuf_appendf (&op->esil, ",%s,%s,%c,%s,=",
								REG (3), MEMBASE (2), op_index, MEMBASE (2));
						}
					} else if (ISPREINDEX32 ()) {
						if (HASMEMINDEX (2)) {
							const char op_index = ISMEMINDEXSUB (2)? '-': '+';
							r_strbuf_appendf (&op->esil, ",%s,%s,%c,%s,=",
								MEMINDEX (2), MEMBASE (2), op_index, MEMBASE (2));
						} else {
							r_strbuf_appendf (&op->esil, ",%s,%d,+,%s,=",
								MEMBASE (2), MEMDISP (2), MEMBASE (2));
						}
					}
				}
			}
		}
		break;
	case ARM_INS_LDRB:
		if (ISMEM(1) && LSHIFT2(1)) {
			r_strbuf_appendf (&op->esil, "%s,%d,%s,<<,+,0xffffffff,&,[1],%s,=",
				MEMBASE (1), LSHIFT2 (1), MEMINDEX (1), REG (0));
		} else if (HASMEMINDEX (1)) {
			r_strbuf_appendf (&op->esil, "%s,%s,+,0xffffffff,&,[1],%s,=",
				MEMINDEX (1), MEMBASE (1), REG (0));
		} else {
			r_strbuf_appendf (&op->esil, "%s,%d,+,[1],%s,=",
				MEMBASE (1), MEMDISP (1), REG (0));
		}
		if (ISWRITEBACK32 ()) {
			if (ISIMM(2)) {
				r_strbuf_appendf (&op->esil, ",%s,%d,+,%s,=",
					MEMBASE (1), IMM (2), MEMBASE (1));
			} else {
				r_strbuf_appendf (&op->esil, ",%s,%d,+,%s,=",
					MEMBASE (1), MEMDISP (1), MEMBASE (1));
			}
		}
		break;
	case ARM_INS_UADD8:
		for (i = 0; i < 4; i++) {
			const ut32 bm = 0xffU << (i * 8);
			r_strbuf_appendf (&op->esil, "0x%x,%s,&,0x%x,%s,&,+,0x%x,&,%s",
				bm, REG (1), bm, REG (2), bm, i? "|,": "");
		}
		r_strbuf_appendf (&op->esil, "%s,=", REG (0));
		break;
	case ARM_INS_SXTB:
	case ARM_INS_SXTH:
		r_strbuf_appendf (&op->esil, "%d,%s,~,%s,=",
			(insn->id == ARM_INS_SXTB)? 8: 16, ARG (1), REG (0));
		break;
	case ARM_INS_LDREX:
	case ARM_INS_LDREXB:
	case ARM_INS_LDREXD:
	case ARM_INS_LDREXH:
		op->family = R_ANAL_OP_FAMILY_THREAD;
		// intentional fallthrough
	case ARM_INS_LDRHT:
	case ARM_INS_LDRH:
	case ARM_INS_LDRT:
	case ARM_INS_LDRBT:
	case ARM_INS_LDRSB:
	case ARM_INS_LDRSBT:
	case ARM_INS_LDRSH:
	case ARM_INS_LDRSHT:
	case ARM_INS_LDR:
		switch (insn->id) {
		case ARM_INS_LDRSH:
		case ARM_INS_LDRSHT:
			ldext = "16,SWAP,~";
			ldsz = 2;
			break;
		case ARM_INS_LDRHT:
		case ARM_INS_LDRH:
			ldext = "0xffff,&";
			ldsz = 2;
			break;
		case ARM_INS_LDRSB:
		case ARM_INS_LDRSBT:
			ldext = "8,SWAP,~";
			ldsz = 1;
			break;
		case ARM_INS_LDRBT:
			ldext = "0xff,&";
			ldsz = 1;
			break;
		}
		addr &= ~3LL;
		if (MEMDISP (1) < 0) {
			if (REGBASE (1) == ARM_REG_PC) {
				op->refptr = 4;
				op->ptr = addr + pcdelta + MEMDISP(1);
				r_strbuf_appendf (&op->esil, "0x%"PFMT64x",2,2,0x%"PFMT64x
					",>>,<<,+,0xffffffff,&,[%d],%s,%s,=",
					(ut64)MEMDISP(1), addr + pcdelta, ldsz, ldext, REG(0));
			} else {
				int disp = MEMDISP(1);
				// not refptr, because we can't grab the reg value statically op->refptr = 4;
				if (disp < 0) {
					r_strbuf_appendf (&op->esil, "0x%"PFMT64x",%s,-,0xffffffff,&,[%d],%s,%s,=",
							(ut64)-disp, MEMBASE(1), ldsz, ldext, REG(0));
				} else {
					r_strbuf_appendf (&op->esil, "0x%"PFMT64x",%s,+,0xffffffff,&,[%d],%s,%s,=",
							(ut64)disp, MEMBASE(1), ldsz, ldext, REG(0));
				}
			}
		} else {
			if (REGBASE(1) == ARM_REG_PC) {
				op->refptr = 4;
				op->ptr = addr + pcdelta + MEMDISP(1);
				if (ISMEM(1) && LSHIFT2(1)) {
					r_strbuf_appendf (&op->esil, "2,2,0x%"PFMT64x
						",>>,<<,%d,%s,<<,+,0xffffffff,&,[%d],%s,%s,=",
						addr + pcdelta, LSHIFT2(1), MEMINDEX(1), ldsz, ldext, REG(0));
				} else {
					if (HASMEMINDEX (1)) {
						const char op_index = ISMEMINDEXSUB (1)? '-': '+';
						r_strbuf_appendf (&op->esil, "%s,2,2,0x%"PFMT64x
							",>>,<<,%c,0xffffffff,&,[%d],%s,%s,=",
							MEMINDEX (1), addr + pcdelta, op_index, ldsz, ldext, REG (0));
					} else {
						r_strbuf_appendf (&op->esil, "2,2,0x%"PFMT64x
							",>>,<<,%d,+,0xffffffff,&,[%d],%s,%s,=",
							addr + pcdelta, MEMDISP(1), ldsz, ldext, REG(0));
					}
				}
			} else {
				if (ISMEM(1) && LSHIFT2(1)) {
					r_strbuf_appendf (&op->esil, "%s,%d,%s,<<,+,0xffffffff,&,[%d],%s,%s,=",
						MEMBASE (1), LSHIFT2 (1), MEMINDEX (1), ldsz, ldext, REG (0));
				} else if (HASMEMINDEX(1)) {	// e.g. `ldr r2, [r3, r1]`
					const char op_index = ISMEMINDEXSUB (1)? '-': '+';
					r_strbuf_appendf (&op->esil, "%s,%s,%c,0xffffffff,&,[%d],%s,%s,=",
						MEMINDEX (1), MEMBASE (1), op_index, ldsz, ldext, REG (0));
				} else {
					r_strbuf_appendf (&op->esil, "%d,%s,+,0xffffffff,&,[%d],%s,%s,=",
						MEMDISP (1), MEMBASE (1), ldsz, ldext, REG (0));
				}
				if (ISWRITEBACK32 ()) {
					if (ISPOSTINDEX32 ()) {
						if (ISIMM (2)) {
							const char op_index = ISMEMINDEXSUB (2)? '-': '+';
							r_strbuf_appendf (&op->esil, ",%d,%s,%c,%s,=",
								IMM (2), MEMBASE (1), op_index, MEMBASE (1));
						} else {
							const char op_index = ISMEMINDEXSUB (2)? '-': '+';
							r_strbuf_appendf (&op->esil, ",%d,%s,<<,%s,%c,%s,=",
								LSHIFT2 (2), REG (2), MEMBASE (1), op_index, MEMBASE (1));
						}
					} else if (ISPREINDEX32 ()) {
						if (HASMEMINDEX (1)) {
							const char op_index = ISMEMINDEXSUB (1)? '-': '+';
							r_strbuf_appendf (&op->esil, ",%d,%s,<<,%s,%c,%s,=",
								LSHIFT2 (1), MEMINDEX (1), MEMBASE (1), op_index, MEMBASE (1));
						} else {
							r_strbuf_appendf (&op->esil, ",%s,%d,+,%s,=",
								MEMBASE (1), MEMDISP (1), MEMBASE (1));
						}
					}
				}
			}
		}
		break;
	case ARM_INS_MRS:
		// TODO: esil for MRS
		break;
	case ARM_INS_MSR:
		msr_flags = insn->detail->arm.operands[0].reg >> 4;
		r_strbuf_append (&op->esil, "0,");
		if (msr_flags & 1) {
			r_strbuf_append (&op->esil, "0xff,|,");
		}
		if (msr_flags & 2) {
			r_strbuf_append (&op->esil, "0xff00,|,");
		}
		if (msr_flags & 4) {
			r_strbuf_append (&op->esil, "0xff0000,|,");
		}
		if (msr_flags & 8) {
			r_strbuf_append (&op->esil, "0xff000000,|,");
		}
		r_strbuf_appendf (&op->esil, "DUP,!,SWAP,&,%s,SWAP,cpsr,&,|,cpsr,=", REG(1));
		break;
	case ARM_INS_UBFX:
		if (IMM (3) > 0 && IMM (3) <= 32 - IMM (2)) {
			size_t index = IMM (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%d,%s,%d,%"PFMT64u",<<,&,>>,%s,=",
				IMM(2), REG(1), IMM(2), bitmask_by_width[index], REG(0));
		}
		break;
	case ARM_INS_UXTB:
		r_strbuf_appendf (&op->esil, "%s,0xff,&,%s,=", ARG(1), REG(0));
		break;
	case ARM_INS_RSB:
		if (OPCOUNT () == 2) {
			r_strbuf_appendf (&op->esil, "%s,%s,-=", ARG(0), ARG(1));
		} else if (OPCOUNT () == 3) {
			r_strbuf_appendf (&op->esil, "%s,%s,-,%s,=", ARG(1), ARG(2), ARG(0));
		}
		break;
	case ARM_INS_BIC:
		if (OPCOUNT () == 2) {
			r_strbuf_appendf (&op->esil, "%s,0xffffffff,^,%s,&=", ARG(1), ARG(0));
		} else {
			r_strbuf_appendf (&op->esil, "%s,0xffffffff,^,%s,&,%s,=", ARG(2), ARG(1), ARG(0));
		}
		break;
	case ARM_INS_SMMLA:
		r_strbuf_appendf (&op->esil, "32,%s,%s,*,>>,%s,+,0xffffffff,&,%s,=",
			REG(1), REG(2), REG(3), REG(0));
		break;
	case ARM_INS_SMMLAR:
		r_strbuf_appendf (&op->esil, "32,0x80000000,%s,%s,*,+,>>,%s,+,0xffffffff,&,%s,=",
			REG(1), REG(2), REG(3), REG(0));
		break;
	case ARM_INS_UMULL:
		r_strbuf_appendf (&op->esil, "32,%s,%s,*,DUP,0xffffffff,&,%s,=,>>,%s,=",
			REG(2), REG(3), REG(0), REG(1));
		break;
	case ARM_INS_MLS:
		r_strbuf_appendf (&op->esil, "%s,%s,*,%s,-,0xffffffff,&,%s,=",
			REG(1), REG(2), REG(3), REG(0));
		break;
	case ARM_INS_MLA:
		r_strbuf_appendf (&op->esil, "%s,%s,*,%s,+,0xffffffff,&,%s,=",
			REG(1), REG(2), REG(3), REG(0));
		break;
	case ARM_INS_MVN:
		r_strbuf_appendf (&op->esil, "-1,%s,^,0xffffffff,&,%s,=",
			ARG(1), REG(0));
		break;
	case ARM_INS_BFI:
	{
		if (OPCOUNT() >= 3 && ISIMM(3) && IMM(3) > 0 && IMM(3) < 64) {
			size_t index = IMM (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			ut64 mask = bitmask_by_width[index];
			ut64 shift = IMM(2);
			ut64 notmask = ~(mask << shift);
			// notmask,dst,&,lsb,mask,src,&,<<,|,dst,=
			r_strbuf_setf (&op->esil, "%"PFMT64u",%s,&,%"PFMT64u",%"PFMT64u",%s,&,<<,|,0xffffffff,&,%s,=",
				notmask, REG(0), shift, mask, REG(1), REG(0));
		}
		break;
	}
	case ARM_INS_BFC:
	{
		if (OPCOUNT() >= 2 && ISIMM(2) && IMM(2) > 0 && IMM(2) < 64) {
			size_t index = IMM (2) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			ut64 mask = bitmask_by_width[IMM(2) - 1];
			ut64 shift = IMM(1);
			ut64 notmask = ~(mask << shift);
			// notmask,dst,&,dst,=
			r_strbuf_setf (&op->esil, "%"PFMT64u",%s,&,0xffffffff,&,%s,=",
				notmask, REG(0), REG(0));
		}
		break;
	}
	case ARM_INS_REV:
	{
		const char *r0 = REG(0);
		const char *r1 = REG(1);
		// the whole source is read before the write, so rd == rn works
		r_strbuf_appendf (&op->esil,
			"24,0xff,%s,&,<<,"
			"16,0xff,8,%s,>>,&,<<,|,"
			"8,0xff,16,%s,>>,&,<<,|,"
			"0xff,24,%s,>>,&,|,%s,=",
			r1, r1, r1, r1, r0);
		break;
	}
	case ARM_INS_REV16:
	{
		const char *r0 = REG(0);
		const char *r1 = REG(1);
		r_strbuf_appendf (&op->esil,
			"8,0xff00ff00,%s,&,>>,"
			"8,0x00ff00ff,%s,&,<<,|,%s,=",
			r1, r1, r0);
		break;
	}
	case ARM_INS_REVSH:
	{
		const char *r0 = REG(0);
		const char *r1 = REG(1);
		r_strbuf_appendf (&op->esil,
			"16,8,0xff00,%s,&,>>,"
			"8,0x00ff,%s,&,<<,|,~,%s,=",
			r1, r1, r0);
		break;
	}
	case ARM_INS_TBB:
		r_strbuf_appendf (&op->esil, "%s,%s,+,0xffffffff,&,DUP,[1],1,SWAP,<<,+,pc,+=",
			MEMBASE (0), MEMINDEX (0));
		break;
	case ARM_INS_TBH:
		r_strbuf_appendf (&op->esil, "%s,%d,%s,<<,+,0xffffffff,&,[2],1,SWAP,<<,pc,+=",
			MEMBASE (0), LSHIFT2 (0), MEMINDEX (0));
		break;
	default:
		break;
	}
	// Update flags if required...TODO different instructions update different flags, but this should fix
	// many errors
	if (insn->detail->arm.update_flags) {
		switch(insn->id) {
		case ARM_INS_UADD8:
			// the parallel add/sub family writes GE, never NZCV
			break;
		case ARM_INS_CMP:
			r_strbuf_append (&op->esil, ",$z,zf,:=,31,$s,nf,:=,32,$b,!,cf,:=,31,$o,vf,:=");
			break;
		case ARM_INS_ADD:
		case ARM_INS_RSB:
		case ARM_INS_RSC:
		case ARM_INS_SUB:
		case ARM_INS_SBC:
		case ARM_INS_ADC:
		case ARM_INS_CMN:
			r_strbuf_append (&op->esil, ",$z,zf,:=,31,$s,nf,:=,31,$c,cf,:=,31,$o,vf,:=");
			break;
		default:
			r_strbuf_append (&op->esil, ",$z,zf,:=,31,$s,nf,:=");
		}
	}

	r_strbuf_append (&op->esil, postfix);

	return 0;
}

static int cond_cs2r2(int cc) {
	if (cc == ARM_CC_AL || cc < 0) {
		cc = R_ANAL_CONDTYPE_AL;
	} else {
		switch (cc) {
		case ARM_CC_EQ: cc = R_ANAL_CONDTYPE_EQ; break;
		case ARM_CC_NE: cc = R_ANAL_CONDTYPE_NE; break;
		case ARM_CC_HS: cc = R_ANAL_CONDTYPE_HS; break;
		case ARM_CC_LO: cc = R_ANAL_CONDTYPE_LO; break;
		case ARM_CC_MI: cc = R_ANAL_CONDTYPE_MI; break;
		case ARM_CC_PL: cc = R_ANAL_CONDTYPE_PL; break;
		case ARM_CC_VS: cc = R_ANAL_CONDTYPE_VS; break;
		case ARM_CC_VC: cc = R_ANAL_CONDTYPE_VC; break;
		case ARM_CC_HI: cc = R_ANAL_CONDTYPE_HI; break;
		case ARM_CC_LS: cc = R_ANAL_CONDTYPE_LS; break;
		case ARM_CC_GE: cc = R_ANAL_CONDTYPE_GE; break;
		case ARM_CC_LT: cc = R_ANAL_CONDTYPE_LT; break;
		case ARM_CC_GT: cc = R_ANAL_CONDTYPE_GT; break;
		case ARM_CC_LE: cc = R_ANAL_CONDTYPE_LE; break;
		}
	}
	return cc;
}

static void anop64(csh handle, RAnalOp *op, cs_insn *insn) {
	ut64 addr = op->addr;

	/* grab family */
	if (cs_insn_group (handle, insn, ARM64_GRP_CRC )) {
		op->family = R_ANAL_OP_FAMILY_CRYPTO;
#if CS_API_MAJOR < 6
	// XXX - Can't find ARM64 feature crypto in cs6 arm64
	} else if (cs_insn_group (handle, insn, ARM64_GRP_CRYPTO)) {
		op->family = R_ANAL_OP_FAMILY_CRYPTO;
#endif
	} else if (cs_insn_group (handle, insn, ARM64_GRP_PRIVILEGE)) {
		op->family = R_ANAL_OP_FAMILY_PRIV;
	} else if (cs_insn_group (handle, insn, ARM64_GRP_NEON)) {
		op->family = R_ANAL_OP_FAMILY_VEC;
	} else if (cs_insn_group (handle, insn, ARM64_GRP_FPARMV8)) {
		op->family = R_ANAL_OP_FAMILY_FPU;
	} else {
		op->family = R_ANAL_OP_FAMILY_CPU;
	}

	op->cond = cond_cs2r2 (insn->detail->arm64.cc);
	if (op->cond == R_ANAL_CONDTYPE_NV) {
		op->type = R_ANAL_OP_TYPE_NOP;
		return;
	}

	switch (insn->detail->arm64.cc) {
	case ARM64_CC_GE:
	case ARM64_CC_GT:
	case ARM64_CC_LE:
	case ARM64_CC_LT:
		op->sign = true;
		break;
	default:
		break;
	}

	switch (insn->id) {
#if CS_API_MAJOR > 4
	case ARM64_INS_UDF:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case ARM64_INS_PACDA:
	case ARM64_INS_PACDB:
	case ARM64_INS_PACDZA:
	case ARM64_INS_PACDZB:
	case ARM64_INS_PACGA:
	case ARM64_INS_PACIA:
	case ARM64_INS_PACIA1716:
	case ARM64_INS_PACIASP:
	case ARM64_INS_PACIAZ:
	case ARM64_INS_PACIB:
	case ARM64_INS_PACIB1716:
	case ARM64_INS_PACIBSP:
	case ARM64_INS_PACIBZ:
	case ARM64_INS_PACIZA:
	case ARM64_INS_PACIZB:
	case ARM64_INS_AUTDA:
	case ARM64_INS_AUTDB:
	case ARM64_INS_AUTDZA:
	case ARM64_INS_AUTDZB:
	case ARM64_INS_AUTIA:
	case ARM64_INS_AUTIA1716:
	case ARM64_INS_AUTIASP:
	case ARM64_INS_AUTIAZ:
	case ARM64_INS_AUTIB:
	case ARM64_INS_AUTIB1716:
	case ARM64_INS_AUTIBSP:
	case ARM64_INS_AUTIBZ:
	case ARM64_INS_AUTIZA:
	case ARM64_INS_AUTIZB:
	case ARM64_INS_XPACD:
	case ARM64_INS_XPACI:
	case ARM64_INS_XPACLRI:
		op->type = R_ANAL_OP_TYPE_CMP;
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		break;
#endif
	case ARM64_INS_SVC:
		op->type = R_ANAL_OP_TYPE_SWI;
		op->val = IMM64(0);
		break;
	case ARM64_INS_ADRP:
	case ARM64_INS_ADR:
		op->type = R_ANAL_OP_TYPE_LEA;
		op->ptr = IMM64(1);
		break;
	case ARM64_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		op->cycles = 1;
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_SUBP:
	case ARM64_INS_SUBPS:
		op->cycles = 1;
		op->sign = true;
		op->type = insn->id == ARM64_INS_SUBPS && (arm64_reg)REGID64 (0) == ARM64_REG_XZR? R_ANAL_OP_TYPE_CMP: R_ANAL_OP_TYPE_SUB;
		break;
#if CS_API_MAJOR == 5
	case ARM64_INS_CMPP:
		op->type = R_ANAL_OP_TYPE_CMP;
		op->sign = true;
		break;
#endif
	case ARM64_INS_SUBG:
#endif
#if CS_API_MAJOR >= 6
	case ARM64_INS_SUBPT:
#endif
	case ARM64_INS_SUB:
		if (ISREG64(0) && (arm64_reg) REGID64(0) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			if (ISIMM64(2) && ISREG64(1) && (arm64_reg) REGID64(1) == ARM64_REG_SP) {
				//sub sp, sp, 0x10
				op->stackptr = SHIFTED_IMM64 (2, 64);
			}
			op->val = op->stackptr;
		}
		op->cycles = 1;
		/* fallthru */
	case ARM64_INS_MSUB:
#if CS_API_MAJOR >= 6
	case ARM64_INS_MSUBPT:
#endif
	case ARM64_INS_FSUB:
	case ARM64_INS_FMSUB:
	case ARM64_INS_FNMSUB:
	case ARM64_INS_SBC:
	case ARM64_INS_NGC:
	case ARM64_INS_NGCS:
#if CS_API_MAJOR > 4
	case ARM64_INS_SBCS:
	case ARM64_INS_SUBS:
#endif
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case ARM64_INS_FDIV:
	case ARM64_INS_FSQRT:
	case ARM64_INS_FRECPE:
	case ARM64_INS_FRECPS:
	case ARM64_INS_FRECPX:
	case ARM64_INS_FRSQRTE:
	case ARM64_INS_FRSQRTS:
	case ARM64_INS_SDIV:
	case ARM64_INS_UDIV:
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case ARM64_INS_MUL:
	case ARM64_INS_SMULL:
	case ARM64_INS_FMUL:
	case ARM64_INS_FNMUL:
	case ARM64_INS_FMULX:
	case ARM64_INS_UMULL:
		/* TODO: if next instruction is also a MUL, cycles are /=2 */
		/* also known as Register Indexing Addressing */
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_ADDG:
#endif
#if CS_API_MAJOR >= 6
	case ARM64_INS_ADDPT:
#endif
	case ARM64_INS_ADD:
		if (ISREG64 (0) && (arm64_reg) REGID64 (0) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			if (ISIMM64 (2) && ISREG64 (1) && (arm64_reg) REGID64 (1) == ARM64_REG_SP) {
				//add sp, sp, 0x10
				op->stackptr = -(st64)SHIFTED_IMM64 (2, 64);
			}
			// op->val = op->stackptr;
		} else if ((arm64_reg) REGID64 (0) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_RESET;
			op->stackptr = 0;
		} else {
			if (ISIMM64 (2)) {
				op->val = SHIFTED_IMM64 (2, 64);
			} else {
				op->val = 0;
			}
		}
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case ARM64_INS_ADC:
	case ARM64_INS_UMADDL:
	case ARM64_INS_SMADDL:
	case ARM64_INS_FADD:
	case ARM64_INS_FMADD:
	case ARM64_INS_FNMADD:
	case ARM64_INS_FMLA:
	case ARM64_INS_FMLS:
	case ARM64_INS_MLA:
	case ARM64_INS_MLS:
	case ARM64_INS_MADD:
#if CS_API_MAJOR >= 6
	case ARM64_INS_MADDPT:
#endif
#if CS_API_MAJOR > 4
	case ARM64_INS_ADDS:
	case ARM64_INS_ADCS:
#endif
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
#if CS_API_MAJOR >= 6
	case ARM64_INS_MADPT:
	case ARM64_INS_MLAPT:
		op->type = R_ANAL_OP_TYPE_ADD;
		op->family = R_ANAL_OP_FAMILY_VEC;
		break;
#endif
	case ARM64_INS_CSEL:
	case ARM64_INS_FCSEL:
	case ARM64_INS_CSET:
	case ARM64_INS_CINC:
		op->type = R_ANAL_OP_TYPE_CMOV;
		break;
#if 0
	case ARM64_INS_BTI:
		op->type = R_ANAL_OP_TYPE_NOP;
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		break;
#endif
	case ARM64_INS_MOV:
		if ((arm64_reg) REGID64(0) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_RESET;
			op->stackptr = 0;
		}
		op->cycles = 1;
		/* fallthru */
	case ARM64_INS_MOVI:
	case ARM64_INS_MVNI:
	case ARM64_INS_TBL:
	case ARM64_INS_TBX:
	case ARM64_INS_ADDV:
	case ARM64_INS_SMAXV:
	case ARM64_INS_SMINV:
	case ARM64_INS_UMAXV:
	case ARM64_INS_UMINV:
	case ARM64_INS_FMAXV:
	case ARM64_INS_FMINV:
	case ARM64_INS_FMAXNMV:
	case ARM64_INS_FMINNMV:
	case ARM64_INS_ADDP:
	case ARM64_INS_FADDP:
	case ARM64_INS_SADDLP:
	case ARM64_INS_UADDLP:
	case ARM64_INS_SADALP:
	case ARM64_INS_UADALP:
	case ARM64_INS_SABD:
	case ARM64_INS_SMAX:
	case ARM64_INS_SMIN:
	case ARM64_INS_UABD:
	case ARM64_INS_UMAX:
	case ARM64_INS_UMIN:
	case ARM64_INS_MOVK:
	case ARM64_INS_MOVN:
	case ARM64_INS_SMOV:
	case ARM64_INS_UMOV:
	case ARM64_INS_FMOV:
	case ARM64_INS_SBFX:
	case ARM64_INS_UBFX:
	case ARM64_INS_UBFM:
	case ARM64_INS_BFI:
	case ARM64_INS_SBFIZ:
	case ARM64_INS_UBFIZ:
	case ARM64_INS_BFXIL:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (ISIMM64 (1)) {
			op->val = IMM64(1);
		}
		break;
	case ARM64_INS_MRS:
	case ARM64_INS_MSR:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_PRIV;
		break;
	case ARM64_INS_MOVZ:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 8;
		op->val = IMM64(1);
		break;
	case ARM64_INS_UXTB:
	case ARM64_INS_SXTB:
		op->type = R_ANAL_OP_TYPE_CAST;
		op->ptr = 0LL;
		op->ptrsize = 1;
		break;
	case ARM64_INS_UXTH:
	case ARM64_INS_SXTH:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 2;
		break;
	case ARM64_INS_UXTW:
	case ARM64_INS_SXTW:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 4;
		break;
	case ARM64_INS_BRK:
	case ARM64_INS_HLT:
		op->type = R_ANAL_OP_TYPE_TRAP;
		// hlt stops the process, not skips some cycles like in x86
		break;
	case ARM64_INS_DMB:
	case ARM64_INS_DSB:
	case ARM64_INS_ISB:
		op->family = R_ANAL_OP_FAMILY_THREAD;
		// intentional fallthrough
	case ARM64_INS_IC: // instruction cache invalidate
	case ARM64_INS_DC: // data cache invalidate
		op->type = R_ANAL_OP_TYPE_SYNC; // or cache
		break;
	//  XXX unimplemented instructions
	case ARM64_INS_CLZ:
	case ARM64_INS_CLS:
	case ARM64_INS_CNT:
	case ARM64_INS_DUP:
	case ARM64_INS_XTN:
	case ARM64_INS_XTN2:
	case ARM64_INS_REV:
	case ARM64_INS_REV64:
	case ARM64_INS_REV16:
	case ARM64_INS_REV32:
	case ARM64_INS_EXT:
	case ARM64_INS_INS:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM64_INS_LSL:
		op->cycles = 1;
		/* fallthru */
	case ARM64_INS_SHL:
	case ARM64_INS_SSHLL:
	case ARM64_INS_SSHLL2:
	case ARM64_INS_USHLL:
	case ARM64_INS_USHLL2:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case ARM64_INS_LSR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case ARM64_INS_SHRN:
	case ARM64_INS_SHRN2:
	case ARM64_INS_RSHRN:
	case ARM64_INS_RSHRN2:
	case ARM64_INS_SQSHRN:
	case ARM64_INS_SQSHRN2:
	case ARM64_INS_SQRSHRN:
	case ARM64_INS_SQRSHRN2:
	case ARM64_INS_SQSHRUN:
	case ARM64_INS_SQSHRUN2:
	case ARM64_INS_SQRSHRUN:
	case ARM64_INS_SQRSHRUN2:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case ARM64_INS_CMEQ:
	case ARM64_INS_CMGE:
	case ARM64_INS_CMGT:
	case ARM64_INS_CMHI:
	case ARM64_INS_CMHS:
	case ARM64_INS_CMLE:
	case ARM64_INS_CMLT:
	case ARM64_INS_CMTST:
	case ARM64_INS_FCMEQ:
	case ARM64_INS_FCMGE:
	case ARM64_INS_FCMGT:
	case ARM64_INS_FCMLE:
	case ARM64_INS_FCMLT:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case ARM64_INS_ASR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SAR;
		break;
	case ARM64_INS_NEG:
	case ARM64_INS_NEGS:
	case ARM64_INS_FNEG:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case ARM64_INS_FCVT:
	case ARM64_INS_FCVTN:
	case ARM64_INS_FCVTN2:
	case ARM64_INS_FCVTL:
	case ARM64_INS_FCVTL2:
	case ARM64_INS_FCVTAS:
	case ARM64_INS_FCVTAU:
	case ARM64_INS_FCVTMS:
	case ARM64_INS_FCVTMU:
	case ARM64_INS_FCVTNS:
	case ARM64_INS_FCVTNU:
	case ARM64_INS_FCVTPS:
	case ARM64_INS_FCVTPU:
	case ARM64_INS_FCVTZS:
	case ARM64_INS_FCVTZU:
	case ARM64_INS_SCVTF:
	case ARM64_INS_UCVTF:
		op->type = R_ANAL_OP_TYPE_CAST;
		break;
	case ARM64_INS_CMP:
		op->type = R_ANAL_OP_TYPE_CMP;
		if (ISIMM64 (1)) {
			op->val = SHIFTED_IMM64 (1, 64);
		}
		break;
	case ARM64_INS_FCMP:
	case ARM64_INS_FCMPE:
	case ARM64_INS_FCCMP:
	case ARM64_INS_FCCMPE:
	case ARM64_INS_CCMP:
	case ARM64_INS_CCMN:
	case ARM64_INS_CMN:
	case ARM64_INS_TST:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case ARM64_INS_ROR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case ARM64_INS_AND:
	case ARM64_INS_BIC:
#if CS_API_MAJOR > 4
	case ARM64_INS_ANDS:
	case ARM64_INS_BICS:
#endif
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case ARM64_INS_ORR:
	case ARM64_INS_ORN:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case ARM64_INS_EOR:
	case ARM64_INS_EON:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case ARM64_INS_STRB:
	case ARM64_INS_STURB:
	case ARM64_INS_STUR:
	case ARM64_INS_STR:
	case ARM64_INS_STP:
	case ARM64_INS_STNP:
	case ARM64_INS_STXR:
	case ARM64_INS_STXRH:
	case ARM64_INS_STLXR:
	case ARM64_INS_STLXRH:
	case ARM64_INS_STXRB:
		op->type = R_ANAL_OP_TYPE_STORE;
		if (ISPREINDEX64 () && (arm64_reg) REGBASE64 (2) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)MEMDISP64 (2);
		} else if (ISPOSTINDEX64 () && (arm64_reg) REGID64 (2) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)IMM64 (3);
		} else if (ISPREINDEX64 () && (arm64_reg) REGBASE64 (1) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)MEMDISP64 (1);
		} else if (ISPOSTINDEX64 () && (arm64_reg) REGID64 (1) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)IMM64 (2);
		}
		break;
	case ARM64_INS_ST1:
	case ARM64_INS_ST2:
	case ARM64_INS_ST3:
	case ARM64_INS_ST4:
		// Capstone omits the fixed post-index offset operand, so skip the
		// pre/post-index stack accounting above
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case ARM64_INS_LD1:
	case ARM64_INS_LD1R:
	case ARM64_INS_LD2:
	case ARM64_INS_LD2R:
	case ARM64_INS_LD3:
	case ARM64_INS_LD3R:
	case ARM64_INS_LD4:
	case ARM64_INS_LD4R:
		// structure loads likewise report no writeback offset operand
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case ARM64_INS_LDUR:
	case ARM64_INS_LDURB:
	case ARM64_INS_LDRSW:
	case ARM64_INS_LDRSB:
	case ARM64_INS_LDRSH:
	case ARM64_INS_LDR:
	case ARM64_INS_LDURSW:
	case ARM64_INS_LDP:
	case ARM64_INS_LDNP:
	case ARM64_INS_LDPSW:
	case ARM64_INS_LDRH:
	case ARM64_INS_LDRB:
		op->type = R_ANAL_OP_TYPE_LOAD;
		switch (insn->id) {
		case ARM64_INS_LDRB:
		case ARM64_INS_LDURB:
		case ARM64_INS_LDRSB:
			op->ptrsize = 1;
			break;
		case ARM64_INS_LDRH:
		case ARM64_INS_LDURH:
		case ARM64_INS_LDRSH:
			op->ptrsize = 2;
			break;
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDURSW:
		case ARM64_INS_LDPSW:
			op->ptrsize = 4;
			break;
		default:
			op->ptrsize = REGSIZE64 (0);
			break;
		}
		if (ISPREINDEX64 () && (arm64_reg) REGBASE64 (2) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)MEMDISP64 (2);
		} else if (ISPOSTINDEX64 () && (arm64_reg) REGID64 (2) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)IMM64 (3);
		} else if (ISPREINDEX64 () && (arm64_reg) REGBASE64 (1) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)MEMDISP64 (1);
		} else if (ISPOSTINDEX64 () && (arm64_reg) REGID64 (1) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)IMM64 (2);
		}
		if (REGID(0) == ARM_REG_PC) {
			op->type = R_ANAL_OP_TYPE_MJMP;
			if ((arm_cc)insn->detail->arm.cc != ARM_CC_AL) {
				op->type = R_ANAL_OP_TYPE_MCJMP;
			}
		} else {
			op->type = R_ANAL_OP_TYPE_LOAD;
		}
		switch (insn->id) {
		case ARM64_INS_LDPSW:
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDRSH:
		case ARM64_INS_LDRSB:
			op->sign = true;
			break;
		}
		if ((arm64_reg) REGBASE64(1) == ARM64_REG_X29) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = MEMDISP64(1);
		} else {
			if (ISMEM64 (1)) {
				// op->type = R_ANAL_OP_TYPE_LEA;
				op->disp = MEMDISP64 (1);
				op->refptr = 8;
			} else if (ISIMM64 (1)) {
				// op->type = R_ANAL_OP_TYPE_LEA;
				op->ptr = IMM64 (1);
				op->refptr = 8;
			} else {
				int d = (int)MEMDISP64(1);
				op->ptr = (d < 0)? -d: d;
				op->refptr = 4;
			}
		}
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_IRG:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM64_INS_BLRAA:
	case ARM64_INS_BLRAAZ:
	case ARM64_INS_BLRAB:
	case ARM64_INS_BLRABZ:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_RCALL;
		op->reg = cs_reg_name (handle, insn->detail->arm64.operands[0].reg);
		break;
	case ARM64_INS_BRAA:
	case ARM64_INS_BRAAZ:
	case ARM64_INS_BRAB:
	case ARM64_INS_BRABZ:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_RJMP;
		op->reg = cs_reg_name (handle, insn->detail->arm64.operands[0].reg);
		op->ireg = cs_reg_name (handle, insn->detail->arm64.operands[1].reg);
		break;
	case ARM64_INS_LDRAA:
	case ARM64_INS_LDRAB:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case ARM64_INS_RETAA:
	case ARM64_INS_RETAB:
	case ARM64_INS_ERETAA:
	case ARM64_INS_ERETAB:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_RET;
		break;
#endif
	case ARM64_INS_ERET:
		op->family = R_ANAL_OP_FAMILY_PRIV;
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case ARM64_INS_RET:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case ARM64_INS_BL: // bl 0x89480
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = IMM64(0);
		op->fail = addr + 4;
		break;
	case ARM64_INS_BLR: // blr x0
		op->type = R_ANAL_OP_TYPE_RCALL;
		op->fail = addr + 4;
		op->reg = cs_reg_name (handle, insn->detail->arm64.operands[0].reg);
		break;
	case ARM64_INS_CBZ:
	case ARM64_INS_CBNZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = IMM64(1);
		op->fail = addr + op->size;
		break;
	case ARM64_INS_TBZ:
	case ARM64_INS_TBNZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = IMM64(2);
		op->fail = addr + op->size;
		break;
	case ARM64_INS_BR:
		// op->type = R_ANAL_OP_TYPE_UJMP; // RJMP ?
		op->type = R_ANAL_OP_TYPE_RJMP;
		op->eob = true;
		op->reg = cs_reg_name (handle, insn->detail->arm64.operands[0].reg);
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_BC:
#endif
	case ARM64_INS_B:
		// BX LR == RET
		if ((arm64_reg) insn->detail->arm64.operands[0].reg == ARM64_REG_LR) {
			op->type = R_ANAL_OP_TYPE_RET;
		} else if (insn->detail->arm64.cc > ARM64_CC_INVALID && insn->detail->arm64.cc < ARM64_CC_AL) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM64(0);
			op->fail = addr + op->size;
		} else {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = IMM64(0);
		}
		break;
	default:
		R_LOG_DEBUG ("ARM64 analysis: Op type %d at 0x%" PFMT64x " not handled", insn->id, op->addr);
		break;
	}
}

static void anal_itblock(RArchSession *as, cs_insn *insn) {
	size_t i, size =  r_str_nlen (insn->mnemonic, 5);
	HtUU *ht_itblock = ht_itblock_for_session (as);
	HtUU *ht_it = ht_it_for_session (as);
	ht_uu_update (ht_itblock, insn->address,  size);
	for (i = 1; i < size; i++) {
		switch (insn->mnemonic[i]) {
		case 0x74: //'t'
			ht_uu_update (ht_it, insn->address + (i * insn->size), insn->detail->arm.cc);
			break;
		case 0x65: //'e'
			ht_uu_update (ht_it, insn->address + (i * insn->size), (insn->detail->arm.cc % 2)?
				insn->detail->arm.cc + 1: insn->detail->arm.cc - 1);
			break;
		default:
			break;
		}
	}
}

static void check_itblock(RArchSession *as, cs_insn *insn) {
	HtUU *ht_itblock = ht_itblock_for_session (as);
	HtUU *ht_it = ht_it_for_session (as);
	bool found;
	ut64 itlen = ht_uu_find (ht_itblock, insn->address, &found);
	if (found) {
		size_t x;
		for (x = 1; x < itlen; x++) {
			ht_uu_delete (ht_it, insn->address + (x*insn->size));
		}
		ht_uu_delete (ht_itblock, insn->address);
	}
}

// a pre- or post-indexed access through sp moves the stack like a push or pop
static void sp_writeback32(RAnalOp *op, cs_insn *insn) {
	const int last = OPCOUNT () - 1;
	if (ISPREINDEX32 ()) {
		if (REGBASE (last) == ARM_REG_SP && insn->detail->arm.operands[last].mem.index == ARM_REG_INVALID) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)MEMDISP (last);
		}
	} else if (ISPOSTINDEX32 ()) {
		if (REGBASE (last - 1) == ARM_REG_SP && ISIMM (last)) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)insn->detail->arm.operands[last].imm;
		}
	}
}

static void anop32(RArchSession *as, csh handle, RAnalOp *op, cs_insn *insn, bool thumb, const ut8 *buf, int len) {
	const ut64 addr = op->addr;
	const int pcdelta = thumb? 4: 8;
	int i;

	op->cond = cond_cs2r2 (insn->detail->arm.cc);
	if (op->cond == R_ANAL_CONDTYPE_NV) {
		op->type = R_ANAL_OP_TYPE_NOP;
		return;
	}
	op->cycles = 1;
	/* grab family */
	if (cs_insn_group (handle, insn, ARM_GRP_CRC)) {
		op->family = R_ANAL_OP_FAMILY_CRYPTO;
#if CS_API_MAJOR < 6
	// XXX - I can't find crypto in cs6
	} else if (cs_insn_group (handle, insn, ARM_GRP_CRYPTO)) {
		op->family = R_ANAL_OP_FAMILY_CRYPTO;
#endif
	} else if (cs_insn_group (handle, insn, ARM_GRP_PRIVILEGE)) {
		op->family = R_ANAL_OP_FAMILY_PRIV;
#if CS_API_MAJOR < 6
	// XXX - I can't find virtualization in cs6
	} else if (cs_insn_group (handle, insn, ARM_GRP_VIRTUALIZATION)) {
		op->family = R_ANAL_OP_FAMILY_VIRT;
#endif
	} else if (cs_insn_group (handle, insn, ARM_GRP_NEON)) {
		op->family = R_ANAL_OP_FAMILY_VEC;
	} else if (cs_insn_group (handle, insn, ARM_GRP_FPARMV8)) {
		op->family = R_ANAL_OP_FAMILY_FPU;
#if CS_API_MAJOR < 6
	// XXX - I can't find thumb2dsp in cs6
	} else if (cs_insn_group (handle, insn, ARM_GRP_THUMB2DSP)) {
		op->family = R_ANAL_OP_FAMILY_VEC;
#endif
	} else {
		op->family = R_ANAL_OP_FAMILY_CPU;
	}

	if (insn->id != ARM_INS_IT) {
		check_itblock (as, insn);
	}

	switch (insn->id) {
#if 0

If PC is specified for Rn, the value used is the address of the instruction plus 4.

These instructions cause a PC-relative forward branch using a table of single byte offsets (TBB) or halfword offsets (TBH). Rn provides a pointer to the table, and Rm supplies an index into the table. The branch length is twice the value of the byte (TBB) or the halfword (TBH) returned from the table. The target of the branch table must be in the same execution state.

jmp $$ + 4 + ( [delta] * 2 )

#endif
	case ARM_INS_TBH: // half word table
		op->type = R_ANAL_OP_TYPE_UJMP;
		op->cycles = 2;
		op->ptrsize = 2;
		op->ireg = r_str_getf (cs_reg_name (handle, INSOP (0).mem.index));
		break;
	case ARM_INS_TBB: // byte jump table
		op->type = R_ANAL_OP_TYPE_UJMP;
		op->cycles = 2;
		op->ptrsize = 1;
		op->ireg = r_str_getf (cs_reg_name (handle, INSOP (0).mem.index));
		break;
	case ARM_INS_PLD:
		op->type = R_ANAL_OP_TYPE_LEA; // not really a lea, just a prefetch
		if (ISMEM (0)) {
			int regBase = REGBASE(0);
			int delta = MEMDISP(0);
			if (regBase == ARM_REG_PC) {
				op->ptr = addr + 4 + delta;
			} else {
				// exotic pld
			}
		}
		break;
	case ARM_INS_IT:
		anal_itblock (as, insn);
		op->cycles = 2;
		break;
	case ARM_INS_BKPT:
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->cycles = 4;
		break;
	case ARM_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		op->cycles = 1;
		break;
	case ARM_INS_POP:
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -4LL * insn->detail->arm.op_count;
		// fallthrough
	case ARM_INS_FLDMDBX:
	case ARM_INS_FLDMIAX:
	case ARM_INS_LDMDA:
	case ARM_INS_LDMDB:
	case ARM_INS_LDMIB:
	case ARM_INS_LDM:
		op->type = R_ANAL_OP_TYPE_POP;
		op->cycles = 2;
		for (i = 0; i < insn->detail->arm.op_count; i++) {
			if (insn->detail->arm.operands[i].type == ARM_OP_REG &&
					insn->detail->arm.operands[i].reg == ARM_REG_PC) {
				if ((arm_cc)insn->detail->arm.cc == ARM_CC_AL) {
					op->type = R_ANAL_OP_TYPE_RET;
				} else {
					op->type = R_ANAL_OP_TYPE_CRET;
				}
				break;
			}
		}
		break;
	case ARM_INS_SUB:
		if (ISREG (0) && REGID (0) == ARM_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			if (ISIMM (1)) {
				//0x0000bf4e      95b0           sub sp, 0x54
				op->stackptr = IMM (1);
			} else if (ISIMM (2) && ISREG (1) && REGID (1) == ARM_REG_SP) {
				// 0x00008254    10d04de2     sub sp, sp, 0x10
				op->stackptr = IMM (2);
			}
			op->val = op->stackptr;
		} else {
			op->val = IMM64 (2);
		}
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case ARM_INS_SUBW:
	case ARM_INS_SSUB8:
	case ARM_INS_SSUB16:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case ARM_INS_ADD:
		if (ISREG (0) && REGID (0) == ARM_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			if (ISIMM (1)) {
				//add sp, 0x54
				op->stackptr = -(st64)IMM (1);
			} else if (ISIMM (2) && ISREG (1) && REGID (1) == ARM_REG_SP) {
				//add sp, sp, 0x10
				op->stackptr = -(st64)IMM (2);
			}
			// op->val = op->stackptr;
		} else {
			ut64 v = IMM (2);
			if (v) {
				op->val = v;
			}
		}
		op->cycles = 1;
		// fallthru
	case ARM_INS_ADC:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_ADD;
		if (REGID (0) == ARM_REG_PC) {
			op->type = R_ANAL_OP_TYPE_RJMP;
			if (REGID (1) == ARM_REG_PC && (arm_cc)insn->detail->arm.cc != ARM_CC_AL) {
				op->type = R_ANAL_OP_TYPE_RCJMP;
				op->fail = addr+op->size;
				op->jump = ((addr & ~3LL) + (thumb? 4: 8) + MEMDISP(1)) & UT64_MAX;
				op->ptr = (addr & ~3LL) + (thumb? 4: 8) + MEMDISP(1);
				op->refptr = 4;
				op->reg = r_str_getf (cs_reg_name (handle, INSOP (2).reg));
				break;
			}
		}
		break;
	case ARM_INS_ADDW:
	case ARM_INS_SADD8:
	case ARM_INS_SADD16:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case ARM_INS_SDIV:
	case ARM_INS_UDIV:
		op->cycles = 4;
		/* fall-thru */
	case ARM_INS_VDIV:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case ARM_INS_MUL:
	case ARM_INS_SMULL:
	case ARM_INS_UMULL:
		/* TODO: if next instruction is also a MUL, cycles are /=2 */
		/* also known as Register Indexing Addressing */
		op->cycles = 4;
		/* fall-thru */
	case ARM_INS_VMUL:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case ARM_INS_TRAP:
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->cycles = 2;
		break;
	case ARM_INS_MOV:
#if CS_API_MAJOR > 4
	case ARM_INS_MOVS:
#endif
		if (REGID(0) == ARM_REG_PC) {
			if (REGID(1) == ARM_REG_LR) {
				op->type = op->cond == R_ANAL_CONDTYPE_AL ? R_ANAL_OP_TYPE_RET : R_ANAL_OP_TYPE_CRET;
			} else {
				op->type = op->cond == R_ANAL_CONDTYPE_AL ? R_ANAL_OP_TYPE_RJMP : R_ANAL_OP_TYPE_RCJMP;
			}
		} else {
			op->type = op->cond == R_ANAL_CONDTYPE_AL ? R_ANAL_OP_TYPE_MOV : R_ANAL_OP_TYPE_CMOV;
		}
		if (ISIMM(1)) {
			op->val = IMM(1);
		}
		break;
	case ARM_INS_MOVT:
	case ARM_INS_MOVW:
	case ARM_INS_VMOVL:
	case ARM_INS_VMOVN:
	case ARM_INS_VQMOVUN:
	case ARM_INS_VQMOVN:
	case ARM_INS_SBFX:
	case ARM_INS_UBFX:
	case ARM_INS_BIC:
	case ARM_INS_BFI:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM_INS_VMOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_FPU;
		op->cycles = 2;
		break;
	case ARM_INS_UDF:
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->cycles = 4;
		break;
	case ARM_INS_SVC:
		if ((arm_cc)insn->detail->arm.cc == ARM_CC_AL) {
			op->type = R_ANAL_OP_TYPE_SWI;
		} else {
			op->type = R_ANAL_OP_TYPE_CSWI;
		}
		op->val = IMM (0);
		break;
	case ARM_INS_ROR:
	case ARM_INS_RRX:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case ARM_INS_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case ARM_INS_ORR:
	case ARM_INS_ORN:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case ARM_INS_EOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case ARM_INS_CMP:
	case ARM_INS_CMN:
	case ARM_INS_TST:
		if (ISIMM(1)) {
			op->val = IMM(1);
		}
		op->reg = r_str_getf (cs_reg_name (handle, INSOP (0).reg));
		/* fall-thru */
	case ARM_INS_VCMP:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case ARM_INS_LSL:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case ARM_INS_LSR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case ARM_INS_ASR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SAR;
		break;
	case ARM_INS_PUSH:
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 4LL * insn->detail->arm.op_count;
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case ARM_INS_STM:
	case ARM_INS_STMDA:
	case ARM_INS_STMDB:
		op->type = R_ANAL_OP_TYPE_PUSH;
// 0x00008160    04202de5     str r2, [sp, -4]!
// 0x000082a0    28000be5     str r0, [fp, -0x28]
		if (REGBASE(1) == ARM_REG_FP) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = MEMDISP(1);
		}
		break;
	case ARM_INS_STREX:
	case ARM_INS_STREXB:
	case ARM_INS_STREXD:
	case ARM_INS_STREXH:
		op->family = R_ANAL_OP_FAMILY_THREAD;
		/* fall-thru */
	case ARM_INS_STR:
	case ARM_INS_STRB:
	case ARM_INS_STRD:
	case ARM_INS_STRBT:
	case ARM_INS_STRH:
	case ARM_INS_STRHT:
	case ARM_INS_STRT:
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_STORE;
		if (ISMEM (1) && REGBASE (1) == ARM_REG_FP) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = (ut64)-MEMDISP (1);
		} else {
			sp_writeback32 (op, insn);
		}
		break;
	case ARM_INS_SXTB:
	case ARM_INS_SXTH:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM_INS_LDREX:
	case ARM_INS_LDREXB:
	case ARM_INS_LDREXD:
	case ARM_INS_LDREXH:
		op->family = R_ANAL_OP_FAMILY_THREAD;
		/* fall-thru */
	case ARM_INS_LDR:
	case ARM_INS_LDRD:
	case ARM_INS_LDRB:
	case ARM_INS_LDRBT:
	case ARM_INS_LDRH:
	case ARM_INS_LDRHT:
	case ARM_INS_LDRSB:
	case ARM_INS_LDRSBT:
	case ARM_INS_LDRSH:
	case ARM_INS_LDRSHT:
	case ARM_INS_LDRT:
		op->cycles = 4;
// 0x000082a8    28301be5     ldr r3, [fp, -0x28]
		if (REGID(0) == ARM_REG_PC) {
			op->type = R_ANAL_OP_TYPE_MJMP;
			if ((arm_cc)insn->detail->arm.cc != ARM_CC_AL) {
				//op->type = R_ANAL_OP_TYPE_MCJMP;
				op->type = R_ANAL_OP_TYPE_MCJMP;
			}
		} else {
			op->type = R_ANAL_OP_TYPE_LOAD;
		}
		switch (insn->id) {
		case ARM_INS_LDRB:
			op->ptrsize = 1;
			break;
		case ARM_INS_LDRH:
		case ARM_INS_LDRHT:
			op->ptrsize = 2;
			break;
		}
		if (ISMEM (1) && REGBASE (1) == ARM_REG_FP) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = -MEMDISP (1);
		} else if (ISMEM (1) && REGBASE (1) == ARM_REG_PC) {
			op->ptr = (addr & ~3LL) + (thumb? 4: 8) + MEMDISP (1);
			op->refptr = 4;
			if (REGID(0) == ARM_REG_PC && (arm_cc)insn->detail->arm.cc != ARM_CC_AL) {
				//op->type = R_ANAL_OP_TYPE_MCJMP;
				op->type = R_ANAL_OP_TYPE_UCJMP;
				op->fail = addr+op->size;
				op->jump = ((addr & ~3LL) + (thumb? 4: 8) + MEMDISP (1)) & UT64_MAX;
				op->ireg = r_str_getf (cs_reg_name (handle, INSOP (1).mem.index));
				break;
			}
		} else {
			sp_writeback32 (op, insn);
		}
		break;
	case ARM_INS_MRS:
	case ARM_INS_MSR:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_PRIV;
		break;
	case ARM_INS_BLX:
		op->cycles = 4;
		if (ISREG(0)) {
			/* blx reg */
			op->type = R_ANAL_OP_TYPE_RCALL;
		} else {
			/* blx label */
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = IMM(0) & UT32_MAX;
			op->fail = addr + op->size;
			op->hint.new_bits = as->config->bits == 32? 16 : 32;
			//switch instruction set always with blx label
			// r_anal_hint_set_bits (a, op->jump, a->config->bits == 32? 16 : 32);
		}
		break;
	case ARM_INS_BL:
		/* bl label */
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = IMM(0) & UT32_MAX;
		op->fail = addr + op->size;
		op->hint.new_bits = as->config->bits;
		break;
	case ARM_INS_CBZ:
	case ARM_INS_CBNZ:
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = IMM (1) & UT32_MAX;
		op->fail = addr + op->size;
		if (op->jump == op->fail) {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->fail = UT64_MAX;
		}
		break;
	case ARM_INS_B:
		/* b.cc label */
		op->cycles = 4;
		if ((arm_cc)insn->detail->arm.cc == ARM_CC_INVALID) {
			op->type = R_ANAL_OP_TYPE_ILL;
			op->fail = addr+op->size;
		} else if ((arm_cc)insn->detail->arm.cc == ARM_CC_AL) {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->fail = UT64_MAX;
		} else {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr+op->size;
		}
		op->jump = IMM(0) & UT32_MAX;
		// propagate bits to create correctly hints ranges
		op->hint.new_bits = as->config->bits;
		break;
	case ARM_INS_BX:
	case ARM_INS_BXJ:
		/* bx reg */
		op->cycles = 4;
		switch (REGID(0)) {
		case ARM_REG_LR:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case ARM_REG_IP:
			op->type = R_ANAL_OP_TYPE_UJMP;
			break;
		case ARM_REG_PC:
			// bx pc is well known without ESIL
			op->type = R_ANAL_OP_TYPE_UJMP;
			op->jump = (addr & ~3LL) + pcdelta;
			op->hint.new_bits = 32;
			break;
		default:
			op->type = R_ANAL_OP_TYPE_UJMP;
			op->eob = true;
			break;
		}
		break;
	case ARM_INS_ADR:
		op->cycles = 2;
		op->type = R_ANAL_OP_TYPE_LEA;
		// Set the pointer address and align it
		op->ptr = IMM(1) + addr + 4 - (addr%4);
		op->refptr = 1;
		break;
	case ARM_INS_UXTAB:
	case ARM_INS_UXTAB16:
		op->type = R_ANAL_OP_TYPE_ADD;
		op->ptr = 0LL;
		op->ptrsize = 1;
		break;
	case ARM_INS_UXTAH:
		op->type = R_ANAL_OP_TYPE_ADD;
		op->ptr = 0LL;
		op->ptrsize = 2;
		break;
	case ARM_INS_UXTB:
	case ARM_INS_UXTB16:
		op->type = R_ANAL_OP_TYPE_CAST;
		op->ptr = 0LL;
		op->ptrsize = 1;
		break;
	case ARM_INS_UXTH:
		op->type = R_ANAL_OP_TYPE_CAST;
		op->ptr = 0LL;
		op->ptrsize = 2;
		break;
	default:
		R_LOG_DEBUG ("ARM analysis: Op type %d at 0x%" PFMT64x " not handled", insn->id, op->addr);
		break;
	}
#if 0
	// TODO needs rewrite
	bool found = 0;
	ut64 itcond;
	HtUU *ht_it = ht_it_for_session (as);
	itcond = ht_uu_find (ht_it,  addr, &found);
	if (found) {
		insn->detail->arm.cc = itcond;
		insn->detail->arm.update_flags = 0;
		free (op->mnemonic);
		op->mnemonic = r_str_newf ("%s%s%s%s",
			r_arch_optype_tostring (op->type),
			cc_name (itcond),
			insn->op_str[0]? " ": "",
			insn->op_str);
		op->cond = itcond;
	}
#endif
}

#if 1
// TODO arch plugins should NOT set register values
static inline bool is_valid(arm_reg reg) {
	return reg != ARM_REG_INVALID;
}

// XXX this function is a disaster
static int parse_reg_name(const char **reg_base, const char **reg_delta, csh handle, cs_insn *insn, int reg_num) {
	cs_arm_op armop = INSOP (reg_num);
	switch (armop.type) {
	case ARM_OP_REG:
		*reg_base = cs_reg_name (handle, armop.reg);
		break;
	case ARM_OP_MEM:
		if (is_valid (armop.mem.base) && is_valid (armop.mem.index)) {
			*reg_base = cs_reg_name (handle, armop.mem.base);
			*reg_delta = cs_reg_name (handle, armop.mem.index);
		} else if (is_valid (armop.mem.base)) {
			*reg_base = cs_reg_name (handle, armop.mem.base);
		} else if (is_valid (armop.mem.index)) {
			*reg_base = cs_reg_name (handle, armop.mem.index);
		}
		break;
	default:
		break;
	}

	return 0;
}

static bool is_valid64(arm64_reg reg) {
	return reg != ARM64_REG_INVALID;
}

static int parse_reg64_name(const char** reg_base, const char **reg_delta, csh handle, cs_insn *insn, int reg_num) {
	cs_arm64_op armop = INSOP64 (reg_num);
	switch (armop.type) {
	case ARM64_OP_REG:
		*reg_base = cs_reg_name (handle, armop.reg);
		break;
	case ARM64_OP_MEM:
		if (is_valid64 (armop.mem.base) && is_valid64 (armop.mem.index)) {
			*reg_base = cs_reg_name (handle, armop.mem.base);
			*reg_delta = cs_reg_name (handle, armop.mem.index);
		} else if (is_valid64 (armop.mem.base)) {
			*reg_base = cs_reg_name (handle, armop.mem.base);
		} else if (is_valid64 (armop.mem.index)) {
			*reg_base = cs_reg_name (handle, armop.mem.index);
		}
		break;
	default:
		break;
	}
	if (*reg_base && **reg_base == 'w') {
		int reg_idx = atoi ((*reg_base) + 1); // XXX dont use atoi
		if (reg_idx >= 0 && reg_idx < R_ARRAY_SIZE (reg_list)) {
			*reg_base = reg_list [reg_idx];
		}
	}
	return 0;
}
#endif

static void set_opdir(RAnalOp *op) {
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_LOAD:
		op->direction = R_ANAL_OP_DIR_READ;
		break;
	case R_ANAL_OP_TYPE_STORE:
		op->direction = R_ANAL_OP_DIR_WRITE;
		break;
	case R_ANAL_OP_TYPE_LEA:
		op->direction = R_ANAL_OP_DIR_REF;
		break;
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_MJMP:
	case R_ANAL_OP_TYPE_UCALL:
		op->direction = R_ANAL_OP_DIR_EXEC;
		break;
	default:
		break;
	}
}

#if 1
// TODO arch plugins should NOT set register values
static int arm_memref_size(RAnalOp *op, cs_insn *insn, int x, int bits) {
	if (op && op->ptrsize > 0) {
		return op->ptrsize;
	}
	if (bits == 64) {
		switch (insn->id) {
		case ARM64_INS_LDARB:
		case ARM64_INS_LDAXRB:
		case ARM64_INS_LDTRB:
		case ARM64_INS_LDTRSB:
		case ARM64_INS_LDURB:
		case ARM64_INS_LDURSB:
		case ARM64_INS_LDXRB:
		case ARM64_INS_LDRB:
		case ARM64_INS_LDRSB:
		case ARM64_INS_STLXRB:
		case ARM64_INS_STTRB:
		case ARM64_INS_STURB:
		case ARM64_INS_STXRB:
		case ARM64_INS_STRB:
			return 1;
		case ARM64_INS_LDARH:
		case ARM64_INS_LDAXRH:
		case ARM64_INS_LDTRH:
		case ARM64_INS_LDTRSH:
		case ARM64_INS_LDURH:
		case ARM64_INS_LDURSH:
		case ARM64_INS_LDXRH:
		case ARM64_INS_LDRH:
		case ARM64_INS_LDRSH:
		case ARM64_INS_STLXRH:
		case ARM64_INS_STTRH:
		case ARM64_INS_STURH:
		case ARM64_INS_STXRH:
		case ARM64_INS_STRH:
			return 2;
		case ARM64_INS_LDTRSW:
		case ARM64_INS_LDURSW:
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDPSW:
			return 4;
		case ARM64_INS_STXR:
		case ARM64_INS_STLXR:
			return REGSIZE64 (1);
		default:
			return REGSIZE64 (x > 0 ? x - 1 : x);
		}
	}
	switch (insn->id) {
	case ARM_INS_LDRB:
	case ARM_INS_LDRBT:
	case ARM_INS_LDRSB:
	case ARM_INS_LDRSBT:
	case ARM_INS_LDREXB:
	case ARM_INS_STRB:
	case ARM_INS_STRBT:
	case ARM_INS_STREXB:
		return 1;
	case ARM_INS_LDRH:
	case ARM_INS_LDRHT:
	case ARM_INS_LDRSH:
	case ARM_INS_LDRSHT:
	case ARM_INS_LDREXH:
	case ARM_INS_STRH:
	case ARM_INS_STRHT:
	case ARM_INS_STREXH:
		return 2;
	case ARM_INS_LDRD:
	case ARM_INS_LDREXD:
	case ARM_INS_STRD:
	case ARM_INS_STREXD:
		return 8;
	default:
		return 4;
	}
}

static void set_src_dst(RAnalOp *op, RAnalValue *val, csh *handle, cs_insn *insn, int x, int bits) {
	if (!val) {
		return;
	}
	cs_arm_op armop = INSOP (x);
	cs_arm64_op arm64op = INSOP64 (x);
	if (bits == 64) {
		parse_reg64_name ((const char **)&val->reg, (const char **)&val->regdelta, *handle, insn, x);
	} else {
		parse_reg_name ((const char**)&val->reg, (const char**)&val->regdelta, *handle, insn, x);
	}
	if (bits == 64) {
		switch (arm64op.type) {
		case ARM64_OP_REG:
			val->type = R_ANAL_VAL_REG;
			break;
		case ARM64_OP_MEM:
			val->type = R_ANAL_VAL_MEM;
			val->memref = arm_memref_size (op, insn, x, bits);
			val->delta = arm64op.mem.disp;
			break;
		case ARM64_OP_IMM:
			val->type = R_ANAL_VAL_IMM;
			val->imm = shifted_imm64 (&arm64op, 64);
			break;
		default:
			break;
		}
	} else {
		switch (armop.type) {
		case ARM_OP_REG:
			val->type = R_ANAL_VAL_REG;
			break;
		case ARM_OP_MEM:
			val->type = R_ANAL_VAL_MEM;
			val->memref = arm_memref_size (op, insn, x, bits);
			val->mul = armop.mem.scale;
			val->delta = armop.mem.disp;
			break;
		case ARM_OP_IMM:
			val->type = R_ANAL_VAL_IMM;
			val->imm = armop.imm;
			break;
		default:
			break;
		}
	}
}
#endif

static void create_src_dst(RAnalOp *op) {
	R_UNUSED RArchValue *_ = NULL;
	_ = RVecRArchValue_emplace_back (&op->srcs);
	_ = RVecRArchValue_emplace_back (&op->srcs);
	_ = RVecRArchValue_emplace_back (&op->srcs);
	_ = RVecRArchValue_emplace_back (&op->dsts);
}

// the second slot of a paired load or store, one element above the first
static void add_pair_slot(RVecRArchValue *side, cs_insn *insn) {
	switch (insn->id) {
	case ARM64_INS_LDP:
	case ARM64_INS_LDNP:
	case ARM64_INS_LDPSW:
	case ARM64_INS_STP:
	case ARM64_INS_STNP:
		break;
	default:
		return;
	}
	const RAnalValue *first = RVecRArchValue_at (side, 0);
	if (!first || !first->memref) {
		return;
	}
	RAnalValue second = *first;
	second.delta += second.memref;
	RVecRArchValue_push_back (side, &second);
}

static void op_fillval(RArchSession *as, RAnalOp *op, csh handle, cs_insn *insn, int bits) {
	create_src_dst (op);
	int i;
	int count = bits == 64 ? insn->detail->arm64.op_count : insn->detail->arm.op_count;
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_CMP:
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_MUL:
	case R_ANAL_OP_TYPE_DIV:
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SAL:
	case R_ANAL_OP_TYPE_SAR:
	case R_ANAL_OP_TYPE_OR:
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_NOR:
	case R_ANAL_OP_TYPE_NOT:
	case R_ANAL_OP_TYPE_LOAD:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_ROR:
	case R_ANAL_OP_TYPE_ROL:
	case R_ANAL_OP_TYPE_CAST:
		for (i = 1; i < count; i++) {
			if (bits == 64) {
				cs_arm64_op arm64op = INSOP64 (i);
				if (arm64op.access == CS_AC_WRITE) {
					continue;
				}
			} else {
				cs_arm_op armop = INSOP (i);
				if (armop.access == CS_AC_WRITE) {
					continue;
				}
			}
			break;
		}
		// TODO arch plugins should NOT set register values
		{
			int j;
			for (j = 0; j < 3; j++, i++) {
				set_src_dst (op, RVecRArchValue_at (&op->srcs, j), &handle, insn, i, bits);
			}
			set_src_dst (op, RVecRArchValue_at (&op->dsts, 0), &handle, insn, 0, bits);
		}
#if CS_API_MAJOR >= 6
		if (bits == 64 && (insn->id == ARM64_INS_MADPT || insn->id == ARM64_INS_MLAPT)) {
			set_src_dst (op, RVecRArchValue_at (&op->srcs, 2), &handle, insn, 0, bits);
		}
#endif
		if (bits == 64) {
			add_pair_slot (&op->srcs, insn);
		}
		break;
	case R_ANAL_OP_TYPE_STORE:
		if (count > 2) {
			if (bits == 64) {
				cs_arm64_op arm64op = INSOP64 (count - 1);
				if ((arm64_op_type) arm64op.type == ARM64_OP_IMM) {
					count--;
				}
			} else {
				cs_arm_op armop = INSOP (count - 1);
				if (armop.type == ARM_OP_IMM) {
					count--;
				}
			}
		}
		// TODO arch plugins should NOT set register values
		{
			set_src_dst (op, RVecRArchValue_at (&op->dsts, 0), &handle, insn, --count, bits);
			if (bits == 64) {
				add_pair_slot (&op->dsts, insn);
			}
			int j;
			for (j = 0; j < 3 && j < count; j++) {
				set_src_dst (op, RVecRArchValue_at (&op->srcs, j), &handle, insn, j, bits);
			}
		}
		break;
	default:
		break;
	}
	if ((bits == 64) && HASMEMINDEX64 (1)) {
		op->ireg = r_str_getf (cs_reg_name (handle, INSOP64 (1).mem.index));
	} else if (HASMEMINDEX (1)) {
		op->ireg = r_str_getf (cs_reg_name (handle, INSOP (1).mem.index));
		op->scale = INSOP (1).mem.scale;
	}
}

static inline bool is_valid_mnemonic(const char *m) {
	return !r_str_startswith (m, "hint") && !r_str_startswith (m, "udf");
}

static int analop(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	csh *cs_handle = cs_handle_for_session (as);
	op->size = (as->config->bits == 16)? 2: 4;
	op->addr = addr;
	if (!buf) {
		buf = op->bytes;
		len = op->size;
	}
#if CS_API_MAJOR < 6
	if (as->config->bits == 64 && len >= 4 && hack_decode_cpa (op, r_read_le32 (buf), mask)) {
		return op->size;
	}
#endif
	RArchCSInsn csi;
	bool ok = r_arch_cs_disasm_iter (*cs_handle, buf, len, addr, &csi);
	cs_insn *insn = &csi.insn;
	if (ok && is_valid_mnemonic (insn->mnemonic)) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			free (op->mnemonic);
			op->mnemonic = r_str_newf ("%s%s%s",
					insn->mnemonic,
					insn->op_str[0]? " ": "",
					insn->op_str);
			r_str_replace_char (op->mnemonic, '#', '\x00');
		}
		// bool thumb = cs_insn_group (cs_handle, insn, ARM_GRP_THUMB);
		bool thumb = as->config->bits == 16;
		op->size = insn->size;
		op->id = insn->id;
		if (as->config->bits == 64) {
			anop64 (*cs_handle, op, insn);
			if (mask & R_ARCH_OP_MASK_OPEX) {
				opex64 (&op->opex, *cs_handle, insn);
			}
			if (mask & R_ARCH_OP_MASK_ESIL) {
				analop64_esil (as, op, addr, buf, len, cs_handle, insn);
			}
		} else {
			anop32 (as, *cs_handle, op, insn, thumb, (ut8*)buf, len);
			if (mask & R_ARCH_OP_MASK_OPEX) {
				opex (&op->opex, *cs_handle, insn);
			}
			if (mask & R_ARCH_OP_MASK_ESIL) {
				analop_esil (as, op, addr, buf, len, cs_handle, insn, thumb);
			}
		}
		set_opdir (op);
		if (mask & R_ARCH_OP_MASK_VAL) {
			op_fillval (as, op, *cs_handle, insn, as->config->bits);
		}
	} else {
		op->size = 4;
		op->type = R_ANAL_OP_TYPE_ILL;
		if (!buf || len < 4) {
			if (mask & R_ARCH_OP_MASK_DISASM) {
				free (op->mnemonic);
				op->mnemonic = strdup ("invalid");
			}
			return -1;
		}
		hacky_arm_anal (as, op, buf, len, mask);
		if (mask & R_ARCH_OP_MASK_DISASM) {
			if (hacky_arm_asm (as, op, buf, len) < 1) {
				free (op->mnemonic);
				op->mnemonic = strdup ("invalid");
			} else if (op->type == R_ANAL_OP_TYPE_ILL) {
				op->type = R_ANAL_OP_TYPE_UNK;	// this is because hacky_arm_anal and hacky_arm_asm work differently
			}
		}
	}
	return true;
}

static bool plugin_changed(RArchSession *as) {
	PluginData *pd = as->data;
	if (as->config->bits != pd->bits) {
		return true;
	}
	if (R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config) != pd->bigendian) {
		return true;
	}
	return strcmp (r_str_get (pd->cpu), r_str_get (as->config->cpu)) != 0;
}

static bool init(RArchSession *as);
static bool fini(RArchSession *as);

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	if (plugin_changed (as)) {
		fini (as);
		init (as);
	}
	csh *handle = cs_handle_for_session (as);
	PluginData *pd = as->data;
	if (pd && as->config->syntax != pd->last_syntax) {
		pd->last_syntax = as->config->syntax;
		int mode = (as->config->syntax == R_ARCH_SYNTAX_REGNUM)
				? CS_OPT_SYNTAX_NOREGNAME: CS_OPT_SYNTAX_DEFAULT;
		cs_option (*handle, CS_OPT_SYNTAX, mode);
	}
	return analop (as, op, op->addr, op->bytes, op->size, mask) >= 1;
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_WODST:
		return 1;
	case R_ARCH_INFO_DATA_ALIGN:
	case R_ARCH_INFO_INVOP_SIZE:
	case R_ARCH_INFO_MAXOP_SIZE:
		break;
	case R_ARCH_INFO_MINOP_SIZE:
	case R_ARCH_INFO_CODE_ALIGN:
		if (as->config && as->config->bits == 16) {
			return 2;
		}
		break;
	}
	return 4; // XXX
}

#include "preludes.inc.c"

extern char *r_arm_cs_mnemonics(RArchSession *as, csh *cs_handle, int id, bool json);
extern char *r_arm64_cs_mnemonics(RArchSession *as, csh *cs_handle, int id, bool json);

static char *arm_mnemonics(RArchSession *as, int id, bool json) {
	csh *cs_handle = cs_handle_for_session (as);
	if (as->config->bits == 64) {
		return r_arm64_cs_mnemonics (as, cs_handle, id, json);
	}
	return r_arm_cs_mnemonics (as, cs_handle, id, json);
}

extern bool r_arm_arch_cs_init(RArchSession *as, csh *cs_handle);
extern bool r_arm64_arch_cs_init(RArchSession *as, csh *cs_handle);

static inline bool cs_init(RArchSession *as, csh *cs_handle) {
	if (as->config->bits == 64) {
		return r_arm64_arch_cs_init (as, cs_handle);
	}
	return r_arm_arch_cs_init (as, cs_handle);
}

static bool init(RArchSession* as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	as->data = R_NEW0 (PluginData);
	csh *cs_handle = cs_handle_for_session (as);
	if (!cs_init (as, cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (as->data);
		return false;
	}

	PluginData *pd = as->data;
	pd->bits = as->config->bits;
	pd->bigendian = R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config);
	pd->cpu = as->config->cpu? strdup (as->config->cpu): NULL;
	pd->ht_it = ht_uu_new0 ();
	if (!pd->ht_it) {
		R_LOG_ERROR ("Cannot initialize 'ht_it'");
		cs_close (&(pd->cs_handle));
		R_FREE (as->data);
		return false;
	}

	pd->ht_itblock = ht_uu_new0 ();
	if (!pd->ht_itblock) {
		R_LOG_ERROR ("Cannot initialize 'ht_itblock'");
		ht_uu_free (pd->ht_it);
		cs_close (&(pd->cs_handle));
		R_FREE (as->data);
		return false;
	}
	return true;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);

	PluginData *pd = (PluginData*) as->data;
	ht_uu_free (pd->ht_itblock);
	ht_uu_free (pd->ht_it);
	free (pd->cpu);
	cs_close (&(pd->cs_handle));
	R_FREE (as->data);
	return true;
}

const RArchPlugin r_arch_plugin_arm_cs = {
	.meta = {
		.name = "arm",
		.desc = "Capstone ARM analyzer",
		.license = "Apache-2.0",
	},
	.arch = "arm",
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.cpus = "cortex,v8",
#if 0
	// made obsolete by "e anal.mask = true"
	.anal_mask = anal_mask,
#endif
	.preludes = anal_preludes,
	.decode = decode,
	.init = init,
	.fini = fini,
	.info = archinfo,
	.regs = regs,
	.mnemonics = arm_mnemonics,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_arm_cs,
	.version = R2_VERSION
};
#endif
