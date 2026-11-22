/*
 * GENERATED -- do not edit.
 *
 * The IEEE 802.11 id registries and element shapes, extracted from
 * src/common/ieee802_11_defs.h, ieee802_11_common.h and ieee802_11_common.c by
 * fuzzing/ledger/registries.py. Regenerate with:
 *
 *	python3 fuzzing/ledger/registries.py . --emit-c > src/common/fuzz_registries.h
 *
 * and check it with --check, which fails when a source has gained a member or
 * changed a shape this file does not have. That check is the point of
 * generating it: upstream adds members regularly, and a table that quietly
 * falls behind re-narrows the very spotlight the synthesis exists to widen --
 * silently, because a registry member that is never emitted looks exactly like
 * one that is, and an id built under the wrong shape looks exactly like one
 * built under the right one.
 *
 * Membership comes from the SECTION of the header each define sits in, not
 * from its name. Five constants in this tree are named for one registry and
 * belong to another.
 */

#ifndef FUZZ_REGISTRIES_H
#define FUZZ_REGISTRIES_H

#include "ieee802_11_defs.h"

/* element id: 183 distinct value(s) */
static const u8 fuzz_elem_ids[] = {
	0, 1, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14,
	15, 16, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
	42, 43, 44, 45, 46, 48, 50, 51, 52, 53, 54, 55,
	56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
	68, 69, 70, 71, 72, 73, 74, 75, 76, 78, 79, 80,
	81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92,
	93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 104, 105,
	106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
	118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 130, 131,
	132, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147,
	148, 151, 152, 153, 154, 156, 157, 158, 159, 160, 161, 162,
	163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 174, 175,
	177, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
	192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 204,
	205, 206, 213, 216, 217, 221, 227, 232, 237, 239, 240, 241,
	242, 244, 255,
};

/* element id, named. Aliases are listed in the comment. */
static const char * const fuzz_elem_ids_names[] = {
	"WLAN_EID_SSID",
	"WLAN_EID_SUPP_RATES",
	"WLAN_EID_DS_PARAMS",
	"WLAN_EID_CF_PARAMS",
	"WLAN_EID_TIM",
	"WLAN_EID_IBSS_PARAMS",
	"WLAN_EID_COUNTRY",
	"WLAN_EID_REQUEST",
	"WLAN_EID_BSS_LOAD",
	"WLAN_EID_EDCA_PARAM_SET",
	"WLAN_EID_TSPEC",
	"WLAN_EID_TCLAS",
	"WLAN_EID_SCHEDULE",
	"WLAN_EID_CHALLENGE",
	"WLAN_EID_PWR_CONSTRAINT",
	"WLAN_EID_PWR_CAPABILITY",
	"WLAN_EID_TPC_REQUEST",
	"WLAN_EID_TPC_REPORT",
	"WLAN_EID_SUPPORTED_CHANNELS",
	"WLAN_EID_CHANNEL_SWITCH",
	"WLAN_EID_MEASURE_REQUEST",
	"WLAN_EID_MEASURE_REPORT",
	"WLAN_EID_QUIET",
	"WLAN_EID_IBSS_DFS",
	"WLAN_EID_ERP_INFO",
	"WLAN_EID_TS_DELAY",
	"WLAN_EID_TCLAS_PROCESSING",
	"WLAN_EID_HT_CAP",
	"WLAN_EID_QOS",
	"WLAN_EID_RSN",
	"WLAN_EID_EXT_SUPP_RATES",
	"WLAN_EID_AP_CHANNEL_REPORT",
	"WLAN_EID_NEIGHBOR_REPORT",
	"WLAN_EID_RCPI",
	"WLAN_EID_MOBILITY_DOMAIN",
	"WLAN_EID_FAST_BSS_TRANSITION",
	"WLAN_EID_TIMEOUT_INTERVAL",
	"WLAN_EID_RIC_DATA",
	"WLAN_EID_DSE_REGISTERED_LOCATION",
	"WLAN_EID_SUPPORTED_OPERATING_CLASSES",
	"WLAN_EID_EXT_CHANSWITCH_ANN",
	"WLAN_EID_HT_OPERATION",
	"WLAN_EID_SECONDARY_CHANNEL_OFFSET",
	"WLAN_EID_BSS_AVERAGE_ACCESS_DELAY",
	"WLAN_EID_ANTENNA",
	"WLAN_EID_RSNI",
	"WLAN_EID_MEASUREMENT_PILOT_TRANSMISSION",
	"WLAN_EID_BSS_AVAILABLE_ADM_CAPA",
	"WLAN_EID_BSS_AC_ACCESS_DELAY",
	"WLAN_EID_TIME_ADVERTISEMENT",
	"WLAN_EID_RRM_ENABLED_CAPABILITIES",
	"WLAN_EID_MULTIPLE_BSSID",
	"WLAN_EID_20_40_BSS_COEXISTENCE",
	"WLAN_EID_20_40_BSS_INTOLERANT",
	"WLAN_EID_OVERLAPPING_BSS_SCAN_PARAMS",
	"WLAN_EID_RIC_DESCRIPTOR",
	"WLAN_EID_MMIE",
	"WLAN_EID_EVENT_REQUEST",
	"WLAN_EID_EVENT_REPORT",
	"WLAN_EID_DIAGNOSTIC_REQUEST",
	"WLAN_EID_DIAGNOSTIC_REPORT",
	"WLAN_EID_LOCATION_PARAMETERS",
	"WLAN_EID_NONTRANSMITTED_BSSID_CAPA",
	"WLAN_EID_SSID_LIST",
	"WLAN_EID_MULTIPLE_BSSID_INDEX",
	"WLAN_EID_FMS_DESCRIPTOR",
	"WLAN_EID_FMS_REQUEST",
	"WLAN_EID_FMS_RESPONSE",
	"WLAN_EID_QOS_TRAFFIC_CAPABILITY",
	"WLAN_EID_BSS_MAX_IDLE_PERIOD",
	"WLAN_EID_TFS_REQ",
	"WLAN_EID_TFS_RESP",
	"WLAN_EID_WNMSLEEP",
	"WLAN_EID_TIM_BROADCAST_REQUEST",
	"WLAN_EID_TIM_BROADCAST_RESPONSE",
	"WLAN_EID_COLLOCATED_INTERFERENCE_REPORT",
	"WLAN_EID_CHANNEL_USAGE",
	"WLAN_EID_TIME_ZONE",
	"WLAN_EID_DMS_REQUEST",
	"WLAN_EID_DMS_RESPONSE",
	"WLAN_EID_LINK_ID",
	"WLAN_EID_WAKEUP_SCHEDULE",
	"WLAN_EID_CHANNEL_SWITCH_TIMING",
	"WLAN_EID_PTI_CONTROL",
	"WLAN_EID_TPU_BUFFER_STATUS",
	"WLAN_EID_INTERWORKING",
	"WLAN_EID_ADV_PROTO",
	"WLAN_EID_EXPEDITED_BANDWIDTH_REQ",
	"WLAN_EID_QOS_MAP_SET",
	"WLAN_EID_ROAMING_CONSORTIUM",
	"WLAN_EID_EMERGENCY_ALERT_ID",
	"WLAN_EID_MESH_CONFIG",
	"WLAN_EID_MESH_ID",
	"WLAN_EID_MESH_LINK_METRIC_REPORT",
	"WLAN_EID_CONGESTION_NOTIFICATION",
	"WLAN_EID_PEER_MGMT",
	"WLAN_EID_MESH_CHANNEL_SWITCH_PARAMETERS",
	"WLAN_EID_MESH_AWAKE_WINDOW",
	"WLAN_EID_BEACON_TIMING",
	"WLAN_EID_MCCAOP_SETUP_REQUEST",
	"WLAN_EID_MCCAOP_SETUP_REPLY",
	"WLAN_EID_MCCAOP_ADVERTISEMENT",
	"WLAN_EID_MCCAOP_TEARDOWN",
	"WLAN_EID_GANN",
	"WLAN_EID_RANN",
	"WLAN_EID_EXT_CAPAB",
	"WLAN_EID_PREQ",
	"WLAN_EID_PREP",
	"WLAN_EID_PERR",
	"WLAN_EID_PXU",
	"WLAN_EID_PXUC",
	"WLAN_EID_AMPE",
	"WLAN_EID_MIC",
	"WLAN_EID_DESTINATION_URI",
	"WLAN_EID_U_APSD_COEX",
	"WLAN_EID_DMG_WAKEUP_SCHEDULE",
	"WLAN_EID_EXTENDED_SCHEDULE",
	"WLAN_EID_STA_AVAILABILITY",
	"WLAN_EID_DMG_TSPEC",
	"WLAN_EID_NEXT_DMG_ATI",
	"WLAN_EID_DMG_CAPABILITIES",
	"WLAN_EID_DMG_OPERATION",
	"WLAN_EID_DMG_BSS_PARAMETER_CHANGE",
	"WLAN_EID_DMG_BEAM_REFINEMENT",
	"WLAN_EID_CHANNEL_MEASUREMENT_FEEDBACK",
	"WLAN_EID_CCKM",
	"WLAN_EID_AWAKE_WINDOW",
	"WLAN_EID_MULTI_BAND",
	"WLAN_EID_ADDBA_EXTENSION",
	"WLAN_EID_NEXTPCP_LIST",
	"WLAN_EID_PCP_HANDOVER",
	"WLAN_EID_DMG_LINK_MARGIN",
	"WLAN_EID_SWITCHING_STREAM",
	"WLAN_EID_SESSION_TRANSITION",
	"WLAN_EID_DYNAMIC_TONE_PAIRING_REPORT",
	"WLAN_EID_CLUSTER_REPORT",
	"WLAN_EID_REPLAY_CAPABILITIES",
	"WLAN_EID_RELAY_TRANSFER_PARAM_SET",
	"WLAN_EID_BEAMLINK_MAINTENANCE",
	"WLAN_EID_MULTIPLE_MAC_SUBLAYERS",
	"WLAN_EID_U_PID",
	"WLAN_EID_DMG_LINK_ADAPTATION_ACK",
	"WLAN_EID_MCCAOP_ADVERTISEMENT_OVERVIEW",
	"WLAN_EID_QUIET_PERIOD_REQUEST",
	"WLAN_EID_QUIET_PERIOD_RESPONSE",
	"WLAN_EID_QMF_POLICY",
	"WLAN_EID_ECAPC_POLICY",
	"WLAN_EID_CLUSTER_TIME_OFFSET",
	"WLAN_EID_INTRA_ACCESS_CATEGORY_PRIORITY",
	"WLAN_EID_SCS_DESCRIPTOR",
	"WLAN_EID_QLOAD_REPORT",
	"WLAN_EID_HCCA_TXOP_UPDATE_COUNT",
	"WLAN_EID_HIGHER_LAYER_STREAM_ID",
	"WLAN_EID_GCR_GROUP_ADDRESS",
	"WLAN_EID_ANTENNA_SECTOR_ID_PATTERN",
	"WLAN_EID_VHT_CAP",
	"WLAN_EID_VHT_OPERATION",
	"WLAN_EID_EXTENDED_BSS_LOAD",
	"WLAN_EID_WIDE_BW_CHSWITCH",
	"WLAN_EID_TRANSMIT_POWER_ENVELOPE",
	"WLAN_EID_CHANNEL_SWITCH_WRAPPER",
	"WLAN_EID_AID",
	"WLAN_EID_QUIET_CHANNEL",
	"WLAN_EID_OPERATING_MODE_NOTIFICATION",
	"WLAN_EID_UPSIM",
	"WLAN_EID_REDUCED_NEIGHBOR_REPORT",
	"WLAN_EID_TVHT_OPERATION",
	"WLAN_EID_DEVICE_LOCATION",
	"WLAN_EID_WHITE_SPACE_MAP",
	"WLAN_EID_FTM_PARAMETERS",
	"WLAN_EID_S1G_BCN_COMPAT",
	"WLAN_EID_TWT",
	"WLAN_EID_S1G_CAPABILITIES",
	"WLAN_EID_VENDOR_SPECIFIC",
	"WLAN_EID_EXT_LENGTH",
	"WLAN_EID_S1G_OPERATION",
	"WLAN_EID_CAG_NUMBER",
	"WLAN_EID_AP_CSN",
	"WLAN_EID_FILS_INDICATION",
	"WLAN_EID_DILS",
	"WLAN_EID_FRAGMENT",
	"WLAN_EID_RSNX",
	"WLAN_EID_EXTENSION",
};

/* element id extension: 57 distinct value(s) */
static const u8 fuzz_elem_ext_ids[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
	13, 14, 32, 33, 35, 36, 38, 39, 42, 52, 54, 55,
	56, 57, 58, 59, 61, 62, 88, 89, 92, 93, 100, 106,
	107, 108, 109, 110, 113, 114, 135, 136, 140, 151, 152, 153,
	154, 155, 156, 157, 158, 159, 161, 162, 164,
};

/* element id extension, named. Aliases are listed in the comment. */
static const char * const fuzz_elem_ext_ids_names[] = {
	"WLAN_EID_EXT_ASSOC_DELAY_INFO",
	"WLAN_EID_EXT_FILS_REQ_PARAMS",
	"WLAN_EID_EXT_FILS_KEY_CONFIRM",
	"WLAN_EID_EXT_FILS_SESSION",
	"WLAN_EID_EXT_FILS_HLP_CONTAINER",
	"WLAN_EID_EXT_FILS_IP_ADDR_ASSIGN",
	"WLAN_EID_EXT_KEY_DELIVERY",
	"WLAN_EID_EXT_WRAPPED_DATA",
	"WLAN_EID_EXT_FTM_SYNC_INFO",
	"WLAN_EID_EXT_EXTENDED_REQUEST",
	"WLAN_EID_EXT_ESTIMATED_SERVICE_PARAMS",
	"WLAN_EID_EXT_FILS_PUBLIC_KEY",
	"WLAN_EID_EXT_NONCE",
	"WLAN_EID_EXT_FUTURE_CHANNEL_GUIDANCE",
	"WLAN_EID_EXT_OWE_DH_PARAM",
	"WLAN_EID_EXT_PASSWORD_IDENTIFIER",
	"WLAN_EID_EXT_HE_CAPABILITIES",
	"WLAN_EID_EXT_HE_OPERATION",
	"WLAN_EID_EXT_HE_MU_EDCA_PARAMS",
	"WLAN_EID_EXT_SPATIAL_REUSE",
	"WLAN_EID_EXT_COLOR_CHANGE_ANNOUNCEMENT",
	"WLAN_EID_EXT_MAX_CHANNEL_SWITCH_TIME",
	"WLAN_EID_EXT_OCV_OCI",
	"WLAN_EID_EXT_MULTIPLE_BSSID_CONFIGURATION",
	"WLAN_EID_EXT_NON_INHERITANCE",
	"WLAN_EID_EXT_KNOWN_BSSID",
	"WLAN_EID_EXT_SHORT_SSID_LIST",
	"WLAN_EID_EXT_HE_6GHZ_BAND_CAP",
	"WLAN_EID_EXT_EDMG_CAPABILITIES",
	"WLAN_EID_EXT_EDMG_OPERATION",
	"WLAN_EID_EXT_MSCS_DESCRIPTOR",
	"WLAN_EID_EXT_TCLAS_MASK",
	"WLAN_EID_EXT_REJECTED_GROUPS",
	"WLAN_EID_EXT_ANTI_CLOGGING_TOKEN",
	"WLAN_EID_EXT_PASN_PARAMS",
	"WLAN_EID_EXT_EHT_OPERATION",
	"WLAN_EID_EXT_MULTI_LINK",
	"WLAN_EID_EXT_EHT_CAPABILITIES",
	"WLAN_EID_EXT_TID_TO_LINK_MAPPING",
	"WLAN_EID_EXT_MULTI_LINK_TRAFFIC_INDICATION",
	"WLAN_EID_EXT_QOS_CHARACTERISTICS",
	"WLAN_EID_EXT_AKM_SUITE_SELECTOR",
	"WLAN_EID_EXT_BANDWIDTH_INDICATION",
	"WLAN_EID_EXT_KNOWN_STA_IDENTIFICATION",
	"WLAN_EID_EXT_PASN_ENCRYPTED_DATA",
	"WLAN_EID_EXT_UHR_OPERATION",
	"WLAN_EID_EXT_UHR_CAPABILITIES",
	"WLAN_EID_EXT_MAPC",
	"WLAN_EID_EXT_SMD_INFO",
	"WLAN_EID_EXT_SMD_BSS_TR_PARAMS",
	"WLAN_EID_EXT_EXT_CHAN_USAGE",
	"WLAN_EID_EXT_UHR_MODE_CHANGE",
	"WLAN_EID_EXT_UHR_PARAMS_UPDATE",
	"WLAN_EID_EXT_TX_POWER_INDICATION",
	"WLAN_EID_EXT_SUPPORTED_GROUPS",
	"WLAN_EID_EXT_SECURITY_PROFILE",
	"WLAN_EID_EXT_POW",
};

/* extended length element id: 1 distinct value(s) */
static const u16 fuzz_elem_extlen_ids[] = {
	0,
};

/* extended length element id, named. Aliases are listed in the comment. */
static const char * const fuzz_elem_extlen_ids_names[] = {
	"WLAN_EID_EXT_LEN_PQC_PARAMETER",
};

/*
 * Element shapes. Which one an id selects is read from element_hdr_size() and
 * from the parse loop's extension dispatch, never decided here.
 *
 *	hdr		octets from the id octet to the body
 *	len_off		where the declared length sits inside that header
 *	len_width	1 or 2 -- and a 2 is a 65,536-value domain, which is
 *			why an element header needs the reduction tiers
 *	extid_off	where the sub-registry id sits, 0 when there is none
 *	covers		the declared length includes the sub-registry id, so a
 *			declared length below extid_width leaves the id the
 *			identity domain just selected out of the frame
 */
enum fuzz_elem_shape {
	FUZZ_SHAPE_BASIC,
	FUZZ_SHAPE_EXT,
	FUZZ_SHAPE_EXTLEN,
	FUZZ_NUM_SHAPES
};

struct fuzz_elem_shape_info {
	const char *name;
	u8 hdr;
	u8 len_off;
	u8 len_width;
	u8 len_le;
	u8 extid_off;
	u8 extid_width;
	u8 extid_le;
	u8 covers;
};

static const struct fuzz_elem_shape_info fuzz_elem_shapes[] = {
	/* BASIC: struct element */
	{ "BASIC", 2, 1, 1, 0, 0, 0, 0, 0 },
	/* EXT: struct element plus the octet ieee802_11_parse_extension() takes */
	{ "EXT", 3, 1, 1, 0, 2, 1, 0, 1 },
	/* EXTLEN: struct ext_len_element */
	{ "EXTLEN", 5, 3, 2, 1, 1, 2, 1, 0 },
};

/* The ids that select a shape, named as the tree names them. */
#define FUZZ_EID_EXT WLAN_EID_EXTENSION
#define FUZZ_EID_EXTLEN WLAN_EID_EXT_LENGTH

/*
 * Fragmentation, read out of ieee802_11_defrag(), the parse loop and
 * ieee802_11_defrag_mle_subelem().
 *
 * A Fragment element is a CONTINUATION of the element before it, which makes
 * it the one place where inserting between two elements removes octets from a
 * third. It is also the only route to an element longer than its length field
 * can say, so the logical length domain is 0..len_max + max_body * N and not
 * 0..len_max.
 */
#define FUZZ_EID_FRAGMENT WLAN_EID_FRAGMENT
#define FUZZ_FRAG_PARENT_LEN 255
#define FUZZ_DEFRAG_MIN_EXT 255
#define FUZZ_DEFRAG_MIN 256
/* The same mechanism one nesting level down: an element whose body is
 * itself a chain, whose members are themselves fragmentable. */
#define FUZZ_SUB_EID_FRAGMENT MULTI_LINK_SUB_ELEM_ID_FRAGMENT
#define FUZZ_SUB_DEFRAG_MIN 255

/*
 * Action frame labels, read out of the frame rather than taken from the call
 * site. Two functions are the convergence point for eight protocols and over
 * a hundred call sites between them; naming the sites would be a hundred
 * hooks to carry across the rebase, and would file every case under whichever
 * caller happened to reach the convergence point rather than under the
 * protocol that will parse it.
 *
 * Most specific first: a row with an oui_type matches only that vendor, a row
 * with a code only that code, and a row with neither is the category's
 * fallback. The lookup takes the first row whose category matches and whose
 * stated fields match, so the order below IS the precedence.
 *
 * 'hdr' is how many octets the label consumed, which is the one offset in an
 * Action frame this engine is entitled to claim: what follows a category is
 * keyed by the category through a union that says nothing about which member
 * applies, so the chain walk gets the prefix the LABEL read and refuses
 * anything it cannot walk from there.
 */
struct fuzz_action_label_entry {
	u8 cat;
	s16 code;
	s16 oui_type;
	u8 hdr;
	const char *label;
};

/* 150 label(s) */
static const struct fuzz_action_label_entry fuzz_action_labels[] = {
	{ 4, 9, 2, 6, "act-public-vendor-wmm" },
	{ 4, 9, 9, 6, "act-public-vendor-p2p" },
	{ 4, 9, 10, 6, "act-public-vendor-wfd" },
	{ 4, 9, 16, 6, "act-public-vendor-hs20" },
	{ 4, 9, 17, 6, "act-public-vendor-hs20-anqp" },
	{ 4, 9, 18, 6, "act-public-vendor-mbo-anqp" },
	{ 4, 9, 19, 6, "act-public-vendor-nan" },
	{ 4, 9, 22, 6, "act-public-vendor-mbo" },
	{ 4, 9, 24, 6, "act-public-vendor-nan-naf" },
	{ 4, 9, 26, 6, "act-public-vendor-dpp" },
	{ 4, 9, 27, 6, "act-public-vendor-multi-ap" },
	{ 4, 9, 28, 6, "act-public-vendor-owe" },
	{ 4, 9, 29, 6, "act-public-vendor-hs20-roaming-cons-sel" },
	{ 4, 9, 30, 6, "act-public-vendor-dpp-cc" },
	{ 4, 9, 31, 6, "act-public-vendor-sae-pk" },
	{ 4, 9, 34, 6, "act-public-vendor-qm" },
	{ 4, 9, 35, 6, "act-public-vendor-wfa-capa" },
	{ 4, 9, 40, 6, "act-public-vendor-p2p2" },
	{ 4, 9, 41, 6, "act-public-vendor-wfa-rsne-override" },
	{ 4, 9, 42, 6, "act-public-vendor-wfa-rsne-override-2" },
	{ 4, 9, 43, 6, "act-public-vendor-wfa-rsnxe-override" },
	{ 4, 9, 44, 6, "act-public-vendor-wfa-rsn-selection" },
	{ 4, 9, 46, 6, "act-public-vendor-pr" },
	{ 4, 9, 51, 6, "act-public-vendor-vendor-ht-capab" },
	{ 4, 0, -1, 2, "act-public-20-40-bss-coex" },
	{ 4, 1, -1, 2, "act-public-dse-enablement" },
	{ 4, 2, -1, 2, "act-public-dse-deenablement" },
	{ 4, 3, -1, 2, "act-public-dse-reg-location-announce" },
	{ 4, 4, -1, 2, "act-public-ext-channel-switch-announce" },
	{ 4, 5, -1, 2, "act-public-dse-measurement-req" },
	{ 4, 6, -1, 2, "act-public-dse-measurement-resp" },
	{ 4, 7, -1, 2, "act-public-measurement-pilot" },
	{ 4, 8, -1, 2, "act-public-dse-power-constraint" },
	{ 4, 9, -1, 2, "act-public-vendor-specific" },
	{ 4, 10, -1, 2, "act-public-gas-initial-req" },
	{ 4, 11, -1, 2, "act-public-gas-initial-resp" },
	{ 4, 12, -1, 2, "act-public-gas-comeback-req" },
	{ 4, 13, -1, 2, "act-public-gas-comeback-resp" },
	{ 4, 14, -1, 2, "act-public-tdls-discovery-response" },
	{ 4, 15, -1, 2, "act-public-location-track-notification" },
	{ 4, 16, -1, 2, "act-public-qab-request-frame" },
	{ 4, 17, -1, 2, "act-public-qab-response-frame" },
	{ 4, 18, -1, 2, "act-public-qmf-policy" },
	{ 4, 19, -1, 2, "act-public-qmf-policy-change" },
	{ 4, 20, -1, 2, "act-public-qload-request" },
	{ 4, 21, -1, 2, "act-public-qload-report" },
	{ 4, 22, -1, 2, "act-public-hcca-txop-advertisement" },
	{ 4, 23, -1, 2, "act-public-hcca-txop-response" },
	{ 4, 24, -1, 2, "act-public-public-key" },
	{ 4, 25, -1, 2, "act-public-channel-availability-query" },
	{ 4, 26, -1, 2, "act-public-channel-schedule-management" },
	{ 4, 27, -1, 2, "act-public-contact-verification-signal" },
	{ 4, 28, -1, 2, "act-public-gdd-enablement-req" },
	{ 4, 29, -1, 2, "act-public-gdd-enablement-resp" },
	{ 4, 30, -1, 2, "act-public-network-channel-control" },
	{ 4, 31, -1, 2, "act-public-white-space-map-announcement" },
	{ 4, 32, -1, 2, "act-public-ftm-request" },
	{ 4, 33, -1, 2, "act-public-ftm" },
	{ 4, 34, -1, 2, "act-public-fils-discovery" },
	{ 4, 47, -1, 2, "act-public-location-measurement-report" },
	{ 9, 9, 2, 6, "act-prot-dual-vendor-wmm" },
	{ 9, 9, 9, 6, "act-prot-dual-vendor-p2p" },
	{ 9, 9, 10, 6, "act-prot-dual-vendor-wfd" },
	{ 9, 9, 16, 6, "act-prot-dual-vendor-hs20" },
	{ 9, 9, 17, 6, "act-prot-dual-vendor-hs20-anqp" },
	{ 9, 9, 18, 6, "act-prot-dual-vendor-mbo-anqp" },
	{ 9, 9, 19, 6, "act-prot-dual-vendor-nan" },
	{ 9, 9, 22, 6, "act-prot-dual-vendor-mbo" },
	{ 9, 9, 24, 6, "act-prot-dual-vendor-nan-naf" },
	{ 9, 9, 26, 6, "act-prot-dual-vendor-dpp" },
	{ 9, 9, 27, 6, "act-prot-dual-vendor-multi-ap" },
	{ 9, 9, 28, 6, "act-prot-dual-vendor-owe" },
	{ 9, 9, 29, 6, "act-prot-dual-vendor-hs20-roaming-cons-sel" },
	{ 9, 9, 30, 6, "act-prot-dual-vendor-dpp-cc" },
	{ 9, 9, 31, 6, "act-prot-dual-vendor-sae-pk" },
	{ 9, 9, 34, 6, "act-prot-dual-vendor-qm" },
	{ 9, 9, 35, 6, "act-prot-dual-vendor-wfa-capa" },
	{ 9, 9, 40, 6, "act-prot-dual-vendor-p2p2" },
	{ 9, 9, 41, 6, "act-prot-dual-vendor-wfa-rsne-override" },
	{ 9, 9, 42, 6, "act-prot-dual-vendor-wfa-rsne-override-2" },
	{ 9, 9, 43, 6, "act-prot-dual-vendor-wfa-rsnxe-override" },
	{ 9, 9, 44, 6, "act-prot-dual-vendor-wfa-rsn-selection" },
	{ 9, 9, 46, 6, "act-prot-dual-vendor-pr" },
	{ 9, 9, 51, 6, "act-prot-dual-vendor-vendor-ht-capab" },
	{ 9, 1, -1, 2, "act-prot-dual-dse-enablement" },
	{ 9, 2, -1, 2, "act-prot-dual-dse-deenablement" },
	{ 9, 4, -1, 2, "act-prot-dual-ext-csa" },
	{ 9, 5, -1, 2, "act-prot-dual-measurement-req" },
	{ 9, 6, -1, 2, "act-prot-dual-measurement-report" },
	{ 9, 8, -1, 2, "act-prot-dual-dse-power-constraint" },
	{ 9, 9, -1, 2, "act-prot-dual-vendor-specific" },
	{ 9, 10, -1, 2, "act-prot-dual-gas-initial-req" },
	{ 9, 11, -1, 2, "act-prot-dual-gas-initial-resp" },
	{ 9, 12, -1, 2, "act-prot-dual-gas-comeback-req" },
	{ 9, 13, -1, 2, "act-prot-dual-gas-comeback-resp" },
	{ 9, 16, -1, 2, "act-prot-dual-qab-request-frame" },
	{ 9, 17, -1, 2, "act-prot-dual-qab-response-frame" },
	{ 9, 18, -1, 2, "act-prot-dual-qmf-policy" },
	{ 9, 19, -1, 2, "act-prot-dual-qmf-policy-change" },
	{ 9, 20, -1, 2, "act-prot-dual-qload-request" },
	{ 9, 21, -1, 2, "act-prot-dual-qload-report" },
	{ 9, 22, -1, 2, "act-prot-dual-hcca-txop-advertisement" },
	{ 9, 23, -1, 2, "act-prot-dual-hcca-txop-response" },
	{ 9, 25, -1, 2, "act-prot-dual-channel-availability-query" },
	{ 9, 26, -1, 2, "act-prot-dual-channel-schedule-management" },
	{ 9, 27, -1, 2, "act-prot-dual-contact-verification-signal" },
	{ 9, 28, -1, 2, "act-prot-dual-gdd-enablement-req" },
	{ 9, 29, -1, 2, "act-prot-dual-gdd-enablement-resp" },
	{ 9, 30, -1, 2, "act-prot-dual-network-channel-control" },
	{ 9, 31, -1, 2, "act-prot-dual-white-space-map-announcement" },
	{ 0, -1, -1, 1, "act-spectrum-mgmt" },
	{ 1, -1, -1, 1, "act-qos" },
	{ 2, -1, -1, 1, "act-dls" },
	{ 3, -1, -1, 1, "act-block-ack" },
	{ 4, -1, -1, 1, "act-public" },
	{ 5, -1, -1, 1, "act-radio-measurement" },
	{ 6, -1, -1, 1, "act-ft" },
	{ 7, -1, -1, 1, "act-ht" },
	{ 8, -1, -1, 1, "act-sa-query" },
	{ 9, -1, -1, 1, "act-protected-dual" },
	{ 10, -1, -1, 1, "act-wnm" },
	{ 11, -1, -1, 1, "act-unprotected-wnm" },
	{ 12, -1, -1, 1, "act-tdls" },
	{ 13, -1, -1, 1, "act-mesh" },
	{ 14, -1, -1, 1, "act-multihop" },
	{ 15, -1, -1, 1, "act-self-protected" },
	{ 16, -1, -1, 1, "act-dmg" },
	{ 17, -1, -1, 1, "act-wmm" },
	{ 18, -1, -1, 1, "act-fst" },
	{ 19, -1, -1, 1, "act-robust-av-streaming" },
	{ 20, -1, -1, 1, "act-unprotected-dmg" },
	{ 21, -1, -1, 1, "act-vht" },
	{ 22, -1, -1, 1, "act-unprotected-s1g" },
	{ 23, -1, -1, 1, "act-s1g" },
	{ 24, -1, -1, 1, "act-flow-control" },
	{ 25, -1, -1, 1, "act-ctrl-resp-mcs-neg" },
	{ 26, -1, -1, 1, "act-fils" },
	{ 27, -1, -1, 1, "act-cdmg" },
	{ 28, -1, -1, 1, "act-cmmg" },
	{ 29, -1, -1, 1, "act-glk" },
	{ 30, -1, -1, 1, "act-he" },
	{ 31, -1, -1, 1, "act-protected-he" },
	{ 32, -1, -1, 1, "act-wur" },
	{ 34, -1, -1, 1, "act-protected-ftm" },
	{ 36, -1, -1, 1, "act-eht" },
	{ 37, -1, -1, 1, "act-protected-eht" },
	{ 43, -1, -1, 1, "act-protected-uhr" },
	{ 126, -1, -1, 1, "act-vendor-specific-protected" },
	{ 127, -1, -1, 1, "act-vendor-specific" },
};

/* The category this engine could not name. It is a label like any other,
 * so a run that sends one says so rather than filing it under a
 * neighbour. */
#define FUZZ_ACTION_OTHER "act-other"
#define FUZZ_ACTION_VENDOR_OUI OUI_WFA

#endif /* FUZZ_REGISTRIES_H */
