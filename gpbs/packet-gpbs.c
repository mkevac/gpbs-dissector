#include "config.h"

#include <dlfcn.h>
#include "protobuf-c.h"
#include "descriptor.pb-c.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>

static guint gpbs_port_pref = 11810;
static const char *gpbs_proto_so = NULL;

#define FRAME_HEADER_LEN 4

static int proto_gpbs = -1;

static int hf_gpbs_pdu_type = -1;
static int hf_gpbs_pdu_type_string = -1;
static int hf_gpbs_pdu_length = -1;

static gint ett_gpbs = -1;

static value_string *request_enum = NULL;
static int request_enum_size = 0;
static value_string *response_enum = NULL;
static int response_enum_size = 0;

static void *gpbs_proto_so_handle = NULL;
static Google__Protobuf__FileDescriptorSet *gpbs_proto_fds = NULL;
static Google__Protobuf__FileDescriptorProto *gpbs_proto_fdp = NULL;

static void gpbs_unserialize_field(const ProtobufCFieldDescriptor *f, void *m, proto_tree *gpbs_tree, tvbuff_t *tvb);
static void gpbs_unserialize_msg(ProtobufCMessage *m, proto_tree *gpbs_message_tree, tvbuff_t *tvb);


static hf_register_info hf[] = {
	{ &hf_gpbs_pdu_type,
		{ "GPBS Type", "gpbs.type",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_gpbs_pdu_type_string,
		{ "GPBS Type String", "gpbs.type_string",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
	},
	{ &hf_gpbs_pdu_length,
		{ "GPBS Length", "gpbs.length",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
	}
};

static size_t gpbs_field_storage_sz(ProtobufCType type)
{
	switch (type) {
		case PROTOBUF_C_TYPE_INT32:
		case PROTOBUF_C_TYPE_SINT32:
		case PROTOBUF_C_TYPE_SFIXED32:
		case PROTOBUF_C_TYPE_UINT32:
		case PROTOBUF_C_TYPE_FIXED32:
		case PROTOBUF_C_TYPE_ENUM:
			return 4;

		case PROTOBUF_C_TYPE_INT64:
		case PROTOBUF_C_TYPE_SINT64:
		case PROTOBUF_C_TYPE_SFIXED64:
		case PROTOBUF_C_TYPE_UINT64:
		case PROTOBUF_C_TYPE_FIXED64:
			return 8;

		case PROTOBUF_C_TYPE_FLOAT:
			return sizeof(float);

		case PROTOBUF_C_TYPE_DOUBLE:
			return sizeof(double);

		case PROTOBUF_C_TYPE_BOOL:
			return sizeof(protobuf_c_boolean);

		case PROTOBUF_C_TYPE_STRING:
		case PROTOBUF_C_TYPE_MESSAGE:
			return sizeof(void *);

		case PROTOBUF_C_TYPE_BYTES:
			return sizeof(ProtobufCBinaryData);
	}

	return 0;
}

static void gpbs_unserialize_msg(ProtobufCMessage *m, proto_tree *gpbs_message_tree, tvbuff_t *tvb)
{
	int i;
	for (i = 0; i < m->descriptor->n_fields; i++) {
		const ProtobufCFieldDescriptor *f = m->descriptor->fields + i;

		void *member = (char *) m + f->offset;
		void *qmember = (char *) m + f->quantifier_offset;
		size_t *quantifier = (size_t *) qmember;
		int has_set = 0;

		if (f->label == PROTOBUF_C_LABEL_OPTIONAL) {
			if (f->quantifier_offset != 0) {
				has_set = * (protobuf_c_boolean *) qmember;
			}
			else if (f->type == PROTOBUF_C_TYPE_MESSAGE || f->type == PROTOBUF_C_TYPE_STRING) {
				has_set = NULL != * (char **) member;
			}
		}

		if (f->label == PROTOBUF_C_LABEL_REPEATED) {
			size_t field_sz = gpbs_field_storage_sz(f->type);
			unsigned r, offset = 0;

			for (r = 0; r < *quantifier; r++) {
				void *m = (* (char **) member) + offset;
				gpbs_unserialize_field(f, m, gpbs_message_tree, tvb);
				offset += field_sz;
			}
		}
		else if ( (f->label == PROTOBUF_C_LABEL_OPTIONAL && (has_set || f->default_value)) ||
				f->label == PROTOBUF_C_LABEL_REQUIRED) {
			gpbs_unserialize_field(f, member, gpbs_message_tree, tvb);

		}
		else {
			continue;
		}
	}
}


static void gpbs_unserialize_field(const ProtobufCFieldDescriptor *f, void *m, proto_tree *gpbs_tree, tvbuff_t *tvb)
{
	switch (f->type) {
		case PROTOBUF_C_TYPE_INT32:
		case PROTOBUF_C_TYPE_SINT32:
		case PROTOBUF_C_TYPE_SFIXED32:
		case PROTOBUF_C_TYPE_UINT32:
		case PROTOBUF_C_TYPE_FIXED32:
		case PROTOBUF_C_TYPE_ENUM:
		{
			int64_t v = * (int32_t *) m;
			uint64_t u = * (uint32_t *) m;

			int is_unsigned = (f->type == PROTOBUF_C_TYPE_UINT32 || f->type == PROTOBUF_C_TYPE_FIXED32);

			proto_tree_add_text(gpbs_tree, tvb, 0, 0, "%s: %ld", f->name, v);

			break;
		}

		case PROTOBUF_C_TYPE_BOOL:
			proto_tree_add_text(gpbs_tree, tvb, 0, 0, "%s: %ld", f->name, * (protobuf_c_boolean *) m);
			break;

		case PROTOBUF_C_TYPE_INT64:
		case PROTOBUF_C_TYPE_SINT64:
		case PROTOBUF_C_TYPE_SFIXED64:
		case PROTOBUF_C_TYPE_UINT64:
		case PROTOBUF_C_TYPE_FIXED64:
		{
			int64_t v = * (int64_t *) m;
			int64_t u = * (uint64_t *) m;

			int as_string = 0;
			int is_unsigned = (f->type == PROTOBUF_C_TYPE_UINT64 || f->type == PROTOBUF_C_TYPE_FIXED64);

			proto_tree_add_text(gpbs_tree, tvb, 0, 0, "%s: %ld", f->name, v);

			break;
		}

		case PROTOBUF_C_TYPE_FLOAT:
			proto_tree_add_text(gpbs_tree, tvb, 0, 0, "%s: %f", f->name, *(float *)m);
			break;

		case PROTOBUF_C_TYPE_DOUBLE:
			proto_tree_add_text(gpbs_tree, tvb, 0, 0, "%s: %f", f->name, *(double *)m);
			break;

		case PROTOBUF_C_TYPE_STRING:
			proto_tree_add_text(gpbs_tree, tvb, 0, 0, "%s: %s", f->name, *(char **)m);
			break;

		case PROTOBUF_C_TYPE_MESSAGE:
		{
			ProtobufCMessage **msg = m;

			proto_item *message_header_item;
			proto_tree *gpbs_message_tree;

			message_header_item = proto_tree_add_text(gpbs_tree, tvb, 9, 0, "GPBS message %s", (*msg)->descriptor->name);
			gpbs_message_tree = proto_item_add_subtree(message_header_item, ett_gpbs);

			gpbs_unserialize_msg(*msg, gpbs_message_tree, tvb);
			break;
		}

		case PROTOBUF_C_TYPE_BYTES:
		{
			proto_tree_add_text(gpbs_tree, tvb, 0, 0, "some bytes");
			break;
		}
	}
}

static void *get_message_descriptor(void *so, Google__Protobuf__FileDescriptorProto *fdp,
		value_string *enum_, int type)
{
	gchar *descriptor_func_name;
	gchar *r_name;

	r_name = val_to_str_const(type, enum_, "unknown");

	gchar **splitted = g_strsplit(fdp->package, ".", 10);
	gchar *joined = g_strjoinv("__", splitted);

	descriptor_func_name = g_strconcat(joined, "__", 
			g_ascii_strdown(r_name, -1), "__descriptor", NULL);

	void *descriptor = dlsym(so, descriptor_func_name);

	g_strfreev(splitted);
	g_free(joined);
	g_free(descriptor_func_name);

	return descriptor;
}

static void dissect_gpbs_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	int is_request = 0;
	int is_response = 0;

	if (pinfo->srcport == gpbs_port_pref) {
		is_response = 1;
	} else if (pinfo->destport == gpbs_port_pref) {
		is_request = 1;
	}

	guint32 size = tvb_get_ntohl(tvb, offset);
	guint32 type = tvb_get_ntohl(tvb, offset+4);

	col_clear(pinfo->cinfo, COL_INFO);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GPBS");
	if (is_request) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%ld > %ld [%s]", pinfo->srcport, pinfo->destport,
				val_to_str(type, request_enum, "0x%02x"));
	} else if (is_response) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%ld > %ld [%s]", pinfo->srcport, pinfo->destport,
				val_to_str(type, response_enum, "0x%02x"));
	}

	if (tree) { /* we are being asked for details */

		proto_item *ti = NULL;
		proto_tree *gpbs_tree = NULL;

		ti = proto_tree_add_item(tree, proto_gpbs, tvb, 0, -1, ENC_NA);

		gpbs_tree = proto_item_add_subtree(ti, ett_gpbs);

		proto_tree_add_item(gpbs_tree, hf_gpbs_pdu_length, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(gpbs_tree, hf_gpbs_pdu_type, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		if (is_response) {
			proto_tree_add_string(gpbs_tree, hf_gpbs_pdu_type_string, tvb, 0, 0, val_to_str(type, response_enum, "unknown"));
		} else if (is_request) {
			proto_tree_add_string(gpbs_tree, hf_gpbs_pdu_type_string, tvb, 0, 0, val_to_str(type, request_enum, "unknown"));
		}
		
		if (size > 4) { /* message not empty */

			proto_item *message_header_item;
			proto_tree *gpbs_message_tree;

			message_header_item = proto_tree_add_text(gpbs_tree, tvb, 9, 0, "GPBS message");
			gpbs_message_tree = proto_item_add_subtree(message_header_item, ett_gpbs);

			void *descriptor = NULL;

			if (is_response) {
				descriptor = get_message_descriptor(gpbs_proto_so_handle, gpbs_proto_fdp, response_enum, type);
			}

			if (is_request) {
				descriptor = get_message_descriptor(gpbs_proto_so_handle, gpbs_proto_fdp, request_enum, type);
			}

			if (!descriptor) {
				return;
			}

			ProtobufCMessage *m = protobuf_c_message_unpack(descriptor, 0, size-4, tvb_get_ptr(tvb, offset, size-4));
			if (!m) {
				return;
			}

			gpbs_unserialize_msg(m, gpbs_message_tree, tvb);

		}
	}
}

static guint get_gpbs_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    return (guint)(tvb_get_ntohl(tvb, offset) + 4);
}

static void dissect_gpbs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN, get_gpbs_message_len, dissect_gpbs_message);
}

void proto_reg_handoff_gpbs(void)
{
	static dissector_handle_t gpbs_handle;

	gpbs_handle = create_dissector_handle(dissect_gpbs, proto_gpbs);
	dissector_add_uint("tcp.port", gpbs_port_pref, gpbs_handle);

	gpbs_proto_so_handle = dlopen(gpbs_proto_so, RTLD_LAZY);
	if (!gpbs_proto_so_handle) {
		return; /* how to return some error? */
	}

	void *fds_data = dlsym(gpbs_proto_so_handle, "FileDescriptorSet");
	if (!fds_data) {
		return; /* how to return some error? */
	}

	unsigned int *fds_len = dlsym(gpbs_proto_so_handle, "FileDescriptorSet_len");
	if (!fds_len) {
		return; /* how to return some error? */
	}

	gpbs_proto_fds = google__protobuf__file_descriptor_set__unpack(0, *fds_len, fds_data);
	if (!gpbs_proto_fds) {
		return; /* how to return some error? */
	}

	if (gpbs_proto_fds->n_file != 1) {
		return; /* how to return some error? */
	}

	gpbs_proto_fdp = gpbs_proto_fds->file[0];

	unsigned enum_no;
	for (enum_no = 0; enum_no < gpbs_proto_fdp->n_enum_type; enum_no++) {
		unsigned value_no;

		Google__Protobuf__EnumDescriptorProto *enum_ = gpbs_proto_fdp->enum_type[enum_no];

		if (!strcmp(enum_->name, "request_msgid")) {

			request_enum = g_malloc(sizeof(value_string)*enum_->n_value);
			request_enum_size = enum_->n_value;

			for (value_no = 0; value_no < enum_->n_value; value_no++) {
				Google__Protobuf__EnumValueDescriptorProto *value = enum_->value[value_no];
				request_enum[value_no].value = value->number;
				request_enum[value_no].strptr = value->name;
			}
		}

		if (!strcmp(enum_->name, "response_msgid")) {
			unsigned value_no;

			response_enum = g_malloc(sizeof(value_string)*enum_->n_value);
			response_enum_size = enum_->n_value;

			for (value_no = 0; value_no < enum_->n_value; value_no++) {
				Google__Protobuf__EnumValueDescriptorProto *value = enum_->value[value_no];
				response_enum[value_no].value = value->number;
				response_enum[value_no].strptr = value->name;
			}
		}
	}
}

void
proto_register_gpbs(void)
{

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_gpbs
    };

    proto_gpbs = proto_register_protocol (
        "GPBS Protocol", /* name       */
        "GPBS",      /* short name */
        "gpbs"       /* abbrev     */
        );

    proto_register_field_array(proto_gpbs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module_t *gpbs_module;

    gpbs_module = prefs_register_protocol(proto_gpbs, proto_reg_handoff_gpbs);
    prefs_register_uint_preference(gpbs_module, "tcp.port", "GPBS TCP Port",
	 " GPBS TCP port if other than the default", 10, &gpbs_port_pref);
    prefs_register_filename_preference(gpbs_module, "proto.so", "GPBS proto *.so",
         " Path to *.so file for needed GPBS service", &gpbs_proto_so);
}

