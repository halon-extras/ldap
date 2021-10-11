#include <HalonMTA.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <string.h>
#include <ldap.h>
#include <openssl/ssl.h>

#define HALON_CA_FILE "/etc/ssl/certs/ca-certificates.crt"
#define HALON_CA_PATH "/etc/ssl/certs"

class MyLDAP
{
	public:
		MyLDAP(const std::string& uri);
		~MyLDAP();
		ldap* ld;
		size_t ref = 1;
		int error;
};

class MyLDAPResult
{
	public:
		MyLDAPResult(MyLDAP* _ldap, int _msgid);
		~MyLDAPResult();

		MyLDAP* ldap;
		int msgid;
};

void LDAP_object_free(void* ptr)
{
	MyLDAP* l = (MyLDAP*)ptr;
	if (l->ref == 1)
		delete l;
	else
		--l->ref;
}

void LDAPResult_object_free(void* ptr)
{
	MyLDAPResult* lr = (MyLDAPResult*)ptr;
	delete lr;
}

void LDAPResult_class_next(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	if (HalonMTA_hsl_argument_length(args))
		return;

	MyLDAPResult* l = (MyLDAPResult*)HalonMTA_hsl_object_ptr_get(hhc);
	if (l->ldap->ld == nullptr)
		return;

	LDAPMessage* result = nullptr;
	int r = ldap_result(l->ldap->ld, l->msgid, 0, nullptr, &result);
	if (r == 0)
		return;
	if (r == -1)
		return;

	if (r == LDAP_RES_SEARCH_RESULT)
	{
		bool f = false;
		HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_BOOLEAN, &f, 0);
		return;
	}

	LDAPMessage* e = ldap_first_entry(l->ldap->ld, result);
	if (!e)
	{
		ldap_msgfree(result);
		return;
	}

	if (ldap_msgtype(e) != LDAP_RES_SEARCH_ENTRY)
	{
		ldap_msgfree(result);
		return;
	}

	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_ARRAY, nullptr, 0);
	HalonHSLValue *key, *val;

	char *a, *dn;
	berval **vals;
	BerElement *ber = nullptr;

	if ((dn = ldap_get_dn(l->ldap->ld, e)) != nullptr)
	{
		HalonMTA_hsl_value_array_add(ret, &key, &val);
		HalonMTA_hsl_value_set(key, HALONMTA_HSL_TYPE_STRING, "dn", 0);
		HalonMTA_hsl_value_set(val, HALONMTA_HSL_TYPE_STRING, dn, 0);
		ldap_memfree(dn);
	}

	double i = 0;
	for (a = ldap_first_attribute(l->ldap->ld, e, &ber); a != nullptr; a = ldap_next_attribute(l->ldap->ld, e, ber))
	{
		if ((vals = ldap_get_values_len(l->ldap->ld, e, a)) != nullptr)
		{
			HalonMTA_hsl_value_array_add(ret, &key, &val);
			HalonMTA_hsl_value_set(key, HALONMTA_HSL_TYPE_STRING, a, 0);

			HalonMTA_hsl_value_set(val, HALONMTA_HSL_TYPE_ARRAY, nullptr, 0);
			HalonHSLValue *key2, *val2;

			for (int x2 = 0; vals[x2] != nullptr; ++x2)
			{
				// we could check ldif_is_not_printable(vals[x2]->bv_val, vals[x2]->bv_len)
				// and possible return the data in a different format (eg. base64)
				// however, that needs to be communicated somehow.
				double di = x2;
				HalonMTA_hsl_value_array_add(val, &key2, &val2);
				HalonMTA_hsl_value_set(key2, HALONMTA_HSL_TYPE_NUMBER, &di, 0);
				HalonMTA_hsl_value_set(val2, HALONMTA_HSL_TYPE_STRING, vals[x2]->bv_val, vals[x2]->bv_len);
			}
			ldap_value_free_len(vals);
		}
		ldap_memfree(a);
	}

	if (ber != nullptr)
		ber_free(ber, 0);

	ldap_msgfree(result);
	return;
}

void LDAP_class_search(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	if (HalonMTA_hsl_argument_length(args) < 1 || HalonMTA_hsl_argument_length(args) > 2)
		return;

	MyLDAP* l = (MyLDAP*)HalonMTA_hsl_object_ptr_get(hhc);
	if (l->ld == nullptr)
		return;

	HalonHSLValue* x = HalonMTA_hsl_argument_get(args, 0);
	char* base = nullptr;
	size_t baselen;
	if (!x || HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_STRING ||
			!HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &base, &baselen) ||
			HalonMTA_hsl_argument_get(args, 1))
	{
		return;
	}

	std::string filter;
	int scope = LDAP_SCOPE_SUBTREE;
	const char** attrs = nullptr;

	HalonHSLValue* opts = HalonMTA_hsl_argument_get(args, 1);
	if (opts)
	{
		HalonHSLValue *k, *v;
		size_t i = 0;
		while ((v = HalonMTA_hsl_value_array_get(opts, i, &k)))
		{
			char* opt;
			size_t optlen;
			if (HalonMTA_hsl_value_type(k) != HALONMTA_HSL_TYPE_STRING ||
				!HalonMTA_hsl_value_get(k, HALONMTA_HSL_TYPE_STRING, &opt, &optlen))
				continue;

			if (strcmp(opt, "filter") == 0)
			{
				char* val;
				size_t vallen;
				if (HalonMTA_hsl_value_type(v) != HALONMTA_HSL_TYPE_STRING ||
					!HalonMTA_hsl_value_get(v, HALONMTA_HSL_TYPE_STRING, &val, &vallen))
					continue;
				filter = std::string(val, vallen);
			}
			if (strcmp(opt, "scope") == 0)
			{
				char* val;
				size_t vallen;
				if (HalonMTA_hsl_value_type(v) != HALONMTA_HSL_TYPE_STRING ||
					!HalonMTA_hsl_value_get(v, HALONMTA_HSL_TYPE_STRING, &val, &vallen))
					continue;
				if (strcmp(val, "one") == 0)
					scope = LDAP_SCOPE_ONELEVEL;
				else if (strcmp(val, "sub") == 0)
					scope = LDAP_SCOPE_SUBTREE;
				else if (strcmp(val, "base") == 0)
					scope = LDAP_SCOPE_BASE;
				else
					return;
			}
			if (strcmp(opt, "attributes") == 0)
			{
				if (HalonMTA_hsl_value_type(v) != HALONMTA_HSL_TYPE_ARRAY)
					continue;
				size_t length = HalonMTA_hsl_value_array_length(v);
				attrs = new const char*[length + 1];

				HalonHSLValue *val2;
				size_t i = 0;
				while ((val2 = HalonMTA_hsl_value_array_get(v, i, nullptr)))
				{
					char* val;
					size_t vallen;
					if (HalonMTA_hsl_value_type(val2) != HALONMTA_HSL_TYPE_STRING ||
						!HalonMTA_hsl_value_get(val2, HALONMTA_HSL_TYPE_STRING, &val, &vallen))
						continue;
					attrs[i++] = val;
				}
				attrs[i++] = nullptr;
			}
		}
	}

	int msgidp;
	int r = ldap_search_ext(
			l->ld,
			base,
			scope,
			filter.empty() ? nullptr : filter.c_str(),
			(char**)attrs, 0, nullptr, nullptr, nullptr, LDAP_NO_LIMIT, &msgidp);
	delete [] attrs;
	if (r != LDAP_SUCCESS)
	{
		l->error = r;
		return;
	}

	HalonHSLObject* object = HalonMTA_hsl_object_new();
	HalonMTA_hsl_object_type_set(object, "LDAPResult");
	HalonMTA_hsl_object_register_function(object, "next", &LDAPResult_class_next);
	HalonMTA_hsl_object_ptr_set(object, new MyLDAPResult(l, msgidp), LDAPResult_object_free);
	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_OBJECT, object, 0);
	HalonMTA_hsl_object_delete(object);
}

void LDAP_class_getoption(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	HalonHSLValue* x = HalonMTA_hsl_argument_get(args, 0);
	char* param = nullptr;
	size_t paramlen;
	if (!x || HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_STRING ||
			!HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &param, &paramlen) ||
			HalonMTA_hsl_argument_get(args, 1))
	{
		return;
	}

	MyLDAP* l = (MyLDAP*)HalonMTA_hsl_object_ptr_get(hhc);
	if (l->ld == nullptr)
		return;

	int r = 0;
	if (strcmp(param, "diagnostic_message") == 0)
	{
		char* msg = nullptr;
		r = ldap_get_option(l->ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void*)&msg);
		if (r != LDAP_SUCCESS)
		{
			l->error = r;
			return;
		}

		if (!msg)
			HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_STRING, "", 0);
		else
		{
			HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_STRING, msg, 0);
			ldap_memfree(msg);
		}
	}
}

void LDAP_class_setoption(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	if (HalonMTA_hsl_argument_length(args) != 2)
		return;

	MyLDAP* l = (MyLDAP*)HalonMTA_hsl_object_ptr_get(hhc);
	if (l->ld == nullptr)
		return;

	HalonHSLValue* x = HalonMTA_hsl_argument_get(args, 0);
	char* param = nullptr;
	size_t paramlen;
	if (!x || HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_STRING ||
			!HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &param, &paramlen) ||
			HalonMTA_hsl_argument_get(args, 1))
	{
		return;
	}

	HalonHSLValue* v = HalonMTA_hsl_argument_get(args, 1);

	int r = 0;
	if (strcmp(param, "protocol_version") == 0)
	{
		double number;
		if (HalonMTA_hsl_value_type(v) != HALONMTA_HSL_TYPE_NUMBER ||
			!HalonMTA_hsl_value_get(v, HALONMTA_HSL_TYPE_NUMBER, &number, nullptr))
			return;
		int v = (int)number;
		r = ldap_set_option(l->ld, LDAP_OPT_PROTOCOL_VERSION, &v);
	}
	else if (strcmp(param, "referrals") == 0)
	{
		bool b;
		if (HalonMTA_hsl_value_type(v) != HALONMTA_HSL_TYPE_BOOLEAN ||
			!HalonMTA_hsl_value_get(v, HALONMTA_HSL_TYPE_BOOLEAN, &b, nullptr))
			return;
		r = ldap_set_option(l->ld, LDAP_OPT_REFERRALS, b ? LDAP_OPT_ON : LDAP_OPT_OFF);
	}
	else if (strcmp(param, "network_timeout") == 0)
	{
		double number;
		if (HalonMTA_hsl_value_type(v) != HALONMTA_HSL_TYPE_NUMBER ||
			!HalonMTA_hsl_value_get(v, HALONMTA_HSL_TYPE_NUMBER, &number, nullptr))
			return;
		int v = (int)number;
		struct timeval to = { v, 0 };
		r = ldap_set_option(l->ld, LDAP_OPT_NETWORK_TIMEOUT, &to);
	}
	else if (strcmp(param, "timeout") == 0)
	{
		double number;
		if (HalonMTA_hsl_value_type(v) != HALONMTA_HSL_TYPE_NUMBER ||
			!HalonMTA_hsl_value_get(v, HALONMTA_HSL_TYPE_NUMBER, &number, nullptr))
			return;
		int v = (int)number;
		struct timeval to = { v, 0 };
		r = ldap_set_option(l->ld, LDAP_OPT_TIMEOUT, &to);
	}
	else if (strcmp(param, "timelimit") == 0)
	{
		double number;
		if (HalonMTA_hsl_value_type(v) != HALONMTA_HSL_TYPE_NUMBER ||
			!HalonMTA_hsl_value_get(v, HALONMTA_HSL_TYPE_NUMBER, &number, nullptr))
			return;
		int v = (int)number;
		struct timeval to = { v, 0 };
		r = ldap_set_option(l->ld, LDAP_OPT_TIMELIMIT, &to);
	}
	else if (strcmp(param, "tls_verify_peer") == 0)
	{
		bool b;
		if (HalonMTA_hsl_value_type(v) != HALONMTA_HSL_TYPE_BOOLEAN ||
			!HalonMTA_hsl_value_get(v, HALONMTA_HSL_TYPE_BOOLEAN, &b, nullptr))
			return;
		int val = b ? LDAP_OPT_X_TLS_DEMAND : LDAP_OPT_X_TLS_NEVER;
		ldap_set_option(l->ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &val);
		val = 0;
		ldap_set_option(l->ld, LDAP_OPT_X_TLS_NEWCTX, &val);
	}
	else if (strcmp(param, "tls_default_ca") == 0)
	{
		bool b;
		if (HalonMTA_hsl_value_type(v) != HALONMTA_HSL_TYPE_BOOLEAN ||
			!HalonMTA_hsl_value_get(v, HALONMTA_HSL_TYPE_BOOLEAN, &b, nullptr))
			return;
		if (b)
		{
			ldap_set_option(l->ld, LDAP_OPT_X_TLS_CACERTFILE, HALON_CA_FILE);
			int val = 0;
			ldap_set_option(l->ld, LDAP_OPT_X_TLS_NEWCTX, &val);
		}
	}
	else
		return;

	if (r != LDAP_SUCCESS)
	{
		l->error = r;
		return;
	}

	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_THIS, hhc, 0);
}

void LDAP_class_bind(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	if (HalonMTA_hsl_argument_length(args) > 2)
		return;

	MyLDAP* l = (MyLDAP*)HalonMTA_hsl_object_ptr_get(hhc);
	if (l->ld == nullptr)
		return;

	std::string username;

	HalonHSLValue* x = HalonMTA_hsl_argument_get(args, 0);
	if (x)
	{
		char* param;
		size_t paramlen;
		if (HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_STRING ||
			!HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &param, &paramlen))
			return;
		username = std::string(param, paramlen);
	}

	struct berval lp = { 0, nullptr };
	x = HalonMTA_hsl_argument_get(args, 1);
	if (x)
	{
		if (HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_STRING ||
			!HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &lp.bv_val, &lp.bv_len))
			return;
	}

	int r = ldap_sasl_bind_s(l->ld, username.empty() ? nullptr : username.c_str(), LDAP_SASL_SIMPLE, &lp, nullptr, nullptr, nullptr);

	if (r != LDAP_SUCCESS)
	{
		l->error = r;
		return;
	}

	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_THIS, hhc, 0);
}

void LDAP_class_unbind(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	if (HalonMTA_hsl_argument_length(args))
		return;

	MyLDAP* l = (MyLDAP*)HalonMTA_hsl_object_ptr_get(hhc);
	if (l->ld == nullptr)
		return;

	int r = ldap_unbind_ext(l->ld, nullptr, nullptr);
	l->ld = nullptr;

	if (r != LDAP_SUCCESS)
	{
		l->error = r;
		return;
	}

	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_THIS, hhc, 0);
}

void LDAP_class_getpeerx509(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	if (HalonMTA_hsl_argument_length(args))
		return;

	MyLDAP* l = (MyLDAP*)HalonMTA_hsl_object_ptr_get(hhc);
	if (l->ld == nullptr)
		return;

	SSL* ssl = nullptr;
	int r = ldap_get_option(l->ld, LDAP_OPT_X_TLS_SSL_CTX, &ssl);
	if (r == LDAP_OPT_ERROR || ssl == nullptr)
	{
		l->error = LDAP_OPT_ERROR;
		return;
	}

	X509* cert = SSL_get_peer_certificate(ssl);
	if (!cert)
	{
		l->error = LDAP_OPT_ERROR;
		return;
	}

	//return class_X509(ReturnValue(std::make_shared<::X_509>(cert, false)));
}

void LDAP_class_errno(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	if (HalonMTA_hsl_argument_length(args))
		return;

	MyLDAP* l = (MyLDAP*)HalonMTA_hsl_object_ptr_get(hhc);
	double err = l->error;
	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_NUMBER, &err, 0);
}

void LDAP_class_starttls(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	if (HalonMTA_hsl_argument_length(args))
		return;

	MyLDAP* l = (MyLDAP*)HalonMTA_hsl_object_ptr_get(hhc);
	if (l->ld == nullptr)
		return;

	int r = ldap_start_tls_s(l->ld, nullptr, nullptr);
	if (r != LDAP_SUCCESS)
	{
		l->error = r;
		return;
	}

	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_THIS, hhc, 0);
}

HALON_EXPORT
void LDAP_class(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	HalonHSLValue* x = HalonMTA_hsl_argument_get(args, 0);
	char* param = nullptr;
	size_t paramlen;
	if (!x || HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_STRING ||
			!HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &param, &paramlen) ||
			HalonMTA_hsl_argument_get(args, 1))
	{
		return;
	}

	HalonHSLObject* object = HalonMTA_hsl_object_new();
	HalonMTA_hsl_object_type_set(object, "LDAP");
	HalonMTA_hsl_object_register_function(object, "starttls", &LDAP_class_starttls);
	HalonMTA_hsl_object_register_function(object, "errno", &LDAP_class_errno);
	HalonMTA_hsl_object_register_function(object, "unbind", &LDAP_class_unbind);
	HalonMTA_hsl_object_register_function(object, "bind", &LDAP_class_bind);
	HalonMTA_hsl_object_register_function(object, "search", &LDAP_class_search);
	HalonMTA_hsl_object_register_function(object, "getoption", &LDAP_class_getoption);
	HalonMTA_hsl_object_register_function(object, "setoption", &LDAP_class_setoption);
	HalonMTA_hsl_object_register_function(object, "getpeerx509", &LDAP_class_getpeerx509);
	HalonMTA_hsl_object_ptr_set(object, new MyLDAP(std::string(param, paramlen)), LDAP_object_free);
	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_OBJECT, object, 0);
	HalonMTA_hsl_object_delete(object);
}

void LDAP_filter_escape(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	struct berval in, ut;

	HalonHSLValue* x = HalonMTA_hsl_argument_get(args, 0);
	if (!x || HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_STRING ||
			!HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &in.bv_val, &in.bv_len) ||
			HalonMTA_hsl_argument_get(args, 1))
	{
		return;
	}

	ldap_bv2escaped_filter_value(&in, &ut);
	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_STRING, ut.bv_val, ut.bv_len);
	free(ut.bv_val);
}

void LDAP_dn2str(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	HalonHSLValue* x = HalonMTA_hsl_argument_get(args, 0);
	if (!x || HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_ARRAY ||
			HalonMTA_hsl_argument_get(args, 1))
	{
		return;
	}

	LDAPDN dn = (LDAPRDN*)malloc(sizeof(LDAPRDN) * (HalonMTA_hsl_value_array_length(x) + 1));

	HalonHSLValue *k, *v;
	size_t i = 0;
	while ((v = HalonMTA_hsl_value_array_get(x, i, &k)))
	{
		HalonHSLValue *v1, *v2;

		if (HalonMTA_hsl_value_type(v) != HALONMTA_HSL_TYPE_ARRAY ||
			HalonMTA_hsl_value_array_length(v) != 2)
		{
			dn[i] = nullptr;
			goto free;
		}

		dn[i] = (LDAPAVA**)malloc(sizeof(LDAPAVA*) * 2);
		dn[i][0] = (LDAPAVA*)malloc(sizeof(LDAPAVA));
		dn[i][0]->la_attr.bv_val = nullptr;
		dn[i][0]->la_value.bv_val = nullptr;
		dn[i][1] = nullptr;

		v1 = HalonMTA_hsl_value_array_get(v, 0, nullptr);
		v2 = HalonMTA_hsl_value_array_get(v, 1, nullptr);
		if (!v1 || HalonMTA_hsl_value_type(v1) != HALONMTA_HSL_TYPE_STRING ||
			!v2 || HalonMTA_hsl_value_type(v2) != HALONMTA_HSL_TYPE_STRING)
		{
			dn[i + 1] = nullptr;
			goto free;
		}
		HalonMTA_hsl_value_get(v2, HALONMTA_HSL_TYPE_STRING, &dn[i][0]->la_attr.bv_val, &dn[i][0]->la_attr.bv_len);
		HalonMTA_hsl_value_get(v2, HALONMTA_HSL_TYPE_STRING, &dn[i][0]->la_value.bv_val, &dn[i][0]->la_value.bv_len);

		dn[i][0]->la_flags = LDAP_AVA_STRING;
		++i;
		continue;
free:
		ldap_dnfree(dn);
		return;
	}
	dn[i] = nullptr;

	char* result = nullptr;
	int r = ldap_dn2str(dn, &result, LDAP_DN_FORMAT_LDAPV3);
	ldap_dnfree(dn);

	if (r != LDAP_SUCCESS)
		return;
	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_STRING, result, 0);
	free(result);
}

void LDAP_str2dn(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	HalonHSLValue* x = HalonMTA_hsl_argument_get(args, 0);
	char* param = nullptr;
	size_t paramlen;
	if (!x || HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_STRING ||
			!HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &param, &paramlen) ||
			HalonMTA_hsl_argument_get(args, 1))
	{
		return;
	}

	LDAPDN dn = nullptr;
	if (ldap_str2dn(param, &dn, LDAP_DN_FORMAT_LDAPV3) != LDAP_SUCCESS)
		return;

	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_ARRAY, nullptr, 0);
	HalonHSLValue *key, *val;

	double di0 = 0;
	double di1 = 1;
	size_t i = 0;
	while (dn[i])
	{
		LDAPAVA* ava = dn[i][0];
		HalonMTA_hsl_value_array_add(ret, &key, &val);
		double di = i;
		HalonMTA_hsl_value_set(key, HALONMTA_HSL_TYPE_NUMBER, &di, 0);
		HalonMTA_hsl_value_set(val, HALONMTA_HSL_TYPE_ARRAY, nullptr, 0);
		HalonHSLValue *key1, *val1;
		HalonMTA_hsl_value_array_add(val, &key1, &val1);
		HalonMTA_hsl_value_set(key1, HALONMTA_HSL_TYPE_NUMBER, &di0, 0);
		HalonMTA_hsl_value_set(val1, HALONMTA_HSL_TYPE_STRING, ava->la_attr.bv_val, ava->la_attr.bv_len);
		HalonMTA_hsl_value_array_add(val, &key1, &val1);
		HalonMTA_hsl_value_set(key1, HALONMTA_HSL_TYPE_NUMBER, &di1, 0);
		HalonMTA_hsl_value_set(val1, HALONMTA_HSL_TYPE_STRING, ava->la_value.bv_val, ava->la_value.bv_len);
		++i;
	}

	ldap_dnfree(dn);
}

void LDAP_err2string(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	HalonHSLValue* x = HalonMTA_hsl_argument_get(args, 0);
	double param = 0;
	if (!x || HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_NUMBER ||
			!HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_NUMBER, &param, nullptr) ||
			HalonMTA_hsl_argument_get(args, 1))
	{
		return;
	}

	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_STRING, ldap_err2string((int)param), 0);
}

HALON_EXPORT
bool Halon_hsl_register(HalonHSLRegisterContext* ptr)
{
	HalonMTA_hsl_register_function(ptr, "LDAP2", &LDAP_class);
	HalonMTA_hsl_register_static_function(ptr, "LDAP2", "filter_escape", &LDAP_filter_escape);
	HalonMTA_hsl_register_static_function(ptr, "LDAP2", "str2dn", &LDAP_str2dn);
	HalonMTA_hsl_register_static_function(ptr, "LDAP2", "dn2str", &LDAP_dn2str);
	HalonMTA_hsl_register_static_function(ptr, "LDAP2", "err2string", &LDAP_err2string);
	return true;
}

HALON_EXPORT
int Halon_version()
{
	return HALONMTA_PLUGIN_VERSION;
}

MyLDAP::MyLDAP(const std::string& uri)
: ld(nullptr)
, error(0)
{
	if (ldap_initialize(&ld, uri.c_str()) != LDAP_SUCCESS)
		ld = nullptr;
	else
	{
		int v = LDAP_VERSION3;
		ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &v);
		ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
		ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTDIR, HALON_CA_PATH);
		int val = 0;
		ldap_set_option(ld, LDAP_OPT_X_TLS_NEWCTX, &val);
	}
}

MyLDAP::~MyLDAP()
{
	if (ld == nullptr)
		return;
	ldap_unbind_ext(ld, nullptr, nullptr);
	ld = nullptr;
}

MyLDAPResult::MyLDAPResult(MyLDAP* _ldap, int _msgid)
: ldap(_ldap)
, msgid(_msgid)
{
	++ldap->ref;
}

MyLDAPResult::~MyLDAPResult()
{
	if (ldap->ref == 1)
		delete ldap;
	else
		--ldap->ref;
}
