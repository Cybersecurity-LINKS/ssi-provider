#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/opensslv.h>

extern const OSSL_DISPATCH did_crud_functions[];
extern const OSSL_DISPATCH did_fake_functions[];
static const OSSL_ALGORITHM ssi_did[] = {
    {"OTT", "provider=ssi", did_crud_functions},
    {"ETH", "provider=ssi", did_fake_functions},
    {NULL, NULL, NULL}};

extern const OSSL_DISPATCH vc_functions[];
static const OSSL_ALGORITHM ssi_vc[] = {
    {"VC", "provider=ssi", vc_functions},
    {NULL, NULL, NULL}};

static const OSSL_PARAM *ssi_gettable_params(void *provctx)
{
    static const OSSL_PARAM param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_END};
    printf("SSI GETTABLE\n");
    return param_types;
}

static int ssi_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    printf("SSI get_params\n");
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "SSI provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) /* always in running state */
        return 0;

    return 1;
}

static const OSSL_ALGORITHM *ssi_query(void *provCtx, int id, int *no_cache)
{
    *no_cache = 0;
    switch (id)
    {
    case OSSL_OP_DID:
        printf("DID QUERY\n");
        return ssi_did;
    case OSSL_OP_VC:
        printf("VC QUERY\n");
        return ssi_vc;
        break;
    }
    return NULL;
}

static void ssi_teardown(void *provctx)
{
    printf("TEARDOWN\n");
}

static const OSSL_DISPATCH ssi_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))ssi_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))ssi_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))ssi_query},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))ssi_teardown},
    {0, NULL}};

OPENSSL_EXPORT int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx)
{
    printf("SSI INIT\n");
    *out = ssi_dispatch_table;
    return 1;
}
