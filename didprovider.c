#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include <openssl/did.h>


extern const OSSL_DISPATCH didprovider_crud_functions[];
extern const OSSL_DISPATCH didprovider_fake_functions[];
static const OSSL_ALGORITHM didprovider_did[] = {
    {"ETH","provider=didprovider", didprovider_fake_functions},
    {"OTT","provider=didprovider", didprovider_crud_functions},
    { NULL, NULL, NULL }
};

static const OSSL_PARAM * didprovider_gettable_params(void *provctx)
{
    static const OSSL_PARAM param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_END
    };
    printf("DID GETTABLE\n");
    return param_types;
}

static int didprovider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    printf("DID get_params\n");
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "DID provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) /* always in running state */
        return 0;

    return 1;
}

static const OSSL_ALGORITHM* didprovider_query_operation(void* provCtx, int id,int* no_cache)
{
    *no_cache = 0;
    printf("DID QUERY\n");
    switch (id) {
        case OSSL_OP_DID:
            return didprovider_did;
        break;

    }
    return NULL;
}

static void didprovider_teardown(void *provctx)
{
    printf("TEARDOWN\n");
}

static const OSSL_DISPATCH dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))didprovider_gettable_params},
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))didprovider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))didprovider_query_operation},
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))didprovider_teardown },
    { 0, NULL }
};

OPENSSL_EXPORT int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,void **provctx){
    printf("DID INIT\n");
    *out = dispatch_table;
    return 1;
}
