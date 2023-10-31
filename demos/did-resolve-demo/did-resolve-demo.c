/*
 * Copyright 2023 Fondazione Links.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.	
 *
 */

#include "openssl/provider.h"
#include "openssl/params.h"
#include "openssl/core.h"
#include "openssl/crypto.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/evp_ssi.h"
#include <openssl/bio.h>
#include <sys/time.h>

int main(int argc, char *argv[]){

    OSSL_PROVIDER *provider_base = NULL;
    OSSL_PROVIDER *provider = NULL;

    EVP_DID_CTX *ctx_did = NULL;
	EVP_DID *evp_did = NULL;

    struct timeval tv1, tv2;

     if(argc != 2){
        fprintf(stderr, "Wrong number of parameters\n");
        return 0;
    }   

    // load the did provider for SSI operations
    provider = OSSL_PROVIDER_load(NULL, "ssi");
    if (provider == NULL) {
        fprintf(stderr, "Error loading provider\n");
        goto err;
    }

    // load the default provider for key operations
    provider_base = OSSL_PROVIDER_load(NULL, "default");
    if (provider_base == NULL) {
        fprintf(stderr, "Error loading provider\n");
        goto err;
    }

    evp_did = EVP_DID_fetch(NULL, "OTT", NULL);
	if (evp_did == NULL) {
		fprintf(stderr, "Error fetching DID\n");
        goto err;
	}

    ctx_did = EVP_DID_CTX_new(evp_did);
	if (ctx_did == NULL){
		fprintf(stderr, "Error creating DID CTX\n");
        goto err;
	}
	
    gettimeofday(&tv1, NULL);

    if(!EVP_DID_resolve(ctx_did, argv[1], NULL)){
		fprintf(stderr, "Error resolving DID\n");
        goto err;
	}

    gettimeofday(&tv2, NULL);
    printf("Total time = %f seconds\n\n",
           (double)(tv2.tv_usec - tv1.tv_usec) / 1000000 +
            (double)(tv2.tv_sec - tv1.tv_sec));

err:
    EVP_DID_free(evp_did);
	EVP_DID_CTX_free(ctx_did);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(provider_base);

    return 0;
}
