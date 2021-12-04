/*
 * A list of the different functions for each algorithm.
 * These functions are called in a loop and are called as
 * state = algo_functions[0]();
 */
mapping(string:function) algo_functions = ([
	/* AEAD Tests */
	"AES-GCM": Crypto.AES.GCM.State, /*GCM*/
	"AES-EAX": Crypto.AES.EAX.State, /*EAX*/
	"AES-CCM": Crypto.AES.CCM.State, /*CCM*/
	"CHACHA20-POLY1305": Crypto.ChaCha20.POLY1305.State, /*ChaCha-Poly1305*/
	//"AEAD-AES-SIV-CMAC" : ???

	/* IndCpa Tests */
	"AES-CBC-PKCS5": Crypto.AES.CBC.Buffer, /*AES-CBC-PKCS5*/
]);

mapping(string:function) special_action_table = ([
   /* GCM only allows a tag size of 16, therefore set the DigestSize to "null" */
   "AES-GCM": unset_digest_size,
]);

/*
 * A list of all the vector files containing the tests.
 * Not all files may be supported.
 */
constant test_vectors = ({
	/* AEAD Tests */
	"aead_aes_siv_cmac_test.json",
	"aegis128L_test.json",
	"aegis128_test.json",
	"aegis256_test.json",
	"aes_ccm_test.json",
	"aes_eax_test.json",
	"aes_gcm_siv_test.json",
	"aes_gcm_test.json",
	"chacha20_poly1305_test.json",
	"xchacha20_poly1305_test.json",

	/* IndCpa Tests */
	"aes_cbc_pkcs5_test.json"
});


#define DBG_INFO 0
#define DBG_SUCCESS 1
#define DBG_ERROR 2
#define DBG_DBG 3

mapping(int:string) colors = ([
	DBG_INFO: "\x1B[34m", //Blue
	DBG_SUCCESS: "\x1B[32m", //Green
	DBG_ERROR: "\x1B[31m", //Red
	DBG_DBG: "\x1B[33m", //Yellow
]);

mapping(string:function) test_function_list = ([
   /* AEAD Testing */
   "aead_test_schema.json": aead_tests,

   /* IndCpa Testing */
   "ind_cpa_test_schema.json": indcpa_tests,
]);
