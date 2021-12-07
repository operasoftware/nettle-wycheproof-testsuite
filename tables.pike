/*
 * tables.pike: Mappings/arrays of different functionality.
 */

/*
 * A list of the different functions for each algorithm.
 * These functions are called in a loop and are usually called as
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

	/* DSA Tests */
	"DSA": Crypto.DSA.State,

	/* ECDSA Tests */
	"ECDSA": Crypto.ECC.Curve, // This is not necessary but left here for future reference.

#if constant(Crypto.ECC.Curve25519) && constant(Crypto.ECC.Curve448)
	/* EDDSA Tests */
	"EDDSA": Crypto.ECC, // This is not necessary but left for future reference.
#endif

	/* MacTest Tests */
	"HMACSHA1": Crypto.HMAC(Crypto.SHA1),
	"HMACSHA224": Crypto.HMAC(Crypto.SHA224),
	"HMACSHA256": Crypto.HMAC(Crypto.SHA256),
	"HMACSHA384": Crypto.HMAC(Crypto.SHA384),
	"HMACSHA3-224": Crypto.HMAC(Crypto.SHA3_224),
	"HMACSHA3-256": Crypto.HMAC(Crypto.SHA3_256),
	"HMACSHA3-384": Crypto.HMAC(Crypto.SHA3_384),
	"HMACSHA3-512": Crypto.HMAC(Crypto.SHA3_512),
	"HMACSHA512": Crypto.HMAC(Crypto.SHA512),
//	"AES-CMAC": ??,
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
	"aes_cbc_pkcs5_test.json",

	/* DSA Tests */
	"dsa_2048_224_sha224_test.json",
	"dsa_2048_224_sha256_test.json",
	"dsa_2048_256_sha256_test.json",
	"dsa_3072_256_sha256_test.json",

	/* DSAP1363 Tests */
	"dsa_2048_224_sha224_p1363_test.json",
	"dsa_2048_224_sha256_p1363_test.json",
	"dsa_2048_256_sha256_p1363_test.json",
	"dsa_3072_256_sha256_p1363_test.json",

	/* ECDSA Tests */
	"ecdsa_brainpoolP224r1_sha224_test.json",
	"ecdsa_brainpoolP256r1_sha256_test.json",
	"ecdsa_brainpoolP320r1_sha384_test.json",
	"ecdsa_brainpoolP384r1_sha384_test.json",
	"ecdsa_brainpoolP512r1_sha512_test.json",
	"ecdsa_secp224r1_sha224_test.json",
	"ecdsa_secp224r1_sha256_test.json",
	"ecdsa_secp224r1_sha3_224_test.json",
	"ecdsa_secp224r1_sha3_256_test.json",
	"ecdsa_secp224r1_sha3_512_test.json",
	"ecdsa_secp224r1_sha512_test.json",
	"ecdsa_secp256k1_sha256_test.json",
	"ecdsa_secp256k1_sha3_256_test.json",
	"ecdsa_secp256k1_sha3_512_test.json",
	"ecdsa_secp256k1_sha512_test.json",
	"ecdsa_secp256r1_sha256_test.json",
	"ecdsa_secp256r1_sha3_256_test.json",
	"ecdsa_secp256r1_sha3_512_test.json",
	"ecdsa_secp256r1_sha512_test.json",
	"ecdsa_secp384r1_sha384_test.json",
	"ecdsa_secp384r1_sha3_384_test.json",
	"ecdsa_secp384r1_sha3_512_test.json",
	"ecdsa_secp384r1_sha512_test.json",
	"ecdsa_secp521r1_sha3_512_test.json",
	"ecdsa_secp521r1_sha512_test.json",

	/* ECDSAP1363 Tests */
	"ecdsa_brainpoolP224r1_sha224_p1363_test.json",
	"ecdsa_brainpoolP256r1_sha256_p1363_test.json",
	"ecdsa_brainpoolP320r1_sha384_p1363_test.json",
	"ecdsa_brainpoolP384r1_sha384_p1363_test.json",
	"ecdsa_brainpoolP512r1_sha512_p1363_test.json",
	"ecdsa_secp224r1_sha224_p1363_test.json",
	"ecdsa_secp224r1_sha256_p1363_test.json",
	"ecdsa_secp224r1_sha512_p1363_test.json",
	"ecdsa_secp256k1_sha256_p1363_test.json",
	"ecdsa_secp256k1_sha512_p1363_test.json",
	"ecdsa_secp256r1_sha256_p1363_test.json",
	"ecdsa_secp256r1_sha512_p1363_test.json",
	"ecdsa_secp384r1_sha384_p1363_test.json",
	"ecdsa_secp384r1_sha512_p1363_test.json",
	"ecdsa_secp521r1_sha512_p1363_test.json",
	"ecdsa_webcrypto_test.json",

#if constant(Crypto.ECC.Curve25519) && constant(Crypto.ECC.Curve448)
	/* EDDSA Tests */
	"eddsa_test.json",
	"ed448_test.json",
#endif

	/* MacTest Tests */
	"aes_cmac_test.json",
	"hmac_sha1_test.json",
	"hmac_sha224_test.json",
	"hmac_sha256_test.json",
	"hmac_sha384_test.json",
	"hmac_sha3_224_test.json",
	"hmac_sha3_256_test.json",
	"hmac_sha3_384_test.json",
	"hmac_sha3_512_test.json",
	"hmac_sha512_test.json",

});

/*
 * A list of the types of tests corresponding to their testing function
 */
mapping(string:function) test_function_list = ([
	/* AEAD Testing */
	"aead_test_schema.json": aead_tests,

	/* IndCpa Testing */
	"ind_cpa_test_schema.json": indcpa_tests,

	/* DSA Tests */
	"dsa_verify_schema.json": dsa_tests,

	/* DSAP1363 Tests */
	"dsa_p1363_verify_schema.json": dsa_tests,

	/* ECDSA Tests */
	"ecdsa_verify_schema.json": ecdsa_tests,

	/* ECDSAP1363 Tests */
	"ecdsa_p1363_verify_schema.json": ecdsa_tests,

#if constant(Crypto.ECC.Curve25519) && constant(Crypto.ECC.Curve448)
	/* EDDSA Tests */
	"eddsa_verify_schema.json": eddsa_tests,
#endif

	/* MacTest Tests */
	"mac_test_schema.json": mactest_tests,
]);

/*
 * A list of "special" functions which should be performed for specific
 * algorithms before running their testcases.
 */
mapping(string:function) special_action_table = ([
	/* GCM only allows a tag size of 16, therefore set the DigestSize to "null" */
	"AES-GCM": unset_digest_size,
]);

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
