/*
 * Copyright (C) 2022 Opera Norway AS. All rights reserved.
 * This file is an original work developed by Joshua Rogers.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

     http:www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/*
 * tables.pike: Mappings/arrays of different functionality.
 */

/*
 * A list of the different functions for each algorithm.
 * These functions are called in a loop and are usually called as
 * state = algo_functions[0]();
 */
mapping(string:function) algo_functions = ([
	/* AeadTest Tests */
	"AES-GCM": Crypto.AES.GCM.State, /*GCM*/
	"AES-EAX": Crypto.AES.EAX.State, /*EAX*/
	"AES-CCM": Crypto.AES.CCM.State, /*CCM*/
	"CHACHA20-POLY1305": Crypto.ChaCha20.POLY1305.State, /*ChaCha-Poly1305*/

	/* IndCpaTest Tests */
	"AES-CBC-PKCS5": Crypto.AES.CBC.Buffer, /*AES-CBC-PKCS5*/

	/* DsaVerify Tests */
	"DSA": Crypto.DSA.State, /*DSA(SHA-1,SHA-224,SHA-256,SHA-256)*/

	/* EcdsaVerify Tests */
	"ECDSA": Crypto.ECC, /*ECDSA*/

	/* EddsaVerify Tests */
	"EDDSA": Crypto.ECC, /*EDDSA*/

	/* EcdhEcpointTest Tests */
	"ECDH": Crypto.ECC, /*ECDH*/

	/* MacTest Tests */
	"HMACSHA1": Crypto.HMAC(Crypto.SHA1), /*HMAC-SHA-1*/
	"HMACSHA224": Crypto.HMAC(Crypto.SHA224), /*HMAC-SHA-224*/
	"HMACSHA256": Crypto.HMAC(Crypto.SHA256), /*HMAC-SHA-256*/
	"HMACSHA384": Crypto.HMAC(Crypto.SHA384), /*HMAC-SHA-384*/
	"HMACSHA512": Crypto.HMAC(Crypto.SHA512), /*HMAC-SHA-512*/
	"HMACSHA3-224": Crypto.HMAC(Crypto.SHA3_224), /*HMAC-SHA-3-224*/
	"HMACSHA3-256": Crypto.HMAC(Crypto.SHA3_256), /*HMAC-SHA-3-256*/
	"HMACSHA3-384": Crypto.HMAC(Crypto.SHA3_384), /*HMAC-SHA-3-384*/
	"HMACSHA3-512": Crypto.HMAC(Crypto.SHA3_512), /*HMAC-SHA-3-512*/

	/* PrimalityTest Tests */
	"PrimalityTest": Crypto.ECC,

	/* RsassaPkcs1Verify Tests */
	"RSASSA-PKCS1-v1_5": Standards.PKCS.RSA.parse_public_key,

	/* RsassaPkcs1Generate Tests */
//	"RSASSA-PKCS1-v1_5-GEN": Standards.PKCS.parse_private_key, // NB: Not Standards.PKCS.RSA.parse_private_key.

	/* RsaesPkcs1Decrypt Tests */
	"RSAES-PKCS1-v1_5": Standards.PKCS.parse_private_key, // NB: As above.

]);

/*
 * A list of all the vector files containing the tests.
 * Not all files may be supported.
 */
constant test_vectors = ({
	/* AeadTest Tests */
	"a128cbc_hs256_test.json",
	"a192cbc_hs384_test.json",
	"a256cbc_hs512_test.json",
	"aead_aes_siv_cmac_test.json",
	"aegis128L_test.json",
	"aegis128_test.json",
	"aegis256_test.json",
	"aes_ccm_test.json",
	"aes_eax_test.json",
	"aes_gcm_siv_test.json",
	"aes_gcm_test.json",
	"aria_ccm_test.json",
	"aria_gcm_test.json",
	"ascon128_test.json",
	"ascon128a_test.json",
	"ascon80pq_test.json",
	"camellia_ccm_test.json",
	"chacha20_poly1305_test.json",
	"morus1280_test.json",
	"morus640_test.json",
	"seed_ccm_test.json",
	"seed_gcm_test.json",
	"sm4_ccm_test.json",
	"sm4_gcm_test.json",
	"xchacha20_poly1305_test.json",

	/* IndCpaTest Tests */
	"aes_cbc_pkcs5_test.json",
	"aes_xts_test.json",
	"aria_cbc_pkcs5_test.json",
	"camellia_cbc_pkcs5_test.json",

	/* DsaVerify Tests */
	"dsa_2048_224_sha224_test.json",
	"dsa_2048_224_sha256_test.json",
	"dsa_2048_256_sha256_test.json",
	"dsa_3072_256_sha256_test.json",

	/* DsaP1363Verify Tests */
	"dsa_2048_224_sha224_p1363_test.json",
	"dsa_2048_224_sha256_p1363_test.json",
	"dsa_2048_256_sha256_p1363_test.json",
	"dsa_3072_256_sha256_p1363_test.json",

	/* EcdsaVerify Tests */
	"ecdsa_brainpoolP224r1_sha224_test.json",
	"ecdsa_brainpoolP224r1_sha3_224_test.json",
	"ecdsa_brainpoolP256r1_sha256_test.json",
	"ecdsa_brainpoolP256r1_sha3_256_test.json",
	"ecdsa_brainpoolP320r1_sha3_384_test.json",
	"ecdsa_brainpoolP320r1_sha384_test.json",
	"ecdsa_brainpoolP384r1_sha3_384_test.json",
	"ecdsa_brainpoolP384r1_sha384_test.json",
	"ecdsa_brainpoolP512r1_sha3_512_test.json",
	"ecdsa_brainpoolP512r1_sha512_test.json",
	"ecdsa_secp160k1_sha256_test.json",
	"ecdsa_secp160r1_sha256_test.json",
	"ecdsa_secp160r2_sha256_test.json",
	"ecdsa_secp192k1_sha256_test.json",
	"ecdsa_secp192r1_sha256_test.json",
	"ecdsa_secp224k1_sha224_test.json",
	"ecdsa_secp224k1_sha256_test.json",
	"ecdsa_secp224r1_sha224_test.json",
	"ecdsa_secp224r1_sha256_test.json",
	"ecdsa_secp224r1_sha3_224_test.json",
	"ecdsa_secp224r1_sha3_256_test.json",
	"ecdsa_secp224r1_sha3_512_test.json",
	"ecdsa_secp224r1_sha512_test.json",
	"ecdsa_secp224r1_shake128_test.json",
	"ecdsa_secp256k1_sha256_test.json",
	"ecdsa_secp256k1_sha3_256_test.json",
	"ecdsa_secp256k1_sha3_512_test.json",
	"ecdsa_secp256k1_sha512_test.json",
	"ecdsa_secp256k1_shake128_test.json",
	"ecdsa_secp256k1_shake256_test.json",
	"ecdsa_secp256r1_sha256_test.json",
	"ecdsa_secp256r1_sha3_256_test.json",
	"ecdsa_secp256r1_sha3_512_test.json",
	"ecdsa_secp256r1_sha512_test.json",
	"ecdsa_secp256r1_shake128_test.json",
	"ecdsa_secp384r1_sha256_test.json",
	"ecdsa_secp384r1_sha3_384_test.json",
	"ecdsa_secp384r1_sha3_512_test.json",
	"ecdsa_secp384r1_sha384_test.json",
	"ecdsa_secp384r1_sha512_test.json",
	"ecdsa_secp384r1_shake256_test.json",
	"ecdsa_secp521r1_sha3_512_test.json",
	"ecdsa_secp521r1_sha512_test.json",
	"ecdsa_secp521r1_shake256_test.json",

	/* EcdsaP1363Verify Tests */
	"ecdsa_brainpoolP224r1_sha224_p1363_test.json",
	"ecdsa_brainpoolP256r1_sha256_p1363_test.json",
	"ecdsa_brainpoolP320r1_sha384_p1363_test.json",
	"ecdsa_brainpoolP384r1_sha384_p1363_test.json",
	"ecdsa_brainpoolP512r1_sha512_p1363_test.json",
	"ecdsa_secp160k1_sha256_p1363_test.json",
	"ecdsa_secp160r1_sha256_p1363_test.json",
	"ecdsa_secp160r2_sha256_p1363_test.json",
	"ecdsa_secp192k1_sha256_p1363_test.json",
	"ecdsa_secp192r1_sha256_p1363_test.json",
	"ecdsa_secp224k1_sha224_p1363_test.json",
	"ecdsa_secp224k1_sha256_p1363_test.json",
	"ecdsa_secp224r1_sha224_p1363_test.json",
	"ecdsa_secp224r1_sha256_p1363_test.json",
	"ecdsa_secp224r1_sha512_p1363_test.json",
	"ecdsa_secp224r1_shake128_p1363_test.json",
	"ecdsa_secp256k1_sha256_p1363_test.json",
	"ecdsa_secp256k1_sha512_p1363_test.json",
	"ecdsa_secp256k1_shake128_p1363_test.json",
	"ecdsa_secp256k1_shake256_p1363_test.json",
	"ecdsa_secp256r1_sha256_p1363_test.json",
	"ecdsa_secp256r1_sha512_p1363_test.json",
	"ecdsa_secp256r1_shake128_p1363_test.json",
	"ecdsa_secp256r1_webcrypto_test.json",
	"ecdsa_secp384r1_sha384_p1363_test.json",
	"ecdsa_secp384r1_sha512_p1363_test.json",
	"ecdsa_secp384r1_shake256_p1363_test.json",
	"ecdsa_secp384r1_webcrypto_test.json",
	"ecdsa_secp521r1_sha512_p1363_test.json",
	"ecdsa_secp521r1_shake256_p1363_test.json",
	"ecdsa_secp521r1_webcrypto_test.json",

	/* EddsaVerify Tests */
	"ed25519_test.json",
	"ed448_test.json",

	/* EcdhEcpointTest Tests */
	"ecdh_secp224r1_ecpoint_test.json",
	"ecdh_secp256r1_ecpoint_test.json",
	"ecdh_secp384r1_ecpoint_test.json",
	"ecdh_secp521r1_ecpoint_test.json",

	/* EcdhTest Tests */
	"ecdh_brainpoolP224r1_test.json",
	"ecdh_brainpoolP256r1_test.json",
	"ecdh_brainpoolP320r1_test.json",
	"ecdh_brainpoolP384r1_test.json",
	"ecdh_brainpoolP512r1_test.json",
	"ecdh_secp224r1_test.json",
	"ecdh_secp256k1_test.json",
	"ecdh_secp256r1_test.json",
	"ecdh_secp384r1_test.json",
	"ecdh_secp521r1_test.json",

	/* EcdhWebcryptoTest Tests */
	"ecdh_secp256k1_webcrypto_test.json",
	"ecdh_secp256r1_webcrypto_test.json",
	"ecdh_secp384r1_webcrypto_test.json",
	"ecdh_secp521r1_webcrypto_test.json",

	/* MacTest Tests */
	"aes_cmac_test.json",
	"aria_cmac_test.json",
	"camellia_cmac_test.json",
	"hmac_sha1_test.json",
	"hmac_sha224_test.json",
	"hmac_sha256_test.json",
	"hmac_sha3_224_test.json",
	"hmac_sha3_256_test.json",
	"hmac_sha3_384_test.json",
	"hmac_sha3_512_test.json",
	"hmac_sha384_test.json",
	"hmac_sha512_224_test.json",
	"hmac_sha512_256_test.json",
	"hmac_sha512_test.json",
	"hmac_sm3_test.json",
	"kmac128_no_customization_test.json",
	"kmac256_no_customization_test.json",
	"siphash_1_3_test.json",
	"siphash_2_4_test.json",
	"siphash_4_8_test.json",
	"siphashx_2_4_test.json",
	"siphashx_4_8_test.json",

	/* MacWithIvTest Tests */
	"aes_gmac_test.json",
	"vmac_128_test.json",
	"vmac_64_test.json",

	/* PrimalityTest Tests */
	"primality_test.json",

	/* HkdfTest Tests */
	"hkdf_sha1_test.json",
	"hkdf_sha256_test.json",
	"hkdf_sha384_test.json",
	"hkdf_sha512_test.json",

	/* KeywrapTest Tests */
	"aes_kwp_test.json",
	"aes_wrap_test.json",
	"aria_kwp_test.json",
	"aria_wrap_test.json",
	"camellia_wrap_test.json",
	"seed_wrap_test.json",

	/* RsassaPkcs1Verify Tests */
	"rsa_signature_2048_sha224_test.json",
	"rsa_signature_2048_sha256_test.json",
	"rsa_signature_2048_sha3_224_test.json",
	"rsa_signature_2048_sha3_256_test.json",
	"rsa_signature_2048_sha3_384_test.json",
	"rsa_signature_2048_sha3_512_test.json",
	"rsa_signature_2048_sha384_test.json",
	"rsa_signature_2048_sha512_224_test.json",
	"rsa_signature_2048_sha512_256_test.json",
	"rsa_signature_2048_sha512_test.json",
	"rsa_signature_3072_sha256_test.json",
	"rsa_signature_3072_sha3_256_test.json",
	"rsa_signature_3072_sha3_384_test.json",
	"rsa_signature_3072_sha3_512_test.json",
	"rsa_signature_3072_sha384_test.json",
	"rsa_signature_3072_sha512_256_test.json",
	"rsa_signature_3072_sha512_test.json",
	"rsa_signature_4096_sha256_test.json",
	"rsa_signature_4096_sha384_test.json",
	"rsa_signature_4096_sha512_256_test.json",
	"rsa_signature_4096_sha512_test.json",
	"rsa_signature_8192_sha256_test.json",
	"rsa_signature_8192_sha384_test.json",
	"rsa_signature_8192_sha512_test.json",

	/* RsassaPssVerify Tests */
	"rsa_pss_2048_sha1_mgf1_20_test.json",
	"rsa_pss_2048_sha256_mgf1_0_test.json",
	"rsa_pss_2048_sha256_mgf1_32_test.json",
	"rsa_pss_2048_sha256_mgf1sha1_20_test.json",
	"rsa_pss_2048_sha384_mgf1_48_test.json",
	"rsa_pss_2048_sha512_224_mgf1_28_test.json",
	"rsa_pss_2048_sha512_256_mgf1_32_test.json",
	"rsa_pss_2048_shake128_params_test.json",
	"rsa_pss_2048_shake128_test.json",
	"rsa_pss_2048_shake256_test.json",
	"rsa_pss_3072_sha256_mgf1_32_test.json",
	"rsa_pss_3072_shake128_params_test.json",
	"rsa_pss_3072_shake128_test.json",
	"rsa_pss_3072_shake256_params_test.json",
	"rsa_pss_3072_shake256_test.json",
	"rsa_pss_4096_sha256_mgf1_32_test.json",
	"rsa_pss_4096_sha384_mgf1_48_test.json",
	"rsa_pss_4096_sha512_mgf1_32_test.json",
	"rsa_pss_4096_sha512_mgf1_64_test.json",
	"rsa_pss_4096_shake256_params_test.json",
	"rsa_pss_4096_shake256_test.json",
	"rsa_pss_misc_test.json",

	/* RsaesOaepDecrypt Tests */
	"rsa_oaep_2048_sha1_mgf1sha1_test.json",
	"rsa_oaep_2048_sha224_mgf1sha1_test.json",
	"rsa_oaep_2048_sha224_mgf1sha224_test.json",
	"rsa_oaep_2048_sha256_mgf1sha1_test.json",
	"rsa_oaep_2048_sha256_mgf1sha256_test.json",
	"rsa_oaep_2048_sha384_mgf1sha1_test.json",
	"rsa_oaep_2048_sha384_mgf1sha384_test.json",
	"rsa_oaep_2048_sha512_224_mgf1sha1_test.json",
	"rsa_oaep_2048_sha512_224_mgf1sha512_224_test.json",
	"rsa_oaep_2048_sha512_mgf1sha1_test.json",
	"rsa_oaep_2048_sha512_mgf1sha512_test.json",
	"rsa_oaep_3072_sha256_mgf1sha1_test.json",
	"rsa_oaep_3072_sha256_mgf1sha256_test.json",
	"rsa_oaep_3072_sha512_256_mgf1sha1_test.json",
	"rsa_oaep_3072_sha512_256_mgf1sha512_256_test.json",
	"rsa_oaep_3072_sha512_mgf1sha1_test.json",
	"rsa_oaep_3072_sha512_mgf1sha512_test.json",
	"rsa_oaep_4096_sha256_mgf1sha1_test.json",
	"rsa_oaep_4096_sha256_mgf1sha256_test.json",
	"rsa_oaep_4096_sha512_mgf1sha1_test.json",
	"rsa_oaep_4096_sha512_mgf1sha512_test.json",
	"rsa_oaep_misc_test.json",
	"rsa_three_primes_oaep_2048_sha1_mgf1sha1_test.json",
	"rsa_three_primes_oaep_3072_sha224_mgf1sha224_test.json",
	"rsa_three_primes_oaep_4096_sha256_mgf1sha256_test.json",

	/* RsassaPkcs1Generate Tests */
//	"rsa_sig_gen_misc_test.json",

	/* RsaesPkcs1Decrypt Tests */
	"rsa_pkcs1_2048_test.json",
	"rsa_pkcs1_3072_test.json",
	"rsa_pkcs1_4096_test.json",

	/* XdhAsnComp Tests */
	"x25519_asn_test.json",
	"x448_asn_test.json",

	/* XdhComp Tests */
	"x25519_test.json",
	"x448_test.json",

	/* XdhJwkComp Tests */
	"x25519_jwk_test.json",
	"x448_jwk_test.json",

	/* XdhPemComp Tests */
	"x25519_pem_test.json",
	"x448_pem_test.json",
});

/*
 * A list of the types(schemas) of tests corresponding to their testing
 * function.
 */
mapping(string:function) test_function_list = ([
	/* AeadTest Testing */
	"aead_test_schema.json": aead_tests,

	/* IndCpaTest Testing */
	"ind_cpa_test_schema.json": indcpa_tests,

	/* DsaVerify Tests */
	"dsa_verify_schema.json": dsa_tests,

	/* EcdsaVerify Tests */
	"ecdsa_verify_schema.json": ecdsa_tests,

	/* EddsaVerify Tests */
#if constant(Crypto.ECC.Curve25519) && constant(Crypto.ECC.Curve448)
	"eddsa_verify_schema.json": eddsa_tests,
#endif

	/* EcdhEcpointTest Tests */
	"ecdh_ecpoint_test_schema.json": ecdh_point_tests,

	/* MacTest Tests */
	"mac_test_schema.json": mactest_tests,

	/* PrimalityTest Tests */
	"primality_test_schema.json": prime_tests,

	/* RsassaPkcs1Verify Tests */
	"rsassa_pkcs1_verify_schema.json": rsa_verify_tests,

	/* RsassaPkcs1Generate Tests */
//	"rsassa_pkcs1_generate_schema.json": rsa_generate_tests,

	/* RsaesPkcs1Decrypt Tests */
	"rsaes_pkcs1_decrypt_schema.json": rsa_decrypt_tests,
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
