# PikeProof

PikeProof is a project to utilize the [Wycheproof](https://github.com/google/wycheproof) cryptographic testcases in Pike, in order to test both the Nettle cryptographic library, and Pike's glue(bindings) to the library.

Various vectors of tests are grouped together into common testing types, each corresponding to a file in the project. Because each testing type generally follow the same formula (e.g. `encrypt()`; `decrypt()`; `verify()`), each vector shares similar functions.

In specific cases of common testing types needing irregular actions to be taken, the `special_action_table` array (in `tables.pike`) handles one(or more)-off functions which can be used to prepare the special cases. For example, the AeadTest-type algorithm "AES-GCM" is special from other AeadTest-types, in that it cannot calculate a truncated digest, and thus special handling must be done to the test's data before the testing begins.

The program is made in such a way that new testcases can be added more-or-less in a plug-and-play fashion.
For example, if new [IndCpaTest](https://github.com/google/wycheproof/blob/master/doc/files.md#IndCpaTest) (corresponding to the [ind_cpa_test_schema.json](https://github.com/google/wycheproof/blob/master/doc/types.md#indcpatestgroup) test group) test vectors are released in the future, it is only necessary to update the file `tables.pike` with an addition to the array `test_vectors` of the new vector's filename (and possibly to the mapping `algo_functions` if a different algorithm is used).

Commit 5c180c4e54f94ace678d7a6feb4a033958e83d00 is an excellent example of just how easy it is to add new test vectors which are automatically cycled through via the main script.

A blog post detailing more of the development process of this project can be found [here](https://joshua.hu/pikeproof-wycheproof-pike-checks).

## Usage

```shell
# Runs all of the Wycheproof tests in Pike.
pike main.pike

# Runs all the tests with verbose debugging information.
pike main.pike D

# Runs all the tests without color output.
main.pike NO_COL

# Runs tests for a specific algorithm (NOT 'type').
main.pike RSAES-PKCS1-v1_5

# Runs tests for a specific algorithm, providing debugging information without color output.
main.pike NO_COL RSAES-PKCS1-v1_5 D
```

## Results
A list of issues found by this program are listed below.

### Crypto.AES.CCM
1. Null Pointer Dereference [Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10072)
2. Incorrect Digest [Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10074)
3. Documentation Lacks IV Truncation Information [Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10073)

### Crypto.DSA
1. Infinite Loop [Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10075)
2. Modified r,s Values Verify With Degrees Of Malleability [Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10077)
3. PKCS Signatured Verified With Degrees Of Malleability [Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10076)

### Crypto.ECC.ECDSA
1. PKCS Signatured Verified With Degrees Of Malleability [Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10076)

### Gmp.mpz.probably_prime_p
1. Inconsistent Prime Handling [Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10079)

### Crypto.ECC.SECP_521R1
1. Incorrect Signature Verification [Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10078)

### Crypto.RSA
1. Decryption With Degrees Of Malleability [Pike](https://git.lysator.liu.se/pikelang/pike/-/issues/10080)

## Ideas (some have been utilised)
1. In various cases, different forms/types of data are provided with respect to keys. For example, public/private keys may be provided in both pem and DER formatting. One test could ensure these keys are parsed to be the same.
2. Properly implement ECDH tests.
3. Implement tests for RSASSA-PSS, RSAES-OAEP, KW
4. Run the tests on hardware which Nettle has assembly optimization -- for example, ARM and SPARC.

## License
The Wycheproof project and its testcases are provided under the [apache-2.0 license](/LICENSE).
