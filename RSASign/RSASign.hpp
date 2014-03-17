/*
Copyright (C) 2014 Charles E Sluder
Class for hashing and signing files

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <stdint.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>


/***
 * This isn't a very good seed, but we are just signing data not generating keys
 * so we don't really care about adding entropy to PRNG.
 */
static const char rndSeed[] = "In Xanadu did Kubla Khan a stately pleasure dome decree. Where Alph, the sacred river, ran through caverns measureless to man down to a sunless sea.";


class RSASign
{
public:
  enum HashType
  {
    HASH_SHA1   = 1,
    HASH_SHA256 = 2,
    HASH_SHA512 = 3
  };

  /***
   * Constructor for the RSA data signing class
   *
   * @param[IN] hashAlgorithm  Enum specifying one of the supported hash algorithms
   */
  RSASign( HashType hashAlgorithm );
  
  /***
   * Destructor for RSA data signing class
   */
  ~RSASign();

  /***
   * Allocate and initialize RSA object for the signing key pair
   *
   * @param[IN] publicKeyExponent  Public key Exponent for the key pair
   * @param[IN] size_e  number of bytes in the exponent
   * @parma[IN] publicKeyModulus Modulus for the public key
   * @param[IN] size_n number of bytes in the modulus
   * @param[IN] privateKeyExponent Private key exponent
   * @param[IN] size_d number of bytes in private key exponent
   */
  void GenerateKey( const unsigned char* publicKeyExponent,
                    const unsigned int size_e,
                    const unsigned char* publicKeyModulus,
                    const unsigned int size_n,
                    const unsigned char* privateKeyExponent,
                    const unsigned int size_d );

  /***
   * Allocate and initialize RSA object for the public key
   *
   * @param[IN] publicKeyExponent  Public key Exponent for the key pair
   * @param[IN] size_e  number of bytes in the exponent
   * @parma[IN] publicKeyModulus Modulus for the public key
   * @param[IN] size_n number of bytes in the modulus
   */
  void GenerateKey( const unsigned char* publicKeyExponent,
                    const unsigned int size_e,
                    const unsigned char* publicKeyModulus,
                    const unsigned int size_n );

  /***
   * Returns size required for a buffer to hold the Signature.
   *
   * @return Returns size required for a buffer to hold the Signature.
   */
  int GetSignatureSize();

  /***
   * Copy the previously generated signature into the supplied buffer.
   *
   * @param[IN] userBuffer  User supplied buffer to hold signature
   * @param[IN] bytes  Size of the buffer.
   *
   * @returns Returns number of bytes copied into userBuffer
   */
  int GetSignature( unsigned char* userBuffer, int bytes );

  /***
   * Copy the previously generated hash digest into the supplied buffer.
   *
   * @param[IN] userBuffer  User supplied buffer to hold digest
   * @param[IN] bytes  Size of the buffer.
   *
   * @returns Returns number of bytes copied into userBuffer
   */
  int GetDigest( unsigned char* userBuffer, int bytes );

  /***
   * Generate a hash for a data buffer
   *
   * @param[IN] data  Data block to be signed
   * @param[IN] dataLength Length of data block (Multiple of 64 bytes)
   *
   * @return Returns number of bytes in hash or value <= 0 on failure
   */
  int GenerateDigest( uint32_t* data, uint32_t dataLength );

  /***
   * Generate an RSA signature for a data buffer
   *
   * @param[IN] data  Data block to be signed
   * @param[IN] dataLength Length of data block (Multiple of 64 bytes)
   *
   * @return Returns number of bytes in signature or value <= 0 on failure
   */
  int GenerateSignature( uint32_t* data, uint32_t dataLength );

  /***
   * Verify the RSA signature for a data buffer
   *
   * @param[IN] data  Data block to be signed
   * @param[IN] dataLength Length of data block (Multiple of 64 bytes)
   *
   * @return returns 1 if signature verified and 0 if verification failed
   */
  int VerifySignature( uint32_t* data,
                       uint32_t data_length_bytes,
                       unsigned char* signature );

  /***
   *  Load the Signing keys from a PEM file
   *
   * @param[IN] pFilename PEM file name containig signing keys
   *
   * @return returns -1 if load failed and 0 if load succeeded 
   */
  int LoadPrivateKeyFile(char* pFilename);

  /***
   * Load the public key used to verify the signed file from an x509
   * certificate.
   *
   * @param[IN] pFilename PEM file containing the x509 certificate
   *
   * @return returns -1 if load failed and 0 if load succeeded 
   */
  int LoadX509(char* pFilename);

private:

  /***
   * Calculate the digest for the previously specified algorithm
   *
   * @param[IN] data  Data block to be hashed
   * @param[IN] dataLength length of data to be hashed
   */
  void _HashData( uint32_t* data, uint32_t dataLength );

private:
  typedef unsigned char* (*hashFunctionPtr)(const unsigned char *d, size_t n, unsigned char *md);

  RSA *m_pKey;
  hashFunctionPtr m_pHashFunction;
  unsigned char *m_pDigest;
  unsigned char *m_pSignature;
  int m_digestLength;
  int m_shaType;
  int m_sigSize;

};

