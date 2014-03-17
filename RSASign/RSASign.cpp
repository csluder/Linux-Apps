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

#include <cstring>

#include "RSASign.hpp"


RSASign::RSASign( HashType hashAlgorithm ):
                  m_pKey(0),
                  m_pDigest(0)
{
  // Pro forma, not really needed for hashing and signing data.
  CRYPTO_malloc_debug_init();
  CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
  CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
  RAND_seed( rndSeed, sizeof(rndSeed) );

  switch (hashAlgorithm)
  {
    case RSASign::HASH_SHA1:
    {
      m_pHashFunction = SHA1;
      m_digestLength = SHA_DIGEST_LENGTH;
      m_shaType = NID_sha1;
      break;
    }

    case RSASign::HASH_SHA256:
    {
      m_pHashFunction = SHA256;
      m_digestLength = SHA256_DIGEST_LENGTH;
      m_shaType = NID_sha256;
      break;
    }

    case RSASign::HASH_SHA512:
    {
      m_pHashFunction = SHA512;
      m_digestLength = SHA512_DIGEST_LENGTH;
      m_shaType = NID_sha512;
      break;
    }

    default:
    {
      m_pHashFunction = SHA256;
      m_digestLength = SHA256_DIGEST_LENGTH;
      m_shaType = NID_sha256;
      break;
    }
  } //End switch statement

  m_pDigest    = new unsigned char[m_digestLength];
}

RSASign::~RSASign()
{
  if ( m_pKey != 0 )
  {
    if ( m_pKey->n != NULL  )
    {
      BN_free( m_pKey->n );
      m_pKey->n = NULL;
    }
    if ( m_pKey->e != NULL  )
    {
      BN_free( m_pKey->e );
      m_pKey->e = NULL;
    }
    if ( m_pKey->d != NULL  )
    {
      BN_free( m_pKey->d );
      m_pKey->d = NULL;
    }
    RSA_free(m_pKey);
    delete[] m_pDigest;
    delete[] m_pSignature;
  }


  CRYPTO_cleanup_all_ex_data();
  ERR_remove_state(0);
  CRYPTO_mem_leaks_fp(stderr);
}

/**
 * Create and RSA key struct from the key exponent and modulus
 */
void RSASign::GenerateKey( const unsigned char* publicKeyExponent,
                      const uint32_t size_e,
                      const unsigned char* publicKeyModulus,
                      const uint32_t size_n,
                      const unsigned char* privateKeyExponent,
                      const uint32_t size_d )
{
  m_pKey = RSA_new();
  m_pKey->n = BN_bin2bn( publicKeyModulus,   size_n, m_pKey->n);
  m_pKey->e = BN_bin2bn( publicKeyExponent,  size_e, m_pKey->e);
  m_pKey->d = BN_bin2bn( privateKeyExponent, size_d, m_pKey->d);

  m_sigSize    = RSA_size( m_pKey );
  m_pSignature = new unsigned char[m_sigSize];

}

void RSASign::GenerateKey( const unsigned char* publicKeyExponent,
                      const uint32_t size_e,
                      const unsigned char* publicKeyModulus,
                      const uint32_t size_n )
{
  m_pKey = RSA_new();
  m_pKey->n = BN_bin2bn( publicKeyModulus,   size_n, m_pKey->n);
  m_pKey->e = BN_bin2bn( publicKeyExponent,  size_e, m_pKey->e);
  m_pKey->d = NULL;

  m_sigSize    = RSA_size( m_pKey );
  m_pSignature = new unsigned char[m_sigSize];
}

/**
 * Let the application know how much memory to allocate for the signature.
 */
int RSASign::GetSignatureSize()
{
  return m_sigSize;
}

/**
 * Calls the appropriate hash function for the application spedified hahs
 */
void RSASign::_HashData( uint32_t* data, uint32_t dataLength )
{
  unsigned char* tempBuffer  = new unsigned char[dataLength];

  if ( tempBuffer != NULL && m_pDigest != NULL ) 
  {
    memcpy( tempBuffer, data, dataLength );
    m_pHashFunction( tempBuffer, dataLength, m_pDigest );

    delete[] tempBuffer;
  }
}

/**
 * Application interface to the hahsing function.
 */
int RSASign::GenerateDigest( uint32_t* data, uint32_t dataLength )
{
  if ( data == NULL || dataLength <= 0 )
  {
    return -2;
  }

  _HashData( data, dataLength );

  return m_digestLength;
}

/**
 * Application interface to the hashing function
 */
int RSASign::GenerateSignature( uint32_t* data, uint32_t dataLength )
{
  int retval = 0;


  if ( (data == NULL) || (m_pKey == NULL) )
  {
    return -2;
  }

  /**
   * RSA sign requires a digest of the data being signed.
   */
  _HashData( data, dataLength );

  if ( m_pDigest != NULL ) 
  {
    unsigned int bytes;

    if (RSA_sign(m_shaType, m_pDigest, m_digestLength, m_pSignature, &bytes , m_pKey) == 1 )
    {
      retval = bytes;
    }
  }
   
  return retval;
}

int RSASign::VerifySignature( uint32_t* data,
                              uint32_t dataLength,
                              unsigned char* signature )
{
  int retval = 0;

  if ( (data == NULL) || (m_pKey == NULL) )
  {
    return -2;
  }

  /**
   * Need a digest to compare against the signature once it is unencrypted.
   */
  _HashData( data, dataLength );

  /**
   * Using the key previously created public key, unencrypt the signature and verify it against
   * digest just computed.
   */
  if ( m_pDigest != NULL ) 
  {
    retval = RSA_verify(m_shaType, m_pDigest, m_digestLength, signature, m_sigSize , m_pKey);
  }
   
  return retval;
}

/**
 * Let the application retrieve the digest for the data.
 */
int RSASign::GetDigest( unsigned char* userBuffer, int bytes )
{
  if ( m_digestLength < bytes )
  {
    bytes = m_sigSize;
  }
 
  memcpy( userBuffer, m_pDigest, bytes );
 
  return bytes;
}

/**
 * Allow the application to retrieve the signature
 */
int RSASign::GetSignature( unsigned char* userBuffer, int bytes )
{
  if ( m_sigSize < bytes )
  {
    bytes = m_sigSize;
  }
  memcpy( userBuffer, m_pSignature, bytes );

  return bytes;
}

/**
 * Load the private key from a pem file
 */
int RSASign::LoadPrivateKeyFile(char *pFilename)
{
  FILE* pFile = fopen(pFilename,"rt");
  int retval = -1;

  if ( pFile != NULL )
  {
    m_pKey = PEM_read_RSAPrivateKey( pFile, NULL, NULL, NULL );
    if ( m_pKey != NULL )
    {
      m_sigSize    = RSA_size( m_pKey );
      m_pDigest    = new unsigned char[m_digestLength];
      m_pSignature = new unsigned char[m_sigSize];
      fclose( pFile );
      retval = 0;
    }
  }

  return retval;
}

/**
 * Load a public key from an x509 certificate
 */
int RSASign::LoadX509(char *pFilename)
{
  int retval = -1;

  // Read in the x509 and get a pointer to the envelope
  // containing the RSA structure.
  FILE* pFile = fopen( pFilename, "rt" );
  if (pFile != NULL )
  {
    // XXX - Need to add a callback to handle encrypted keys
    /**
     * Copy the public key into an envelope
     */
    X509* x509 = PEM_read_X509(pFile,NULL, NULL, NULL);
    EVP_PKEY* pPubKey = X509_get_pubkey(x509);
    X509_free( x509 );
    fclose(pFile);

    // Allocate a new RSA key structure and copy the modulus and exponent
    // into the structure before freeing the envelope for the x509.
    if ( pPubKey != NULL )
    {
      m_pKey = RSA_new();
      m_pKey->e = BN_dup( pPubKey->pkey.rsa->e );
      m_pKey->n = BN_dup( pPubKey->pkey.rsa->n );
      m_pKey->d = NULL;

      m_sigSize    = RSA_size( m_pKey );
      m_pDigest    = new unsigned char[m_digestLength];
      m_pSignature = new unsigned char[m_sigSize];

      EVP_PKEY_free(pPubKey);

      retval = 0;
    }
  }

  return retval;
}
