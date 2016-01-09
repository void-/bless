#include <iostream>
#include <fstream>

#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/x509self.h>
#include <botan/ecdsa.h>

using namespace Botan;

/**
 * @brief generate a certificate and private key for signing in Bless.
 *
 * @param argc length of \p argv
 * @param argv argument vector: ./keygen certificateFile keyFile
 * @return non-zero on failure
 */
int main(int argc, char **argv)
{
  //must have three arguments
  if(argc != 3)
  {
    std::cerr << "usage: " << argv[0] << " certificateOutputFile keyOutputFile"
      << std::endl;
    return -1;
  }

  try
  {
    //open rng and files
    AutoSeeded_RNG rng;
    std::ofstream certOut(argv[1]);
    std::ofstream keyOut(argv[2]);

    //set identifiers to blank for every Bless certificate
    X509_Cert_Options options;
    options.common_name = "..";
    options.country = "..";
    options.state = "";
    options.organization = "";
    options.email = "";
    options.not_before("1970-1-1 00:00:00");
    options.not_after("2038-1-18 19:14:07");
    options.sanity_check();

    //generate private key, currently only p256
    EC_Group group("secp256r1");
    ECDSA_PrivateKey key(rng, group);

    //derive and self-sign certificate
    X509_Certificate cert =
      X509::create_self_signed_cert(options, key, "SHA-256", rng);

    //serialize key and cert
    keyOut << PKCS8::PEM_encode(key, rng, "");
    certOut << cert.PEM_encode();
  }
  catch(std::exception &e)
  {
    std::cerr << "Exception: " << e.what() << std::endl;
    return -2;
  }

  return 0;
}
