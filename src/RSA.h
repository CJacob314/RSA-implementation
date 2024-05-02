#ifndef __RSA_H
#define __RSA_H

#include <boost/integer/mod_inverse.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/multiprecision/number.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include "rust/cxx.h"
#include <atomic> // For multithreading
#include <climits>
#include <filesystem>
#include <fstream>
#include <future> // For multithreading
#include <iostream>
#include <memory>
#include <mutex> // For multithreading
#include <optional>
#include <sstream>
#include <streambuf>
#include <string>
#include <sys/random.h> // For cryptographically secure random numbers
#include <thread>       // For multithreading

#include "StringAssembler.h"

typedef boost::multiprecision::cpp_int BigInt;
typedef BigInt RsaKey;

class RSA {
#define EVEN(x) (!(x & 1))
#define ODD(x) (x & 1)
#define OAEP_ENCODING_PARAM "D92PBJK2X9IPKVQ158O4ICUOFXK4Z5OG"

private:
  const unsigned int Num_Prime_Search_Threads =
      std::thread::hardware_concurrency() << 1;
  std::array<BigInt, 2> primes; // The threads will write to this array when
                                // they've found a sufficient prime.
  std::mutex mtx; // To guard threaded access to the above `primes` array.
  std::atomic<uint8_t> primesFound{0}; // The control which index of `primes` to
                                       // write to once a prime has been found.
  std::atomic<bool> stopFlag{
      false}; // To signal the threads to stop searching for primes.
  std::condition_variable
      cv; // To signal the main thread when we've found two large primes.

  RsaKey privateKey, publicKey; // `publicKey` here is JUST the RSA modulus,
                                // since I always use e = 2^16 - 1.
  uint16_t pubKeyBytes, pubKeyBits;

  bool rabinMillerIsPrime(const BigInt &n, uint64_t accuracy);
  bool __rabinMillerHelper(BigInt d, BigInt n);
  void generatePrime(uint16_t keyLength);

  std::string toAsciiStr(BigInt n) const;
  BigInt fromAsciiStr(const std::string &str) const;

  std::string toAsciiCompressedStr(const BigInt &n) const;
  std::string toAsciiCompressedStr(const uint8_t *, size_t) const;
  BigInt fromAsciiCompressedStr(const std::string &ascii) const;

  const BigInt e = BigInt(1) << 16 | 0x1;

  class BigLCG {
  private:
    BigInt seed;

    const BigInt modulus = BigInt(1) << 128;
    const BigInt multiplier = BigInt(6364136223846793005) * 17;
    const BigInt increment = BigInt(1442695040888963407) * 23;

  public:
    BigLCG();
    BigInt next();
  };

public:
  RSA(){}; // Empty constructor. Will NOT encrypt or decrypt anything

  RSA(uint16_t newKeyLength);
  RSA(RsaKey privateKey, RsaKey publicKey);
  RSA(RsaKey publicKey);
  RSA(RSA &&other) noexcept; // Move constructor
  static std::optional<RSA> buildFromKeyFile(const char *filepath,
                                             bool importPrivateKey = false);
  static RSA
  empty(); // Only for use in comparisons, will not encrypt or decrypt anything
           // [unless you manually call importFromFile(), in which case the !
           // operator will no longer return true].

  // ! operator will return true if and only if the RSA object is invalid/empty
  bool operator!();

  std::unique_ptr<std::string>
  encrypt(const std::string &message, bool compressedAsciiOutput = false) const;

  std::unique_ptr<std::string> decrypt(const std::string &message,
                                       bool compressedAsciiInput = false) const;
  std::unique_ptr<std::string> sign(const std::string &message) const;
  bool verify(const std::string &signedMessage) const;
  std::unique_ptr<std::string> getFingerprint() const;
  bool testKey(void) const; // Returns true iff the private key was able to
                            // decrypt 64 random bytes the public key encrypted.

  bool exportToFile(const std::string &, bool exportPrivateKey = false,
                    bool forWebVersion = false) const;
  bool importFromFile(const std::string &, bool importPrivateKey = false);
  bool importFromString(const std::string &s, bool importPrivateKey = false);

  RsaKey getPrivateKey() const;
  RsaKey getPublicKey() const;
  uint64_t getPublicKeyLength() const;

  static std::unique_ptr<RSA> empty_uptr();

  // Additional class methods to interface with Rust (cxx makes passing strings
  // a real pain)
  std::unique_ptr<std::string>
  encrypt_wrapper(const rust::Str message, bool compressedAsciiOutput) const;
  std::unique_ptr<std::string> decrypt_wrapper(const rust::Str message,
                                               bool compressedAsciiInput) const;
  std::unique_ptr<std::string> sign_wrapper(const rust::Str message) const;
  bool verify_wrapper(const rust::Str signedMessage) const;
  std::unique_ptr<std::string> getFingerprint_wrapper() const;
  bool exportToFile_wrapper(const rust::Str filepath, bool exportPrivateKey,
                            bool forWebVersion) const;
  bool importFromFile_wrapper(const rust::Str filepath, bool importPrivateKey);
  bool importFromString_wrapper(const rust::Str s, bool importPrivateKey);
  uint16_t getPublicKeyBitCnt() const;

#ifdef DEBUG_TESTING
  void testPrimeDetection(BigInt n);
#endif
};

// new_rsa(bits: u16) -> UniquePtr<RSA>
std::unique_ptr<RSA> new_rsa(uint16_t bits);

std::unique_ptr<RSA> buildFromKeyFile(const rust::Str filepath,
                                      bool importPrivateKey = false,
                                      bool fromWebVersion = false);
#endif
