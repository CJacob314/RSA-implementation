#include "../RSA.h"

std::unique_ptr<std::string>
RSA::encrypt_wrapper(const rust::Str message,
                     bool compressedAsciiOutput) const {
  return encrypt(std::string(message.data(), message.size()),
                 compressedAsciiOutput);
}

std::unique_ptr<std::string>
RSA::decrypt_wrapper(const rust::Str message, bool compressedAsciiInput) const {
  return decrypt(std::string(message.data(), message.size()),
                 compressedAsciiInput);
}

std::unique_ptr<std::string> RSA::sign_wrapper(const rust::Str message) const {
  return sign(std::string(message.data(), message.size()));
}

bool RSA::verify_wrapper(const rust::Str signedMessage) const {
  return verify(std::string(signedMessage.data(), signedMessage.size()));
}

std::unique_ptr<std::string> RSA::getFingerprint_wrapper() const {
  return getFingerprint();
}

bool RSA::exportToFile_wrapper(const rust::Str filepath, bool exportPrivateKey,
                               bool forWebVersion) const {
  return exportToFile(std::string(filepath.data(), filepath.size()),
                      exportPrivateKey, forWebVersion);
}

bool RSA::importFromFile_wrapper(const rust::Str filepath,
                                 bool importPrivateKey) {
  return importFromFile(std::string(filepath.data(), filepath.size()),
                        importPrivateKey);
}

bool RSA::importFromString_wrapper(const rust::Str s, bool importPrivateKey) {
  return importFromString(std::string(s.data(), s.size()), importPrivateKey);
}

std::unique_ptr<RSA> buildFromKeyFile(const rust::Str filepath_str,
                                      bool importPrivateKey,
                                      bool fromWebVersion) {
  std::string filepath = std::string(filepath_str.data(), filepath_str.size());
  auto rsa = RSA::empty_uptr();
  auto is_readable_file = [](const std::string &fp) -> bool {
    namespace fs = std::filesystem;
    fs::path path(fp);

    // Check this file exists and is a non-directory file
    if (!fs::exists(path) || !fs::is_regular_file(path)) {
      return false;
    }

    // Check that the file is readable
    std::ifstream file(path);
    if (!file.is_open()) {
      return false;
    }
    return true;
  };

  if (!fromWebVersion) {
    try {
      if (rsa->importFromFile(filepath, importPrivateKey)) {
        return rsa;
      } else {
        std::cerr << "Failed to import RSA key from file: " << filepath
                  << std::endl;
        return NULL;
      }
    } catch (std::runtime_error &e) {
      std::cerr << "Caught exception while reading keyfile \"" << filepath
                << "\": " << e.what() << std::endl;
      return NULL;
    }
  } else {
    auto rsa = RSA::empty_uptr();
    // First, check that filepath exists
    if (!is_readable_file(filepath)) {
      std::cerr << "File \"" << filepath
                << "\" does not exist or is not readable\n"
                << std::flush;
      return NULL;
    }

    // Read all text from file: filepath
    std::ifstream file(filepath);
    std::string fcontents((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
    file.close();
    try {
      rsa->importFromString(fcontents, importPrivateKey);
    } catch (const std::runtime_error &e) {
      std::cerr << "Caught exception while creating RSA object from keyfile\""
                << filepath << "\": " << e.what() << std::endl;
      return NULL;
    }
    return rsa;
  }
}

std::unique_ptr<RSA> RSA::empty_uptr() { return std::make_unique<RSA>(); }

std::unique_ptr<RSA> new_rsa(uint16_t bits) {
  return std::make_unique<RSA>(bits);
}
