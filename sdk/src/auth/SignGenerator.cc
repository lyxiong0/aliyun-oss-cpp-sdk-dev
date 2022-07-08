#include "SignGenerator.h"

using namespace AlibabaCloud::OSS;

SignGenerator::SignGenerator(const std::string& version) : version_(version) {
  // First decided by algorithm, if not 
  // then use version's default algorithm
  if (version == "4.0") {
    signAlgo_ = std::make_shared<HmacSha256Signer>();
  } else {
    signAlgo_ = std::make_shared<HmacSha1Signer>();
  }
}