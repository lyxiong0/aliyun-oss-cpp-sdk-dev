/*
 * Copyright 2009-2017 Alibaba Cloud All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "AuthSignerV4.h"


using namespace AlibabaCloud::OSS;

namespace
{
    const char *TAG = "AuthSignerV4";
}

AuthSignerV4::AuthSignerV4(const std::string &region, const std::string &product) : region_(region), product_(product) {
  signAlgo_ = std::make_shared<HmacSha256Signer>();
}

bool AuthSignerV4::needToSignHeader(const std::string &headerKey, const HeaderSet &additionalHeaders) const {
    return headerKey == "content-type" 
        || headerKey == "content-md5" 
        || headerKey.compare(0, 6, "x-oss-") 
        || additionalHeaders.find(headerKey) != additionalHeaders.end();
}

std::string AuthSignerV4::genCanonicalReuqest(const std::string &method,
                                                 const std::string &resource,
                                                 const HeaderCollection &headers,
                                                 const ParameterCollection &parameters,
                                                 const HeaderSet &additionalHeaders) const
{
    /*Version 4*/
    // HTTP Verb + "\n" +
    // Canonical URI + "\n" +
    // Canonical Query String + "\n" +
    // Canonical Headers + "\n" +
    // Additional Headers + "\n" +
    // Hashed PayLoad

    std::stringstream ss;
    // "GET" | "PUT" | "POST" | ... + "\n"
    ss << method << "\n"; 
    // UriEncode(<Resource>) + "\n"
    ss << UrlEncode(resource, true) << "\n"; 

    // Canonical Query String + "\n"
    // UriEncode(<QueryParam1>) + "=" + UriEncode(<Value>) + "&" + UriEncode(<QueryParam2>) + "\n"
    char separator = '&';
    bool isFirstParam = true;
    for (auto const &param : parameters)
    {
        std::string lowerKey = Trim(ToLower(param.first.c_str()).c_str());
        std::string lowerVal = Trim(ToLower(param.second.c_str()).c_str());
        if (ParamtersToSign.find(lowerKey) == ParamtersToSign.end())
        {
            continue;
        }

        if (!isFirstParam)
        {
            ss << separator;
        }
        else
        {
            isFirstParam = false;
        }

        ss << UrlEncode(lowerKey);
        if (!lowerVal.empty())
        {
            ss << "=" << UrlEncode(lowerVal);
        }
    }
    ss << "\n";

    // Lowercase(<HeaderName1>) + ":" + Trim(<value>) + "\n" + Lowercase(<HeaderName2>) + ":" + Trim(<value>) + "\n" + "\n"
    std::string playload;
    for (const auto &header : headers)
    {
        std::string lowerKey = Trim(ToLower(header.first.c_str()).c_str());
        std::string value = Trim(header.second.c_str());
        if (needToSignHeader(lowerKey, additionalHeaders)) {
            ss << lowerKey << ":" << value << "\n";
            if (lowerKey == "x-oss-content-sha256")
            {
                // hashed payload
                playload = value;
            }
        }
    }
    ss << "\n";

    // Lowercase(<AdditionalHeaderName1>) + ";" + Lowercase(<AdditionalHeaderName2>) + "\n" +
    std::stringstream additionalSS;
    bool isFirstHeader = true;
    for (const auto &addHeader : additionalHeaders)
    {
        if (headers.find(addHeader) == headers.end())
        {
            continue;
        }

        if (!isFirstHeader)
        {
            additionalSS << ";";
        }
        else
        {
            isFirstHeader = false;
        }
        additionalSS << addHeader.c_str();
    }

    ss << additionalSS.str() << "\n"
       << playload;

    return ss.str();
}

std::string AuthSignerV4::genStringToSign(const std::string &canonical, const std::string &date, const std::string &scope, const std::string &algoName) const
{
    // Hex(SHA256Hash(Canonical Reuqest))
    ByteBuffer hash(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, canonical.c_str(), canonical.size());
    SHA256_Final(hash.data(), &sha256);

    std::string hashedCalRequest = LowerHexToString(hash);

    // "OSS4-HMAC-SHA256" + "\n" +
    // TimeStamp + "\n" +
    // Scope + "\n" +
    // Hex(SHA256Hash(Canonical Reuqest))
    std::stringstream stringToSign;
    stringToSign << "OSS4-" << algoName << "\n"
                 << date << "\n"
                 << scope << "\n"
                 << hashedCalRequest;

    return stringToSign.str();
}

std::string AuthSignerV4::genSignature(const std::string &accessKeySecret, const std::shared_ptr<Signer> &signAlgo,
                                          const std::string &day, const std::string &region, const std::string &product,
                                          const std::string &stringToSign) const
{
    // HMACSHA256(HMACSHA256(HMACSHA256(HMACSHA256("aliyun_v4"+SK,Date),Region),oss),"aliyun_v4_request");
    std::string toKey = "aliyun_v4" + accessKeySecret;
    ByteBuffer signingSecret = ByteBuffer{toKey.begin(), toKey.end()};
    ByteBuffer signingDate = signAlgo->calculate(day, signingSecret);
    ByteBuffer signingRegion = signAlgo->calculate(region, signingDate);
    ByteBuffer signingService = signAlgo->calculate(product, signingRegion);
    ByteBuffer signingKey = signAlgo->calculate("aliyun_v4_request", signingService);
    OSS_LOG(LogLevel::LogDebug, TAG, "client(%p) signingSecret:\n%s\n day: \n%s", this, LowerHexToString(signingSecret).c_str(), LowerHexToString(ByteBuffer{day.begin(), day.end()}).c_str());
    OSS_LOG(LogLevel::LogDebug, TAG, "client(%p) signingDate:\n%s\ndate:%s", this, LowerHexToString(signingDate).c_str(), day.c_str());
    OSS_LOG(LogLevel::LogDebug, TAG, "client(%p) signingRegion:\n%s\nregion:%s", this, LowerHexToString(signingRegion).c_str(), region.c_str());
    OSS_LOG(LogLevel::LogDebug, TAG, "client(%p) signingService:\n%s\nproduct:%s", this, LowerHexToString(signingService).c_str(), product.c_str());
    OSS_LOG(LogLevel::LogDebug, TAG, "client(%p) signingKey:\n%s", this, LowerHexToString(signingKey).c_str());
    ByteBuffer signSrc = signAlgo->calculate(stringToSign, signingKey);

    return LowerHexToString(signSrc);
}

std::string AuthSignerV4::genAuthStr(const std::string &accessKeyId, const std::string &scope,
                        const HeaderSet &additionalHeaders, const std::string &signature) const {
    std::stringstream authValue;
    authValue
        << "OSS4-HMAC-SHA256 Credential=" << accessKeyId << "/" << scope;

    if (!additionalHeaders.empty())
    {
        authValue << ",AdditionalHeaders=";
        bool isFirstHeader = true;
        for (const auto &addHeader : additionalHeaders)
        {
            if (!isFirstHeader)
            {
                authValue << ";";
            }
            else
            {
                isFirstHeader = false;
            }
            authValue << addHeader.c_str();
        }
    }

    authValue << ",Signature=" << signature;
    return authValue.str();
}

void AuthSignerV4::addHeaders(HttpRequest& request, const AuthSignerParam& param) const {
    // Date
    if (request.hasHeader(Http::DATE)) {
        request.removeHeader(Http::DATE);
    }
    if (!request.hasHeader("x-oss-date")) {
        request.addHeader("x-oss-date", ToUtcTimeWithoutMill(param.RequestTime()));
    }

    // Sha256
    request.addHeader("x-oss-content-sha256", "UNSIGNED-PAYLOAD");

    // host
    if (param.AddiHeaders().find("host") != param.AddiHeaders().end() &&
        !request.hasHeader(Http::HOST)) {
            request.addHeader(Http::HOST, request.url().toString());
    }
}

bool AuthSignerV4::signRequest(HttpRequest& request, const AuthSignerParam& param) const {
    std::string method = Http::MethodToString(request.method());

    std::string resource;
    resource.append("/");
    if (!param.Bucket().empty()) {
        resource.append(param.Bucket());
        resource.append("/");
    }
    if (!param.Key().empty()) {
        resource.append(param.Key());
    }

    addHeaders(request, param);
    std::string canonical = genCanonicalReuqest(method, resource, request.Headers(), param.Parameters(), param.AddiHeaders());

    std::string date = request.Header("x-oss-date");
    // convert to "20060102" time format
    std::string day(date.begin(), date.begin() + 8);

    std::stringstream scope;
    scope << day
          << "/" << region_
          << "/" << product_
          << "/aliyun_v4_request";

    std::string stringToSign = genStringToSign(canonical, date, scope.str(), signAlgo_->name());
    std::string signature = genSignature(param.Cred().AccessKeySecret(), signAlgo_, day, region_, product_, stringToSign);
    std::string authValue = genAuthStr(param.Cred().AccessKeyId(), scope.str(), param.AddiHeaders(), signature);

    request.addHeader(Http::AUTHORIZATION, authValue);

    OSS_LOG(LogLevel::LogDebug, TAG, "client(%p) CanonicalString:\n%s", this, canonical.c_str());
    OSS_LOG(LogLevel::LogDebug, TAG, "client(%p) stringToSign:\n%s", this, stringToSign.c_str());
    OSS_LOG(LogLevel::LogDebug, TAG, "client(%p) signature:\n%s", this, signature.c_str());
    OSS_LOG(LogLevel::LogDebug, TAG, "client(%p) Authorization:\n%s", this, authValue.c_str());
    return true;
}