#pragma once

#include "SignGenerator.h"
#include <alibabacloud/oss/OssRequest.h>
#include <unordered_set>

namespace AlibabaCloud
{
    namespace OSS
    {
        static std::unordered_set<std::string> signHeaders = {Http::CONTENT_TYPE, Http::CONTENT_MD5};
        class SignGeneratorV4 : public SignGenerator
        {
        public:
            SignGeneratorV4() : SignGenerator("4.0") {}

            virtual void signHeader(const std::shared_ptr<HttpRequest> &httpRequest, const SignParam &signParam) const override;
            virtual std::string presign(const SignParam &signParam) const override;
            virtual std::string signRTMP(const SignParam &signParam) const override;

        // private:
            std::string genCanonicalReuqest(const std::string &method,
                                            const std::string &resource,
                                            const HeaderCollection &headers,
                                            const ParameterCollection &parameters,
                                            const HeaderSet &additionalHeaders) const;

            std::string genStringToSign(const std::string &canonical, const std::string &date, const std::string &scope, const std::string &algoName) const;

            std::string genSignature(const std::string &accessKeySecret, const std::shared_ptr<Signer> &signAlgo,
                                     const std::string &day, const std::string &region, const std::string &product,
                                     const std::string &stringToSign) const;

            void addHeaders(const std::shared_ptr<HttpRequest> &httpRequest, const SignParam &signParam) const;
        };
    }
}